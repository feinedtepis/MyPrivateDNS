import ctypes
import os
import socket
import struct
import subprocess
import threading
from contextlib import asynccontextmanager
import uvicorn
from dnslib import DNSRecord, QTYPE
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import dns_server

DNS_PORT = int(os.getenv("DNS_PORT", 53))


@asynccontextmanager
async def lifespan(app: FastAPI):
    t = threading.Thread(target=dns_server.main, args=(DNS_PORT,), daemon=True)
    t.start()
    yield


app = FastAPI(title="NetShield DNS API", lifespan=lifespan)


def resolve_upstream_ips(domain: str) -> set:
    """Queries 1.1.1.1 directly for A records so we know which active sockets to close."""
    ips = set()
    for host in (domain, f"www.{domain}"):
        try:
            q = DNSRecord.question(host, "A")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.5)
                s.sendto(q.pack(), ("1.1.1.1", 53))
                data, _ = s.recvfrom(4096)
            parsed = DNSRecord.parse(data)
            for rr in parsed.rr:
                if rr.rtype == QTYPE.A:
                    ips.add(struct.unpack("!I", socket.inet_aton(str(rr.rdata)))[0])
        except Exception:
            pass
    return ips


def kill_connections_for_domain(domain: str):
    """Terminates active Windows TCPv4 sockets to a newly blocked domain's IPs."""
    if os.name != "nt":
        return
    try:
        target_ips = resolve_upstream_ips(domain)
        if not target_ips:
            return

        iphlpapi = ctypes.windll.iphlpapi
        size = ctypes.c_ulong(0)
        iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0)
        buf = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 5, 0) != 0:
            return

        num_entries = struct.unpack_from("<I", buf.raw, 0)[0]

        class MIB_TCPROW(ctypes.Structure):
            _fields_ = [
                ("dwState", ctypes.c_ulong),
                ("dwLocalAddr", ctypes.c_ulong),
                ("dwLocalPort", ctypes.c_ulong),
                ("dwRemoteAddr", ctypes.c_ulong),
                ("dwRemotePort", ctypes.c_ulong),
            ]

        offset = 4
        for _ in range(num_entries):
            state, l_addr, l_port, r_addr, r_port = struct.unpack_from("<IIIII", buf.raw, offset)
            offset += 24  # sizeof(MIB_TCPROW_OWNER_PID)
            if socket.ntohl(r_addr) in target_ips and state == 5:  # 5 = ESTABLISHED
                row = MIB_TCPROW(12, l_addr, l_port, r_addr, r_port)  # 12 = DELETE_TCB
                iphlpapi.SetTcpEntry(ctypes.byref(row))
    except Exception:
        pass


def normalize_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def flush_os_dns_cache():
    if os.name == "nt":
        subprocess.run(
            ["ipconfig", "/flushdns"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def save_domain_file(filepath, domains_set):
    with open(filepath, "w", encoding="utf-8") as f:
        sorted_domains = sorted(domains_set)
        f.write("\n".join(sorted_domains) + ("\n" if sorted_domains else ""))


def purge_domain_from_cache(domain):
    with dns_server.cache_lock:
        keys_to_delete = [
            k for k in dns_server.memo
            if k[0] == domain or k[0].endswith("." + domain)
        ]
        for k in keys_to_delete:
            del dns_server.memo[k]


# 1. Get stats, recent query logs, blocklist, allowlist, and toggle status
@app.get("/api/state")
def get_state():
    summary, logs = dns_server.get_stats_snapshot()
    with dns_server.blocklist_lock:
        blocked = sorted(dns_server.blocklist)
        allowed = sorted(dns_server.allowlist)
        enabled = dns_server.blocking_enabled

    return {
        "stats": summary,
        "logs": logs,
        "blocklist": blocked,
        "allowlist": allowed,
        "blocking_enabled": enabled,
    }


# 2. Global On/Off toggle
@app.post("/api/toggle")
def toggle_blocking():
    with dns_server.blocklist_lock:
        dns_server.blocking_enabled = not dns_server.blocking_enabled
        enabled = dns_server.blocking_enabled
    flush_os_dns_cache()
    return {"blocking_enabled": enabled}


# 3. Add domain to blocklist
@app.post("/api/block")
def add_block(body: dict):
    domain = normalize_domain(body.get("domain"))
    if domain:
        with dns_server.blocklist_lock:
            dns_server.blocklist.add(domain)
            save_domain_file(dns_server.BLOCKLIST_FILE, dns_server.blocklist)
        purge_domain_from_cache(domain)
        flush_os_dns_cache()
        kill_connections_for_domain(domain)
    return {"ok": True}


# 4. Remove domain from blocklist
@app.delete("/api/block/{domain}")
def remove_block(domain: str):
    domain = normalize_domain(domain)
    with dns_server.blocklist_lock:
        dns_server.blocklist.discard(domain)
        save_domain_file(dns_server.BLOCKLIST_FILE, dns_server.blocklist)
    flush_os_dns_cache()
    return {"ok": True}


# 5. Add domain to allowlist (exception override)
@app.post("/api/allow")
def add_allow(body: dict):
    domain = normalize_domain(body.get("domain"))
    if domain:
        with dns_server.blocklist_lock:
            dns_server.allowlist.add(domain)
            save_domain_file(dns_server.ALLOWLIST_FILE, dns_server.allowlist)
        flush_os_dns_cache()
    return {"ok": True}


# 6. Remove domain from allowlist
@app.delete("/api/allow/{domain}")
def remove_allow(domain: str):
    domain = normalize_domain(domain)
    with dns_server.blocklist_lock:
        dns_server.allowlist.discard(domain)
        save_domain_file(dns_server.ALLOWLIST_FILE, dns_server.allowlist)
    purge_domain_from_cache(domain)
    flush_os_dns_cache()
    return {"ok": True}


# 7. Clear DNS cache manually
@app.post("/api/cache/clear")
def clear_cache():
    with dns_server.cache_lock:
        dns_server.memo.clear()
    flush_os_dns_cache()
    return {"ok": True}


# Serve ./public/index.html (must be mounted LAST so /api/* routes take priority)
if os.path.isdir("public"):
    app.mount("/", StaticFiles(directory="public", html=True), name="static")


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3000, access_log=False)