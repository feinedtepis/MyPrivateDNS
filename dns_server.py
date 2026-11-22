import argparse
import os
import socket
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from dnslib import DNSRecord, QTYPE, RCODE, RR, A, AAAA

BLOCKLIST_FILE = "blocklist.txt"
ALLOWLIST_FILE = "allowlist.txt"
MAX_CACHE_SIZE = 5000
CLIENT_TTL_CAP = 2
LOCAL_RECORDS = {
    "netshield.home": "127.0.0.1",
    "dev.home": "127.0.0.1",
}
blocklist = set()
allowlist = set()
memo = {}
blocking_enabled = True

blocklist_lock = threading.Lock()
cache_lock = threading.Lock()
send_lock = threading.Lock()

MAX_LOG_ENTRIES = 100

stats = {
    "total": 0,
    "blocked": 0,
    "cached": 0,
    "resolved": 0,
    "failed": 0,
    "rewritten": 0,
}
recent_logs = deque(maxlen=MAX_LOG_ENTRIES)
stats_lock = threading.Lock()


def get_stats_snapshot():
    with stats_lock:
        return dict(stats), list(recent_logs)


def log_request(domain, qtype, action, client_ip, latency_ms):
    qtype_name = QTYPE.get(qtype, str(qtype))
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "domain": domain,
        "type": qtype_name,
        "action": action,
        "client": client_ip,
        "latency_ms": round(latency_ms, 2),
    }

    with stats_lock:
        stats["total"] += 1
        key = action.lower()
        if key in stats:
            stats[key] += 1
        recent_logs.appendleft(entry)

    print(f"[{entry['time']}] {action:<9} | {domain} ({qtype_name}) | {entry['latency_ms']} ms")


def safe_send(sock, payload, addr):
    try:
        with send_lock:
            sock.sendto(payload, addr)
    except OSError:
        pass


def verify_dns(request, response, sender, dns_ip):
    try:
        parsed = DNSRecord.parse(response)
        if request.header.id != parsed.header.id:
            return None
        if parsed.header.qr != 1:
            return None
        if parsed.questions != request.questions:
            return None
        if sender != (dns_ip, 53):
            return None
        return parsed
    except Exception:
        return None


def load_domain_file(filepath):
    if not os.path.exists(filepath):
        with open(filepath, "w", encoding="utf-8"):
            pass
        return set()

    ignored_hosts = {"localhost", "localhost.localdomain", "local", "broadcasthost"}
    domains = set()

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.split("#", 1)[0].strip()
            if not raw:
                continue

            parts = raw.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                domain = parts[1]
            else:
                domain = parts[0]

            domain = domain.lower().rstrip(".")
            if domain.startswith("www."):
                domain = domain[4:]
            if domain and domain not in ignored_hosts:
                domains.add(domain)

    return domains


def is_blocked(domain):
    parts = domain.split(".")
    with blocklist_lock:
        if not blocking_enabled:
            return False

        for i in range(len(parts)):
            if ".".join(parts[i:]) in allowlist:
                return False

        for i in range(len(parts)):
            if ".".join(parts[i:]) in blocklist:
                return True

    return False


def has_edns(parsed_record):
    return any(record.rtype == 41 for record in parsed_record.ar)


def get_cached_response(key, request):
    with cache_lock:
        if key not in memo:
            return None

        cached_response, stored_time, ttl = memo[key]
        elapsed_time = time.monotonic() - stored_time

        if elapsed_time >= ttl:
            del memo[key]
            return None

        cached_record = DNSRecord.parse(cached_response)
        cached_record.header.id = request.header.id
        cached_record.questions = request.questions
        cached_record.header.rd = request.header.rd
        cached_record.header.cd = request.header.cd

        for records in (cached_record.rr, cached_record.auth, cached_record.ar):
            for record in records:
                if record.rtype != 41:
                    remaining = max(1, record.ttl - int(elapsed_time))
                    record.ttl = min(CLIENT_TTL_CAP, remaining)

        return cached_record


def resolve_dns(sock, data, request, key, addr):
    dns_servers = ["1.1.1.1", "8.8.8.8"]

    for dns_ip in dns_servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(2.5)
                upstream.sendto(data, (dns_ip, 53))
                response, sender = upstream.recvfrom(4096)

            parsed = verify_dns(request, response, sender, dns_ip)
            if parsed is None or parsed.header.tc == 1:
                continue

            if parsed.rr and not has_edns(parsed):
                ttl = min(record.ttl for record in parsed.rr)
                if ttl > 0:
                    with cache_lock:
                        if len(memo) >= MAX_CACHE_SIZE:
                            del memo[next(iter(memo))]
                        memo[key] = (response, time.monotonic(), ttl)

            # Actually rewrite the TTL inside the packet sent back to Windows/browsers
            for records in (parsed.rr, parsed.auth, parsed.ar):
                for record in records:
                    if record.rtype != 41:
                        record.ttl = min(CLIENT_TTL_CAP, record.ttl)

            safe_send(sock, parsed.pack(), addr)
            return True

        except Exception:
            continue

    reply = request.reply()
    reply.header.rcode = RCODE.SERVFAIL
    safe_send(sock, reply.pack(), addr)
    return False


def handle_client(sock, data, addr):
    start_time = time.perf_counter()
    try:
        request = DNSRecord.parse(data)

        if request.header.qr != 0 or request.header.opcode != 0 or len(request.questions) != 1:
            return

        domain = str(request.q.qname).rstrip(".").lower()
        qtype = request.q.qtype
        client_ip = addr[0]
        if client_ip.startswith("::ffff:"):
            client_ip = client_ip[7:]
        if is_blocked(domain):
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            safe_send(sock, reply.pack(), addr)
            log_request(domain, qtype, "BLOCKED", client_ip, (time.perf_counter() - start_time) * 1000)
            return

        if domain in LOCAL_RECORDS:
            reply = request.reply()
            if qtype == QTYPE.A:
                reply.add_answer(
                    RR(rname=request.q.qname, rtype=QTYPE.A, rdata=A(LOCAL_RECORDS[domain]), ttl=60)
                )
            elif qtype == QTYPE.AAAA:
                
                reply.add_answer(
                    RR(rname=request.q.qname, rtype=QTYPE.AAAA, rdata=AAAA("::1"), ttl=60)
                )
            safe_send(sock, reply.pack(), addr)
            log_request(domain, qtype, "REWRITTEN", client_ip, (time.perf_counter() - start_time) * 1000)
            return

        key = (domain, request.q.qtype, request.q.qclass)
        cached_response = get_cached_response(key, request)

        if cached_response is not None:
            safe_send(sock, cached_response.pack(), addr)
            log_request(domain, qtype, "CACHED", client_ip, (time.perf_counter() - start_time) * 1000)
            return

        if resolve_dns(sock, data, request, key, addr):
            log_request(domain, qtype, "RESOLVED", client_ip, (time.perf_counter() - start_time) * 1000)
        else:
            log_request(domain, qtype, "FAILED", client_ip, (time.perf_counter() - start_time) * 1000)

    except Exception as e:
        print(f"[DNS ERROR] addr={addr}: {e}")


def main(port=None):
    if port is None:
        parser = argparse.ArgumentParser(description="NetShield DNS server")
        parser.add_argument("--port", type=int, default=53, help="Port to bind (default: 53)")
        port = parser.parse_args().port

    loaded_blocked = load_domain_file(BLOCKLIST_FILE)
    loaded_allowed = load_domain_file(ALLOWLIST_FILE)
    with blocklist_lock:
        blocklist.clear()
        blocklist.update(loaded_blocked)
        allowlist.clear()
        allowlist.update(loaded_allowed)
    print(f"Loaded {len(loaded_blocked)} blocked and {len(loaded_allowed)} allowed domains.")

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)    
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        sock.ioctl(socket.SIO_UDP_CONNRESET, False)
    try:
        sock.bind(("::", port))
    except PermissionError:
        print(f"Permission denied on port {port}. Run as Administrator.")
        return

    print(f"NetShield DNS server running on 127.0.0.1:{port}...")

    with ThreadPoolExecutor(max_workers=20) as executor:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                executor.submit(handle_client, sock, data, addr)
            except (ConnectionResetError, OSError):
                continue
            except KeyboardInterrupt:
                summary, _ = get_stats_snapshot()
                print(f"\nShutting down NetShield... Summary: {summary}")
                break

    sock.close()


if __name__ == "__main__":
    main()