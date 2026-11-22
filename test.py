import socket
import time
from dnslib import DNSRecord

DNS_HOST = "127.0.0.1"
DNS_PORT = 5300

# Mix of normal, repeat (to trigger cache hits), and blocked domains
TEST_DOMAINS = [
    "google.com",
    "github.com",
    "youtube.com",        # Should be BLOCKED if in blocklist.txt
    "ads.youtube.com",    # Subdomain block test
    "google.com",         # Should hit CACHE
    "cloudflare.com",
    "wikipedia.org",
    "github.com",         # Should hit CACHE
    "cloudflare.com",     # Should hit CACHE
    "doubleclick.net",
]

def send_query(domain: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        query = DNSRecord.question(domain).pack()
        start = time.perf_counter()
        sock.sendto(query, (DNS_HOST, DNS_PORT))
        data, _ = sock.recvfrom(4096)
        elapsed_ms = (time.perf_counter() - start) * 1000

        reply = DNSRecord.parse(data)
        ips = [str(rr.rdata) for rr in reply.rr] or ["NXDOMAIN / No Answer"]
        print(f"{domain:<20} -> {', '.join(ips):<25} ({elapsed_ms:.2f} ms)")
    except socket.timeout:
        print(f"{domain:<20} -> TIMEOUT")
    finally:
        sock.close()

if __name__ == "__main__":
    print(f"Sending {len(TEST_DOMAINS)} test queries to {DNS_HOST}:{DNS_PORT}...\n")
    for d in TEST_DOMAINS:
        send_query(d)
        time.sleep(0.25)  # Gives upstream resolution time to save into cache
    print("\nDone! Check http://127.0.0.1:3000 to view updated stats and logs.")