
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from dnslib import DNSRecord, RCODE

blocklist = []
memo = {}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 5300))

cache_lock = threading.Lock()


def verify_dns(request, response, sender, dns_ip):
    try:
        parsed = DNSRecord.parse(response)

        if request.header.id != parsed.header.id:
            print("Header Mismatch")
            return None

        if parsed.header.qr != 1:
            print("Query Mismatch")
            return None

        if parsed.questions != request.questions:
            print("Question Mismatch")
            return None

        if sender != (dns_ip, 53):
            print("Sender Mismatch")
            return None

        return parsed

    except Exception as e:
        print("Invalid DNS response:", e)
        return None


def load_blocklist():
    domains = []

    with open("blocklist.txt", "r") as f:
        for line in f:
            domain = line.strip().lower()
            if domain:
                domains.append(domain)

    return domains


def is_blocked(domain):
    return any(
        domain == item or domain.endswith("." + item)
        for item in blocklist
    )


def get_cached_response(key, request):
    with cache_lock:
        if key not in memo:
            return None

        cached_response, stored_time, ttl = memo[key]

        elapsed_time = time.monotonic() - stored_time

        if elapsed_time >= ttl:
            print("Cache expired:", key[0])
            del memo[key]
            return None

        print("Cache hit:", key[0])

        cached_response = DNSRecord.parse(cached_response)
        cached_response.header.id = request.header.id

        for record in cached_response.rr:
            record.ttl = max(0, record.ttl - int(elapsed_time))

        return cached_response


def resolve_dns(data, request, key, addr):
    dns_servers = ["1.1.1.1", "8.8.8.8"]

    for dns_ip in dns_servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(3)
                upstream.sendto(data, (dns_ip, 53))
                response, sender = upstream.recvfrom(4096)

            parsed = verify_dns(request, response, sender, dns_ip)

            if parsed is None:
                continue

            # Handle truncated DNS responses
            if parsed.header.tc == 1:
                print("Truncated response from:", dns_ip)
                continue

            # Cache only responses containing answer records
            if parsed.rr:
                ttl = min(record.ttl for record in parsed.rr)

                if ttl > 0:
                    with cache_lock:
                        memo[key] = (
                            response,
                            time.monotonic(),
                            ttl
                        )

                    print("Cached:", key[0], "TTL:", ttl)

            # Forward validated response
            sock.sendto(response, addr)
            return

        except Exception as e:
            print("DNS server error:", dns_ip, e)

    # Both upstream servers failed
    reply = request.reply()
    reply.header.rcode = RCODE.SERVFAIL
    sock.sendto(reply.pack(), addr)


def handle_client(data, addr):
    try:
        request = DNSRecord.parse(data)

        domain = str(request.q.qname).rstrip(".").lower()

        print("Received request:", domain)

        if is_blocked(domain):
            print("Blocked:", domain)

            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN

            sock.sendto(reply.pack(), addr)
            return

        key = (domain, request.q.qtype, request.q.qclass)

        cached_response = get_cached_response(key, request)

        if cached_response is not None:
            sock.sendto(cached_response.pack(), addr)
            return

        resolve_dns(data, request, key, addr)

    except Exception as e:
        print("Error processing request:", e)


blocklist = load_blocklist()

print("NetShield DNS server running...")

with ThreadPoolExecutor(max_workers=10) as executor:

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            executor.submit(handle_client, data, addr)

        except KeyboardInterrupt:
            print("Shutting down NetShield...")
            break

sock.close()
