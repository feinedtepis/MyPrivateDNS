
import socket
from concurrent.futures import ThreadPoolExecutor
from dnslib import DNSRecord, QTYPE, DNSQuestion

def send_query(domain):
    request = DNSRecord(q=DNSQuestion(domain, QTYPE.A))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(request.pack(), ("127.0.0.1", 5300))

        response, _ = s.recvfrom(4096)

    answer = DNSRecord.parse(response)

    print(domain, "->", answer.header.rcode)

domains = [
    "google.com",
    "github.com",
    "youtube.com",
    "wikipedia.org",
    "stackoverflow.com"
]

with ThreadPoolExecutor(max_workers=5) as executor:
    result=list(executor.map(send_query, domains))
