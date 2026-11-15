import socket
from dnslib import DNSRecord, DNSQuestion, QTYPE

d = DNSRecord(q=DNSQuestion("youtube.com", QTYPE.A))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

sock.sendto(d.pack(), ("127.0.0.1", 5300))

response, address = sock.recvfrom(4096)

answer = DNSRecord.parse(response)

print(answer)