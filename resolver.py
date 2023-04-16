import binascii
import socket
from dnslib import DNSRecord

ip_root = "192.33.4.12"
ip_port = 54

def parse_raw_dns(message):
    parsed = DNSRecord.parse(message)
    ANCOUNT = parsed.header.a
    NSCOUNT = parsed.header.auth
    ARCOUNT = parsed.header.ar
    Answer = parsed.rr
    Authority = parsed.auth
    Additional = parsed.ar
    
    struct = {"ANCOUNT": ANCOUNT,
              "NSCOUNT": NSCOUNT,
              "ARCOUNT": ARCOUNT,
              "Answer": Answer,
              "Authority": Authority,
              "Additional": Additional,
              }
    return struct

def resolver(mensaje_consulta):
    pass

buff_size = 2048
socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
resolver_address = ("localhost", 8000)
socket.bind(resolver_address)
while(True):
    message,_ = socket.recvfrom(buff_size)

    struct = parse_raw_dns(message)
    print(struct)





#Guardar: Qname, ANCOUNT, NSCOUNT, ARCOUNT, Answer, Authority y Additional