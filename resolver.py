import binascii
import socket
from dnslib import DNSRecord


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
    new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    new_sock.sendto(mensaje_consulta,root)
    message,address = new_sock.recvfrom(buff_size)
    parsed = parse_raw_dns(message)
    if parsed["ANCOUNT"] > 0:
        for record in parsed["Answer"]:
            if record.rclass == 1:
                return message
    elif parsed["NSCOUNT"] > 0:
        for record in parsed["Additional"]:
            if record.rclass == 1:
                pass #mandar message a records
            


 


root = ('192.33.4.12', 53)
resolver_address = ("localhost", 8000)
buff_size = 2048
resolver_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
resolver_socket.bind(resolver_address)


while(True):
    message,_ = resolver_socket.recvfrom(buff_size)

    resolver(message)





#Guardar: Qname, ANCOUNT, NSCOUNT, ARCOUNT, Answer, Authority y Additional