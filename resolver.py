import binascii
import socket
import sys
from dnslib import DNSRecord, RR, QTYPE

debug = False
if len(sys.argv)>1:
    debug = True if sys.argv[1]=="debug" else False


def parse_raw_dns(message):
    parsed = DNSRecord.parse(message)
    Qname = str(parsed.get_q().get_qname())
    ANCOUNT = parsed.header.a
    NSCOUNT = parsed.header.auth
    ARCOUNT = parsed.header.ar
    Answer = parsed.rr
    Authority = parsed.auth
    Additional = parsed.ar
    
    struct = {  
              "Qname":Qname,
              "ANCOUNT": ANCOUNT,
              "NSCOUNT": NSCOUNT,
              "ARCOUNT": ARCOUNT,
              "Answer": Answer,
              "Authority": Authority,
              "Additional": Additional,
              }
    return struct

def res_aux(mes,mensaje_consulta,debug=False):
    new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    parsed_mes = parse_raw_dns(mes)

    if (parsed_mes["ANCOUNT"] > 0):
        for item in parsed_mes["Answer"]:
            if item.rtype==1:
                return mes
    if (parsed_mes["NSCOUNT"]>0):
        for item in parsed_mes["Authority"]:
            ns_detour=False
            if item.rtype==2:
                ns_detour = True
                break
        if ns_detour:
            ip_found = False
            for item in parsed_mes["Additional"]:
                if item.rtype == 1:
                    ip_found = True
                    add = (str(item.rdata),53)
                    if debug:
                        print(f'(debug) Consultando "{parsed_mes["Qname"]}" a "{item.rname}" en "{item.rdata}"')

                    new_sock.sendto(mensaje_consulta,add)
                    response,_ = new_sock.recvfrom(buff_size)



            if (not ip_found):
                ns_name=""
                for item in parsed_mes["Authority"]:
                    if item.rtype == 2:
                        ns_name = str(item.rdata)
                        break
                if ns_name!="":
                    ns_raw_answer = resolver(bytes(DNSRecord.question(ns_name).pack()))
                    ns_answer = parse_raw_dns(ns_raw_answer)
                    ns_answer = ns_answer["Answer"]
                    ns_ip = ""
                    for item in ns_answer:
                        if item.rtype == 1:
                            ns_ip = str(item.rdata)
                            break
                    if ns_ip!="":
                        if debug:
                            print(f'(debug) Consultando "{parsed_mes["Qname"]}" a "{ns_name}" en "{ns_ip}"')

                        new_sock.sendto(mensaje_consulta,(ns_ip,53))
                        response,_ = new_sock.recvfrom(buff_size)

        return response

def resolver(mensaje_consulta,debug=False):
    new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    new_sock.sendto(mensaje_consulta,root)
    mes,address = new_sock.recvfrom(buff_size)

    result = res_aux(mes,mensaje_consulta,debug)

    while(parse_raw_dns(result)["ANCOUNT"]==0):
        result = res_aux(result,mensaje_consulta)

    return result




cache = {}
cache_times = {}

root = ('192.33.4.12', 53)
resolver_address = ("localhost", 8000)
buff_size = 2048
resolver_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
resolver_socket.bind(resolver_address)


while(True):
    cache_keys = list(cache.keys())

    message,req_add = resolver_socket.recvfrom(buff_size)

    domain_name = parse_raw_dns(message)["Qname"]

    if domain_name in cache_keys:
        if debug:
            print("Cached answer")
        result = cache[domain_name]
        message = DNSRecord.parse(message)
        message.add_answer(RR(domain_name,QTYPE.A,rdata=DNSRecord.parse(result).a.rdata))
        result = message.pack()
        cache_times[domain_name]+=1
    else:
        result = resolver(message,True)

    for k,v in cache_times.items():
        if v <= 1:
            del cache_times[k]
            del cache[k]
        else:
            cache_times[k] -= 1


    if (len(cache_keys)>=5):
        erase_key = min(cache_times, key= cache_times.get)
        del cache_times[erase_key]
        del cache[erase_key]
    cache[domain_name] = result
    cache_times[domain_name] = 20

    resolver_socket.sendto(result, req_add)

