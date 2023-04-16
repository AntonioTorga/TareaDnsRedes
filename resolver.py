import binascii
import socket

buff_size = 2048
socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
resolver_address = ("localhost", 8000)
socket.bind(resolver_address)
while(True):
    message,_ = socket.recvfrom(buff_size)
    print(message)




