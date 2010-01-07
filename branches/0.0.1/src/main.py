'''
Created on 31.12.2009

@author: danfocus
'''
import socket
import select
import struct
import Queue
import random
import hashlib

#from random import randrange
from threading import Thread

serv_addr = '0.0.0.0'
serv_port = 5190

FLAP_HRD_SIZE = 6
AIM_MD5_STRING = "AOL Instant Messenger (SM)"

#---------------------------------
#   Channels
CH_NEW_CONNECTION = 0x01
CH_FNAC = 0x02
CH_ERROR = 0x03
CH_LOGOUT = 0x04

q = Queue.Queue()

connections = {}
challenge = ""

def tohex(str_):
    """
    Use for debug
        str->hex
        return ([hex], str)
    """

    hex_ = map(lambda x: "%.2x" % ord(x), tuple(str_))
    text = " ".join(hex_)
    return hex_, text

class Connection(object):
    def __init__(self, connection, address):
        self.connection = connection
        self.address = address
        self.isequence = None
        self.osequence = None
        self.accepted = -1

class Fnac(object):
    def __init__(self, family, subtype, flags=0, id=0, data=None):
        self.family = family
        self.subtype = subtype
        self.flags = flags
        self.id = id
        self.data = data
    def parse_hdr(self, string):
        return (ord(string[0]) << 8) + ord(string[1]), (ord(string[2]) << 8) + ord(string[3])
    def make_fnac(self):
        l = len(self.data)
        fmt = '!HHHIH %ds' % l
        return struct.pack(fmt, self.family, self.subtype, self.flags, self.id, l, self.data)

def parse_tlv(str_):
    tlvs = {}
    data = str_[10:]
    while(len(data)):
        tlv_id = (ord(data[0]) << 8) + ord(data[1])
        tlv_len = (ord(data[2]) << 8) + ord(data[3])
        tlv_end = 4 + tlv_len
        tlv_data = data[4:tlv_end]
        tlvs[tlv_id] = tlv_data
        data = data[tlv_end:]
    return tlvs    
    
        
def parse_fnac(str_, fileno):
    global challenge
    fn_family = (ord(str_[0]) << 8) + ord(str_[1])
    fn_sub = (ord(str_[2]) << 8) + ord(str_[3])
    if fn_family == 0x17:
        if fn_sub == 0x06:
            challenge = str(random.randint(1000000000, 9999999999))
            fn = Fnac(0x17, 0x07, 0, 0, challenge)
            fl = Flap(0x02, connections[fileno].osequence, fn.make_fnac())
            connections[fileno].connection.send(fl.make_flap())
            connections[fileno].osequence = connections[fileno].osequence + 1 
            print "Challenge:", challenge
        if fn_sub == 0x02:
            m = hashlib.md5()
            m.update(challenge)
            a = parse_tlv(str_)
            if a.has_key(0x4c):
                m2 = hashlib.md5()
                m2.update("12345")
                m.update(m2.digest())
            else:
                m.update("12345")
            m.update(AIM_MD5_STRING)
            
            if a[0x25] == m.digest():
                print "Auth - OK"
            else:
                print "Auth - Fail"

class Flap(object):
    def __init__(self, channel=None, sequence=None, data=None):
        self.channel = channel
        self.data = data
        self.sequence = sequence
    def parse_hdr(self, string):
        if ord(string[0]) != 0x2A:
            return
        self.channel = ord(string[1])
        self.sequence = (ord(string[2]) << 8) + ord(string[3])
        return (ord(string[4]) << 8) + ord(string[5])
    def channel(self, channel):
        self.channel = channel
    def data(self, data):
        self.data = data
    def sequence(self, sequence):
        self.sequence = sequence
    def make_flap(self):
        l = len(self.data)
        fmt = '!BBHH %ds' % l
        return struct.pack(fmt, 0x2a, self.channel, self.sequence, l, self.data)
    

class Flap_processor(Thread):
    def __init__(self):
        Thread.__init__(self)
    def run(self):
        pass

def main():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversocket.bind((serv_addr, serv_port))
    serversocket.listen(1)
    serversocket.setblocking(0)
    serversocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    epoll = select.epoll()
    epoll.register(serversocket.fileno(), select.EPOLLIN)
    
    try:
#        connections = {}; requests = {}; responses = {}; addresses = {}
        while True:
            events = epoll.poll(1)
            for fileno, event in events:
                if fileno == serversocket.fileno():
                    connection, address = serversocket.accept()
                    connection.setblocking(0)
                    epoll.register(connection.fileno(), select.EPOLLIN)
                    connections[connection.fileno()] = Connection(connection, address)
                    seq = random.randrange(0xFFFF)
                    fl = Flap(CH_NEW_CONNECTION, seq, struct.pack('!i', 1))
                    if connection.send(fl.make_flap()):
                        connections[connection.fileno()].osequence = seq + 1
                        connections[connection.fileno()].accepted += 1
                elif event & select.EPOLLIN:
                    fl = Flap()
                    conn = connections[fileno].connection.recv(FLAP_HRD_SIZE)
                    if not conn:
                        epoll.modify(fileno, 0)
                    else:
                        a = fl.parse_hdr(conn)
                        data = connections[fileno].connection.recv(a)
                        if fl.channel == CH_NEW_CONNECTION:
                            if not connections[fileno].accepted:
                                connections[fileno].accepted += 1
                                connections[fileno].isequence = fl.sequence + 1
                            else:
                                epoll.modify(fileno, 0)
                                connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                        elif fl.channel == CH_FNAC:
                            #fn = Fnac()
                            #fn_family, fn_sub = fn.parse_hdr(data)
                            #print fn_family, fn_sub
                            parse_fnac(data, fileno)
                            
                elif event & select.EPOLLOUT:
                    pass
#                    byteswritten = connections[fileno].send(responses[fileno])
#                    responses[fileno] = responses[fileno][byteswritten:]
#                    if len(responses[fileno]) == 0:
#                        connections[fileno].setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
#                        epoll.modify(fileno, 0)
#                        connections[fileno].shutdown(socket.SHUT_RDWR)
                elif event & select.EPOLLHUP:
                    epoll.unregister(fileno)
                    connections[fileno].connection.close()
                    del connections[fileno]
    finally:
        epoll.unregister(serversocket.fileno())
        epoll.close()
        serversocket.close()
    

if __name__ == '__main__':
    main()

