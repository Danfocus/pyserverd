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
import MySQLdb

#from random import randrange
from threading import Thread

serv_addr = '0.0.0.0'
serv_port = 5190

FLAP_START = 0x2A
FLAP_HRD_SIZE = 6
AIM_MD5_STRING = "AOL Instant Messenger (SM)"

#---------------------------------
#   Channels
CH_NEW_CONNECTION = 0x01
CH_SNAC = 0x02
CH_ERROR = 0x03
CH_LOGOUT = 0x04

q = Queue.Queue()

connections = {}
challenge = ""

db = None

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

class Tlv_c(object):
    def __init__(self, id, value):
        self.id = id
        self.value = str(value)
    def make_tlv_c(self):
        l = len(self.value)
        fmt = '!HH %ds' % l
        return struct.pack(fmt, self.id, l, self.value)
    
def make_tlv(list_):
    slist = [x.make_tlv_c() for x in list_]
    text = "".join(slist)
    return text
        

class Snac(object):
    def __init__(self, family, subtype, flags=0, id=0, data=None):
        self.family = family
        self.subtype = subtype
        self.flags = flags
        self.id = id
        self.data = data
    def parse_hdr(self, string):
        return (ord(string[0]) << 8) + ord(string[1]), (ord(string[2]) << 8) + ord(string[3])
    def make_snac(self):
        l = len(self.data)
        fmt = '!HHHIH %ds' % l
        return struct.pack(fmt, self.family, self.subtype, self.flags, self.id, l, self.data)
    def make_snac_tlv(self):
        l = len(self.data)
        fmt = '!HHHI %ds' % l
        return struct.pack(fmt, self.family, self.subtype, self.flags, self.id, self.data)

def parse_tlv(str_):
    tlvs = {}
    data = str_
    while(len(data)):
        tlv_id = (ord(data[0]) << 8) + ord(data[1])
        tlv_len = (ord(data[2]) << 8) + ord(data[3])
        tlv_end = 4 + tlv_len
        tlv_data = data[4:tlv_end]
        tlvs[tlv_id] = tlv_data
        data = data[tlv_end:]
    return tlvs    
    
def generate_cookie():
    slist = map(lambda x: chr(random.randint(0, 0xFF)), xrange(256))
    return "".join(slist)
        
def parse_snac(str_, fileno):
    global challenge, db
    sn_family = (ord(str_[0]) << 8) + ord(str_[1])
    sn_sub = (ord(str_[2]) << 8) + ord(str_[3])
    if sn_family == 0x17:
        if sn_sub == 0x06:
            challenge = str(random.randint(1000000000, 9999999999))
            c = db.cursor()
            tlvc = parse_tlv(str_[10:])
            c.execute("""UPDATE users SET challenge = %s WHERE uin = %s""", (challenge, tlvc[0x01]))
            sn = Snac(0x17, 0x07, 0, 0, challenge)
            fl = Flap(CH_SNAC, connections[fileno].osequence, sn.make_snac())
            connections[fileno].connection.send(fl.make_flap())
            connections[fileno].osequence = connections[fileno].osequence + 1 
#            print "Challenge:", challenge
        if sn_sub == 0x02:
            m = hashlib.md5()
            tlvc = parse_tlv(str_[10:])
            c = db.cursor()
            c.execute("""SELECT challenge,password FROM users WHERE uin = %s""", (tlvc[0x01]))
            challenge, password = c.fetchone()
            m.update(challenge)
            if tlvc.has_key(0x4c):
                m2 = hashlib.md5()
                m2.update(password)
                m.update(m2.digest())
            else:
                m.update(password)
            m.update(AIM_MD5_STRING)
            
            if tlvc[0x25] == m.digest():
                print "Auth - OK"
                cookie = generate_cookie()
                c.execute("""REPLACE INTO users_cookies SET users_uin = %s, cookie = %s""",(tlvc[0x01], struct.pack("!%ds" % len(cookie), cookie)))
                tl = [Tlv_c(0x8e, '\x00'), Tlv_c(0x01, tlvc[0x01]), Tlv_c(0x05, "127.0.0.1:5190"), Tlv_c(0x06, cookie)]
                a = make_tlv(tl)
                sn = Snac(0x17, 0x03, 0, 0, a)
                fl = Flap(CH_SNAC, connections[fileno].osequence, sn.make_snac_tlv())
                connections[fileno].connection.send(fl.make_flap_close())
                connections[fileno].osequence = connections[fileno].osequence + 2
            else:
                print "Auth - Fail"

class Flap(object):
    def __init__(self, channel=None, sequence=None, data=None):
        self.channel = channel
        self.data = data
        self.sequence = sequence
    def parse_hdr(self, string):
        if ord(string[0]) != FLAP_START:
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
        return struct.pack(fmt, FLAP_START, self.channel, self.sequence, l, self.data)
    def make_flap_close(self):
        return self.make_flap() + struct.pack('!BBHH', FLAP_START, CH_LOGOUT, self.sequence + 1, 0)
    

class Flap_processor(Thread):
    def __init__(self):
        Thread.__init__(self)
    def run(self):
        pass

def main():
    global db
    db = MySQLdb.connect(unix_socket="/var/run/mysql/mysql.sock", user="pyserverd", passwd="pyserverd", db="pyserverd", use_unicode=True, charset='utf8')
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
                #print len(connections)
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
                        connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                    else:
                        a = fl.parse_hdr(conn)
                        data = connections[fileno].connection.recv(a)
                        if fl.channel == CH_NEW_CONNECTION:
                            if not connections[fileno].accepted:
                                connections[fileno].accepted += 1
                                connections[fileno].isequence = fl.sequence + 1
#                            else:
#                                epoll.modify(fileno, 0)
#                                connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                            print "New_connect tail:", tohex(data[4:])
                            tlvc = parse_tlv(data[4:])
                            if tlvc.has_key(0x01):
                                c = db.cursor()
                                #cookie = c.execute("""SELECT cookie FROM Users WHERE uin = %s""", (tlvc[0x01]))
                                
                        elif fl.channel == CH_SNAC:
                            parse_snac(data, fileno)
                elif event & select.EPOLLOUT:
                    print "Ready to out: ", fileno
                elif event & select.EPOLLHUP:
                    print "Close coonection: ", fileno
                    epoll.unregister(fileno)
                    connections[fileno].connection.close()
                    del connections[fileno]
                elif event & select.EPOLLERR:
                    print "Error coonection: ", fileno
    finally:
        epoll.unregister(serversocket.fileno())
        epoll.close()
        serversocket.close()
    

if __name__ == '__main__':
    main()

