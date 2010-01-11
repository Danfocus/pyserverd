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

from threading import Thread

from defines import *
from config import *
import db_mysql

q = Queue.Queue()

connections = {}

db = db_mysql.db_mysql()

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
        self.flap = None

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

def make_fam_list():
    slist = [struct.pack('!H', x) for x in SUPPORTED_SERVICES.keys()]
    text = "".join(slist)
    return text

def make_fam_vers_list():
    slist = [struct.pack('!HH', x,y) for x,y in SUPPORTED_SERVICES]
    text = "".join(slist)
    return text

def make_well_known_url():
    slist = [struct.pack("!HH %ds" % len(y), x, len(y), y) for x, y in WELL_KNOWN_URL.iteritems()]
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
    #global challenge, db
    sn_family = (ord(str_[0]) << 8) + ord(str_[1])
    sn_sub = (ord(str_[2]) << 8) + ord(str_[3])
    if sn_family == SN_TYP_REGISTRATION:
        if sn_sub == SN_IES_AUTHxREQUEST:
            challenge = str(random.randint(1000000000, 9999999999))
            #c = db.cursor()
            tlvc = parse_tlv(str_[10:])
            if not db.db_set_challenge(tlvc[0x01], challenge):
                tl = [Tlv_c(0x01, tlvc[0x01]), Tlv_c(0x04, MISMATCH_PASSWD), Tlv_c(0x08, '\x00\x05')]
                sn = Snac(SN_TYP_REGISTRATION, SN_IES_LOGINxREPLY, 0, 0, make_tlv(tl))
                fl = Flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
                connections[fileno].flap = fl.make_flap_close()
                return
            #c.execute("""UPDATE users SET challenge = %s WHERE uin = %s""", (challenge, tlvc[0x01]))
            sn = Snac(SN_TYP_REGISTRATION, SN_IES_AUTHxKEY, 0, 0, challenge)
            fl = Flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac())
            connections[fileno].flap = fl.make_flap()
        if sn_sub == SN_IES_AUTHxLOGIN:
            m = hashlib.md5()
            tlvc = parse_tlv(str_[10:])
            challenge, password = db.db_select_users_where("challenge,password", tlvc[0x01])
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
                db.db_set_cookie(tlvc[0x01], struct.pack("!%ds" % len(cookie), cookie))
                #c.execute("""REPLACE INTO users_cookies SET users_uin = %s, cookie = %s""",(tlvc[0x01], struct.pack("!%ds" % len(cookie), cookie)))
                tl = [Tlv_c(0x8e, '\x00'), Tlv_c(0x01, tlvc[0x01]), Tlv_c(0x05, serv_addr + ":" + str(serv_port)), Tlv_c(0x06, cookie)]
                a = make_tlv(tl)
                sn = Snac(SN_TYP_REGISTRATION, SN_IES_LOGINxREPLY, 0, 0, a)
                fl = Flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
                connections[fileno].flap = fl.make_flap_close()       #connections[fileno].osequence = connections[fileno].osequence + 2
            else:
                print "Auth - Fail"
                
    if sn_family == SN_TYP_GENERIC:
        if sn_sub == SN_GEN_REQUESTxVERS:
            sn = Snac(SN_TYP_GENERIC, SN_GEN_VERSxRESPONSE, 0, 0, make_fam_vers_list())
            fl = Flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
            #sn = Snac(SN_TYP_GENERIC, SN_GEN_MOTD, 0, 0, make_fam_vers_list())
            connections[fileno].flap = fl.make_flap_close()
                                    
                

class Flap(object):
    def __init__(self, channel=None, sequence=None, data=None):
        self.channel = channel
        self.data = data
        self.sequence = sequence
    def parse_hdr(self, string):
        if ord(string[0]) != FLAP_STARTMARKER:
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
        return struct.pack(fmt, FLAP_STARTMARKER, self.channel, self.sequence, l, self.data)
    def make_flap_close(self):
        return self.make_flap() + struct.pack('!BBHH', FLAP_STARTMARKER, FLAP_FRAME_SIGNOFF, self.sequence + 1, 0)
    def add_make_flap(self, fl):
        return self.make_flap() + fl.make_flap()
    
    

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
                print len(connections)
                if fileno == serversocket.fileno():
                    connection, address = serversocket.accept()
                    connection.setblocking(0)
                    epoll.register(connection.fileno(), select.EPOLLOUT)
                    connections[connection.fileno()] = Connection(connection, address)
                    seq = random.randrange(0xFFFF)
                    fl = Flap(FLAP_FRAME_SIGNON, seq, struct.pack('!i', FLAP_VERSION))
                    #if connection.send(fl.make_flap()):
                    connections[connection.fileno()].osequence = seq
                    connections[connection.fileno()].accepted += 1
                        
                    connections[connection.fileno()].flap = fl.make_flap()
                elif event & select.EPOLLIN:
                    print "Ready to in: ", fileno
                    fl = Flap()
                    conn = connections[fileno].connection.recv(FLAP_HRD_SIZE)
                    if not conn:
                        epoll.modify(fileno, 0)
                        connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                    else:
                        a = fl.parse_hdr(conn)
                        if a:
                            data = connections[fileno].connection.recv(a)
                        if fl.channel == FLAP_FRAME_SIGNON:
                            if not connections[fileno].accepted:
                                connections[fileno].accepted += 1
                                connections[fileno].isequence = fl.sequence + 1
#                            else:
#                                epoll.modify(fileno, 0)
#                                connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                            print "New_connect tail:", tohex(data[4:])
                            tlvc = parse_tlv(data[4:])
                            if tlvc.has_key(FL_SIGNON_COOKIE):
                                print "Second connect"
                                a = db.db_get_cookie(tlvc[FL_SIGNON_COOKIE])
                                print str(a)
                                if a:
                                    sn = Snac(SN_TYP_GENERIC, SN_GEN_SERVERxFAMILIES, 0, 0, make_fam_list())
                                    fl = Flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
                                    connections[fileno].osequence += 1
                                    sn = Snac(SN_TYP_GENERIC, SN_GEN_WELLxKNOWNxURLS, 0, 0, make_well_known_url())
                                    fl2 = Flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
                                    connections[fileno].flap = fl.add_make_flap(fl2)
                                    epoll.modify(fileno, select.EPOLLOUT)
                        elif fl.channel == FLAP_FRAME_DATA:
                            parse_snac(data, fileno)
                            epoll.modify(fileno, select.EPOLLOUT)
                        elif fl.channel == FLAP_FRAME_SIGNOFF:
                            epoll.modify(fileno, 0)
                            connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                elif event & select.EPOLLOUT:
                    print "Ready to out: ", fileno
                    if connections[fileno].connection.send(connections[fileno].flap):
                        connections[fileno].osequence += 1
                        connections[fileno].flap = None
                        epoll.modify(fileno, select.EPOLLIN)
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

