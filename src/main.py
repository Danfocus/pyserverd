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
import time
import ConfigParser
#import logging

from threading import Thread

from defines import * #@UnusedWildImport

from flap import flap

from snac import snac

q = Queue.Queue()

connections = {}

cnf = ConfigParser.ConfigParser()
cnf.read('pyserverd.conf')

if cnf.get('db', 'db_type') == 'mysql':
    from databases import db_mysql
    _sql = db_mysql.sql
elif cnf.get('db', 'db_type') == 'pgsql':
    from databases import db_pgsql
    _sql = db_pgsql.sql
else:
    print "Database not supported"
    exit()

db = _sql(cnf.get('db', 'db_host'), cnf.getint('db', 'db_port'),
               cnf.get('db', 'db_user'), cnf.get('db', 'db_passwd'),
               cnf.get('db', 'db_name'), cnf.getboolean('db', 'db_use_unicode'),
               cnf.get('db', 'db_charset'))

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
        self.accepted = None
        self.uin = None
        self.flap = Queue.Queue()

class Tlv_c(object):
    def __init__(self, id, value, len=None):
        self.id = id
        self.value = str(value)
        self.len = len
    def make_tlv_c(self):
        if self.len:
            l = self.len
        else:
            l = len(self.value)
        fmt = '!HH %ds' % l
        return struct.pack(fmt, self.id, l, self.value)
    
def make_tlv(list_):
    slist = [x.make_tlv_c() for x in list_]
    text = "".join(slist)
    return text

def make_tlvblock(list_):
    text = make_tlv(list_)
    fmt = '!H %ds' % len(text)
    return struct.pack(fmt, len(list_), text)

def make_tlvlblock(list_):
    text = make_tlv(list_)
    l = len(text)
    fmt = '!H %ds' % l
    return struct.pack(fmt, l, text)



def make_fam_list():
    slist = [struct.pack('!H', x) for x in SUPPORTED_SERVICES.keys()]
    text = "".join(slist)
    return text

def make_fam_vers_list():
    slist = [struct.pack('!HH', x, y) for x, y in SUPPORTED_SERVICES.iteritems()]
    text = "".join(slist)
    return text

def make_well_known_url():
    slist = [struct.pack("!HH %ds" % len(y), x, len(y), y) for x, y in WELL_KNOWN_URL.iteritems()]
    text = "".join(slist)
    return text

def make_motd():
    return struct.pack("!HHHHHHH" , 5, 2, 2, 30, 3, 2, 1200)

def make_rate_info():
    slist = [struct.pack("!HIIIIIIIIB", x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9]) for x in RATE_CLASSES]
    text = "".join(slist)
    return struct.pack("!H", len(RATE_CLASSES)) + text

def make_rate_gr(tpl):
    slist = [struct.pack("!HH" , x[0], x[1]) for x in tpl]
    text = "".join(slist)
    return text

def make_rate_groups():
    slist = [struct.pack("!HH %ds" % len(make_rate_gr(y)), x, len(y), make_rate_gr(y)) for x, y in RATE_GROUPS.iteritems()]
    text = "".join(slist)
    return text

def make_self_info(fileno):
    tl = [Tlv_c(1, 81),
          Tlv_c(12, '', 32),
          Tlv_c(10, connections[fileno].address[0])]
    tl.append(Tlv_c(5, db.db_select_users_where("UNIX_TIMESTAMP(member_since)", connections[fileno].uin)[0], 4))
    tl.append(Tlv_c(15, 1, 4))
    tl.append(Tlv_c(3, db.db_select_users_where("UNIX_TIMESTAMP(online_since)", connections[fileno].uin)[0], 4))
    return struct.pack("!B %ds H" % len(str(connections[fileno].uin)), len(str(connections[fileno].uin)), str(connections[fileno].uin), 0) + make_tlvblock(tl)


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
    sn_family = (ord(str_[0]) << 8) + ord(str_[1])
    sn_sub = (ord(str_[2]) << 8) + ord(str_[3])
    #print sn_family, sn_sub
    if sn_family == SN_TYP_REGISTRATION:
        if sn_sub == SN_IES_AUTHxREQUEST:
            challenge = str(random.randint(1000000000, 9999999999))
            tlvc = parse_tlv(str_[10:])
            if not db.db_set_challenge(tlvc[0x01], challenge):
                tl = [Tlv_c(0x01, tlvc[0x01]), Tlv_c(0x04, MISMATCH_PASSWD), Tlv_c(0x08, '\x00\x05')]
                sn = snac(SN_TYP_REGISTRATION, SN_IES_LOGINxREPLY, 0, 0, make_tlv(tl))
                fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
                connections[fileno].flap.put((fl.make_flap_close(), 1))
                return
            sn = snac(SN_TYP_REGISTRATION, SN_IES_AUTHxKEY, 0, 0, challenge)
            fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac())
            connections[fileno].flap.put((fl.make_flap(), 1))
        elif sn_sub == SN_IES_AUTHxLOGIN:
            m = hashlib.md5()
            tlvc = parse_tlv(str_[10:])
            challenge = db.db_get_challenge(tlvc[0x01], cnf.getint('general', 'cookie_lifetime'))
            if challenge:
                password = db.db_select_users_where("password", tlvc[0x01])[0]
                m.update(challenge)
                if 0x4c in tlvc:
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
                    tl = [Tlv_c(0x8e, '\x00'), Tlv_c(0x01, tlvc[0x01]), Tlv_c(0x05, cnf.get('general', 'bos_addr')), Tlv_c(0x06, cookie)]
                    a = make_tlv(tl)
                    sn = snac(SN_TYP_REGISTRATION, SN_IES_LOGINxREPLY, 0, 0, a)
                    fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
                    connections[fileno].flap.put((fl.make_flap_close(), 1))       #connections[fileno].osequence = connections[fileno].osequence + 2
                else:
                    print "Auth - Fail - wrong password"
            else:
                print "Auth - Fail - no challenge"
        else:
            print "unknown snac(%s,%s)" % (sn_family, sn_sub)
            
    elif sn_family == SN_TYP_GENERIC:
        if sn_sub == SN_GEN_REQUESTxVERS:
            sn = snac(SN_TYP_GENERIC, SN_GEN_VERSxRESPONSE, 0, 0, make_fam_vers_list())
            fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
            sn = snac(SN_TYP_GENERIC, SN_GEN_MOTD, 0, 0, make_motd())
            fl2 = flap(FLAP_FRAME_DATA, connections[fileno].osequence + 1, sn.make_snac_tlv())
            connections[fileno].flap.put((fl.add_make_flap(fl2), 2))
        elif sn_sub == SN_GEN_REQUESTxRATE:
            sn = snac(SN_TYP_GENERIC, SN_GEN_RATExRESPONSE, 0, 0, make_rate_info() + make_rate_groups())
            fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
            connections[fileno].flap.put((fl.make_flap(), 1))
        elif sn_sub == SN_GEN_RATExACK:
            pass
        elif sn_sub == SN_GEN_INFOxREQUEST:
            sn = snac(SN_TYP_GENERIC, SN_GEN_INFOxRESPONSE, 0, 0, make_self_info(fileno))
            fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
            connections[fileno].flap.put((fl.make_flap(), 1))
        else:
            print "unknown snac(%s,%s)" % (sn_family, sn_sub)
    
    else:
        print "unknown snac(%s,%s)" % (sn_family, sn_sub)
            

def main():
    
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversocket.bind((cnf.get('general', 'serv_addr'), cnf.getint('general', 'serv_port')))
    serversocket.listen(cnf.getint('general', 'connections_listen'))
    serversocket.setblocking(0)
    serversocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    _poll.register(serversocket.fileno(), _events.EPOLLIN)
    
    try:
        while True:
            events = _poll.poll(1)
            for fileno, event in events:
                #print len(connections)
                if fileno == serversocket.fileno():
                    connection, address = serversocket.accept()
                    connection.setblocking(0)
                    connections[connection.fileno()] = Connection(connection, address)
                    seq = random.randrange(0xFFFF)
                    fl = flap(FLAP_FRAME_SIGNON, seq, struct.pack('!i', FLAP_VERSION))
                    connections[connection.fileno()].osequence = seq
                        
                    #for stupid clients like qip2005
                    time.sleep(cnf.getint('general', 'new_connection_delay'))
                    
                    connections[connection.fileno()].flap.put((fl.make_flap(), 1))
                    _poll.register(connection.fileno(), _events.EPOLLIN | _events.EPOLLOUT)
                elif event & _events.EPOLLIN:
                    #print "Ready to in: ", fileno
                    fl = flap()
                    conn = connections[fileno].connection.recv(FLAP_HDR_SIZE)
                    if (not conn) or (len(conn) < FLAP_HDR_SIZE):
                        _poll.modify(fileno, 0)
                        try:
                            connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                        except:
                            pass
                    else:
                        a = fl.parse_hdr(conn)
                        if a:
                            if a <= FLAP_MAX_SIZE:
                                if (not connections[fileno].isequence) or connections[fileno].isequence == fl.sequence:
                                    if not connections[fileno].isequence:
                                        connections[fileno].isequence = fl.sequence + 1
                                    else:
                                        connections[fileno].isequence += 1
                                    fl.data = connections[fileno].connection.recv(a)
                                    if len(fl.data) == a:
                                        q.put((fl, fileno))
                                    else:
                                        _poll.modify(fileno, 0)
                                        try:
                                            connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                                        except:
                                            pass
                                    
                                else:
                                    _poll.modify(fileno, 0)
                                    try:
                                        connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                                    except:
                                        pass
                            else:
                                _poll.modify(fileno, 0)
                                try:
                                    connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                                except:
                                    pass
                elif event & _events.EPOLLOUT:
                    #print "Ready to out: ", fileno
                    if not connections[fileno].flap.empty():
                        qsize = connections[fileno].flap.qsize()
                        tfl = ""
                        while (qsize):
                            fl, oseq = connections[fileno].flap.get()
                            tfl += fl
                            connections[fileno].osequence += oseq
                            qsize -= 1
                        
                        connections[fileno].connection.send(tfl)
                    if connections[fileno].flap.empty():
                        _poll.modify(fileno, _events.EPOLLIN)
                elif event & _events.EPOLLHUP:
                    #print "Close connection: ", fileno
                    _poll.unregister(fileno)
                    connections[fileno].connection.close()
                    del connections[fileno]
                elif event & _events.EPOLLERR:
                    print "Error connection: ", fileno
    finally:
        _poll.unregister(serversocket.fileno())
        _poll.close()
        serversocket.close()
    
# A revised version of our thread class:
class handlerThread(Thread):

# Note that we do not override Thread's __init__ method.
# The Queue module makes this not necessary.

    def run(self):
        
        # Have our thread serve "forever":
        while True:
            # Get a client out of the queue
            fl, fileno = q.get()
            
            # Check if we actually have an actual client in the client variable:
            if fl != None:
                if fl.channel == FLAP_FRAME_SIGNON:
                    if not connections[fileno].accepted:
                        connections[fileno].accepted = True
#                            else:
#                                epoll.modify(fileno, 0)
#                                connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                    #print "New_connect tail:", tohex(fl.data[4:])
                    tlvc = parse_tlv(fl.data[4:])
                    if FL_SIGNON_COOKIE in tlvc:
                        #print "Second connect"
                        a = db.db_get_cookie(tlvc[FL_SIGNON_COOKIE], cnf.getint('general', 'cookie_lifetime'))
                        #print str(a)
                        if a:
                            connections[fileno].uin = a
                            sn = snac(SN_TYP_GENERIC, SN_GEN_SERVERxFAMILIES, 0, 0, make_fam_list())
                            fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
                            sn = snac(SN_TYP_GENERIC, SN_GEN_WELLxKNOWNxURLS, 0, 0, make_well_known_url())
                            fl2 = flap(FLAP_FRAME_DATA, connections[fileno].osequence + 1, sn.make_snac_tlv())
                            connections[fileno].flap.put((fl.add_make_flap(fl2), 2))
                            _poll.modify(fileno, _events.EPOLLIN | _events.EPOLLOUT)
                elif connections[fileno].accepted and fl.channel == FLAP_FRAME_DATA:
                    parse_snac(fl.data, fileno)
                    _poll.modify(fileno, _events.EPOLLIN | _events.EPOLLOUT)
                elif fl.channel == FLAP_FRAME_SIGNOFF:
                    _poll.modify(fileno, 0)
                    connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                

if __name__ == '__main__':
    if hasattr(select, "epoll"):
        # Python 2.6+ on Linux
        _events = select
        _poll = select.epoll()
    elif hasattr(select, "kqueue"):
        # BSD
        from eventhandlers._kqueue import _kqueue
        _events = _kqueue()
        _poll = _kqueue()
    else:
        # All other systems
        from eventhandlers._select import _select
        _events = _select()
        _poll = _select()
    
    handlerThread().start()
    #handlerThread().start()
    main()


