'''
Created on 31.12.2009

@author: danfocus
'''
import snac_families.sn01_generic
import snac_families.sn19_ssi
import snac_families.sn23_registration

from tlv_procs import parse_tlv
from snac import snac
from flap import flap

from cnf import cnf
cnf = cnf.cnf

from eventhandlers import _poll
_events = _poll._poll._events
_poll = _poll._poll._poll

from db import db
db = db.db

import socket
import struct
import Queue
import random
import time
#import logging

from threading import Thread

from defines import * #@UnusedWildImport

q = Queue.Queue()

connections = {}


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
        self.fileno = None
        self.flap = Queue.Queue()

def make_fam_list():
    slist = [struct.pack('!H', x) for x in SUPPORTED_SERVICES.keys()]
    text = "".join(slist)
    return text

def make_well_known_url():
    slist = [struct.pack("!HH %ds" % len(y), x, len(y), y) for x, y in WELL_KNOWN_URL.iteritems()]
    text = "".join(slist)
    return text

def parse_snac(str_, connection):
    sn_family = (ord(str_[0]) << 8) + ord(str_[1])
    sn_sub = (ord(str_[2]) << 8) + ord(str_[3])
    #print sn_family, sn_sub
    if sn_family == SN_TYP_REGISTRATION:
        snac_families.sn23_registration.parse_snac_registration(sn_sub, connection, str_)
    elif sn_family == SN_TYP_GENERIC:
        snac_families.sn01_generic.parse_snac_generic(sn_sub, connection)
    elif sn_family == SN_TYP_SSI:
        snac_families.sn19_ssi.parse_snac_ssi(sn_sub, connection)
            #sn = snac(SN_TYP_SSI, SN_SSI_PARAMxREPLY, 0, 0, make_ssi_param())
            #fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
            #connections[fileno].flap.put((fl.make_flap(), 1))
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
                    connections[connection.fileno()].fileno = fileno
                    seq = random.randrange(65536)
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
                #fl.parse_flap(connections[fileno], db)
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
                    parse_snac(fl.data, connections[fileno])
                    _poll.modify(fileno, _events.EPOLLIN | _events.EPOLLOUT)
                elif fl.channel == FLAP_FRAME_SIGNOFF:
                    _poll.modify(fileno, 0)
                    connections[fileno].connection.shutdown(socket.SHUT_RDWR)
                

if __name__ == '__main__':
    handlerThread().start()
    #handlerThread().start()
    main()


