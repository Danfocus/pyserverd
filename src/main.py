'''
Created on 31.12.2009

@author: danfocus
'''
#import cProfile
#import pstats

from config import Config
cnf = Config()

#import logging
import logging.handlers

formatter = logging.Formatter('%(asctime)s - %(clientip)s %(dirn)s\n%(message)s\n')

deflogger = logging.getLogger('Logger')
deflogger.setLevel(logging.INFO)
if cnf.logfile_enable:
    deffh = logging.handlers.RotatingFileHandler(cnf.logfile, maxBytes=cnf.logfile_size, backupCount=5)
    deffh.setFormatter(formatter)
else:
    deffh = logging.NullHandler()
deflogger.addHandler(deffh)

debuglogger = logging.getLogger('Debug_logger')
debuglogger.setLevel(logging.DEBUG)
if cnf.debuglog_enable:
    debfh = logging.handlers.RotatingFileHandler(cnf.debuglog, maxBytes=cnf.debuglog_size, backupCount=5)
    debfh.setFormatter(formatter)
else:
    debfh = logging.NullHandler()
debuglogger.addHandler(debfh)

from connection import connection

from snac_families import *

from tlv_procs import parse_tlv
from snac import snac
from flap import flap

import select

from dbconn import dbconn
#db = dbconn().db

import socket
import struct
import Queue
import random
import time

import common

from threading import Thread, Condition

from defines import * #@UnusedWildImport

q = Queue.Queue()

connections = {}

cond = Condition()


def parse_snac(str_, connection):
    """
    Use for parse snac
    """
    sn_family = (ord(str_[0]) << 8) + ord(str_[1])
    sn_sub = (ord(str_[2]) << 8) + ord(str_[3])
    str_ = str_[10:]
    debuglogger.debug("FLAP CH(2): SNAC(%02d,%02d):\n%s" % (sn_family, sn_sub, common.hex_data_f(str_)), extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
    if sn_family == SN_TYP_GENERIC:
        sn01_generic.parse_snac(sn_sub, connection, str_)
    elif sn_family == SN_TYP_LOCATION:
        sn02_location.parse_snac(sn_sub, connection, str_)
    elif sn_family == SN_TYP_BUDDYLIST:
        sn03_buddylist.parse_snac(sn_sub, connection)
    elif sn_family == SN_TYP_MESSAGING:
        sn04_messaging.parse_snac(sn_sub, connection, str_)
    elif sn_family == SN_TYP_BOS:
        sn09_bos.parse_snac(sn_sub, connection)
    elif sn_family == SN_TYP_SSI:
        sn19_ssi.parse_snac(sn_sub, connection, str_)
    elif sn_family == SN_TYP_REGISTRATION:
        sn23_registration.parse_snac(sn_sub, connection, str_)
    else:
        deflogger.warning("UNKNOWN SNAC(%02d,%02d)" % (sn_family, sn_sub), extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
        debuglogger.warning("UNKNOWN SNAC(%02d,%02d)" % (sn_family, sn_sub), extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})

def main():
    
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversocket.bind((cnf.serv_addr, cnf.serv_port))
    serversocket.listen(cnf.connections_listen)
    serversocket.setblocking(0)
    serversocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    _poll.register(serversocket.fileno(), _events.EPOLLIN)
    
    try:
        while True:
            events = _poll.poll(cnf.pool_timeout)
            for fileno, event in events:
                #print len(connections)
                if fileno == serversocket.fileno():
                    conn, address = serversocket.accept()
                    conn.setblocking(0)
                    connections[conn.fileno()] = connection(conn, address)
                    connections[conn.fileno()].fileno = conn.fileno()
                    fl = flap(FLAP_FRAME_SIGNON, struct.pack('!i', FLAP_VERSION))
                    connections[conn.fileno()].osequence = random.randrange(65536)
                        
                    #for stupid clients like qip2005
                    time.sleep(cnf.new_connection_delay)
                    
                    connections[conn.fileno()].flap_put(fl)
                    cond.acquire()
                    cond.notifyAll()
                    cond.release()
                    #_poll.register(conn.fileno(), _events.EPOLLIN | _events.EPOLLOUT)
                elif event & _events.EPOLLOUT:
                    #print "Ready to out: ", fileno
                    if not connections[fileno].flap_empty():
                        qsize = connections[fileno].flap_qsize()
                        tfl = ""
                        while (qsize):
                            fl = connections[fileno].flap_get()
                            fl.sequence = connections[fileno].osequence
                            debuglogger.debug("%s" % fl, extra={'clientip': connections[fileno].address[0], 'dirn': '--OUT-->>'})
                            fl = fl.make_flap()
                            if (len(tfl) + len(fl)) > FLAP_MAX_SIZE:
                                connections[fileno].send(tfl)
                                tfl = ""
                            tfl += fl
                            connections[fileno].osequence += 1
                            qsize -= 1
                        
                        connections[fileno].send(tfl)
                    cond.acquire()
                    cond.notifyAll()
                    cond.release()
                    #if connections[fileno].flap_empty():
                    #    _poll.modify(fileno, _events.EPOLLIN)
                elif event & _events.EPOLLIN:
                    #print "Ready to in: ", fileno
                    fl = flap()
                    conn = connections[fileno].recv(FLAP_HDR_SIZE)
                    if (not conn) or (len(conn) < FLAP_HDR_SIZE):
                        _poll.modify(fileno, 0)
                        try:
                            connections[fileno].shutdown()
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
                                    fl.content = connections[fileno].recv(a)
                                    if len(fl.content) == a:
                                        q.put((fl, fileno))
                                    else:
                                        _poll.modify(fileno, 0)
                                        try:
                                            connections[fileno].shutdown()
                                        except:
                                            pass
                                    
                                else:
                                    _poll.modify(fileno, 0)
                                    try:
                                        connections[fileno].shutdown()
                                    except:
                                        pass
                            else:
                                _poll.modify(fileno, 0)
                                try:
                                    connections[fileno].shutdown()
                                except:
                                    pass
                elif event & _events.EPOLLHUP:
                    deflogger.info("Close connection: %d" % fileno, extra={'clientip': connections[fileno].address[0], 'dirn': ''})
                    _poll.unregister(fileno)
                    del connections[fileno]
                elif event & _events.EPOLLERR:
                    deflogger.info("Error connection: %d" % fileno, extra={'clientip': connections[fileno].address[0], 'dirn': ''})
    finally:
        _poll.unregister(serversocket.fileno())
        _poll.close()
        serversocket.close()
    
# A revised version of our thread class:
class handlerThread(Thread):
    
    def run(self):

        db = dbconn().db
        
        # Have our thread serve "forever":
        while True:
            # Get a client out of the queue
            fl, fileno = q.get()
            
            # Check if we actually have an actual client in the client variable:
            if fl != None:
                #fl.parse_flap(connections[fileno], db)
                if fl.channel == FLAP_FRAME_SIGNON:
                    if connections[fileno].status == 0:
                        connections[fileno].status = 1
#                            else:
#                                epoll.modify(fileno, 0)
#                                connections[fileno].shutdown()
                    #print "New_connect tail:", tohex(fl.content[4:])
                    tlvc = parse_tlv(fl.content[4:])
                    if FL_SIGNON_COOKIE in tlvc:
                        #print "Second connect"
                        a = db.db_get_cookie(tlvc[FL_SIGNON_COOKIE], cnf.cookie_lifetime)
                        #print str(a)
                        if a:
                            connections[fileno].uin = a
                            #sn = snac(SN_TYP_GENERIC, SN_GEN_SERVERxFAMILIES, 0, 0, make_fam_list())
                            sn = snac(SN_TYP_GENERIC, SN_GEN_SERVERxFAMILIES, 0, 0, 0)
                            sn.make_fam_list()
                            fl = flap(FLAP_FRAME_DATA, sn)
                            connections[fileno].flap_put(fl)
                            #sn = snac(SN_TYP_GENERIC, SN_GEN_WELLxKNOWNxURLS, 0, 0, make_well_known_url())
                            sn = snac(SN_TYP_GENERIC, SN_GEN_WELLxKNOWNxURLS, 0, 0, 0)
                            sn.make_well_known_url()
                            fl = flap(FLAP_FRAME_DATA, sn)
                            connections[fileno].flap_put(fl)
                            cond.acquire()
                            cond.notifyAll()
                            cond.release()
                            #_poll.modify(fileno, _events.EPOLLIN | _events.EPOLLOUT)
                            connections[fileno].status = 4
                elif connections[fileno].status and fl.channel == FLAP_FRAME_DATA:
                    if connections[fileno].status > 0:
                        parse_snac(fl.content, connections[fileno])
                        cond.acquire()
                        cond.notifyAll()
                        cond.release()
                        #if not connections[fileno].flap_empty():
                        #    _poll.modify(fileno, _events.EPOLLIN | _events.EPOLLOUT)
                elif fl.channel == FLAP_FRAME_SIGNOFF:
                    _poll.modify(fileno, 0)
                    connections[fileno].shutdown()

class queueHandler(Thread):
    
    def run(self):
        while True:
            for a in connections.values():
                if not a.flap_empty():
                    try:
                        _poll.modify(a.fileno, _events.EPOLLIN | _events.EPOLLOUT)
                    except:
                        _poll.register(a.fileno, _events.EPOLLIN | _events.EPOLLOUT)
                else:
                    try:
                        _poll.modify(a.fileno, _events.EPOLLIN)
                    except:
                        _poll.register(a.fileno, _events.EPOLLIN)
            
            cond.acquire()
            cond.wait()
            cond.release()

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
        
    
    queueHandler().start()
    handlerThread().start()
    handlerThread().start()
    handlerThread().start()
    main()

    #cProfile.run('main()', 'main_prof')
    #stats = pstats.Stats('main_prof')
    #stats.strip_dirs()
    #stats.sort_stats('time')
    #stats.print_stats(5)
