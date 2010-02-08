'''
Created on 05.02.2010

@author: danfocus
'''
from snac import snac
from tlv_procs import parse_tlv

from cnf import cnf
#cnf = cnf.cnf

#import snac_families.sn01_generic
#import snac_families.sn19_ssi
#import snac_families.sn23_registration

from eventhandlers import _poll
_events = _poll._poll._events
_poll = _poll._poll._poll

import socket

import struct
from defines import FLAP_STARTMARKER, FLAP_FRAME_SIGNOFF, FL_SIGNON_COOKIE,\
    FLAP_FRAME_DATA, SN_TYP_GENERIC, SN_GEN_SERVERxFAMILIES,\
    SN_GEN_WELLxKNOWNxURLS, FLAP_FRAME_SIGNON, SUPPORTED_SERVICES,\
    WELL_KNOWN_URL, SN_TYP_REGISTRATION, SN_TYP_SSI

class flap(object):
    '''
    classdocs
    '''
    cnf = cnf.cnf

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
        
#    def parse_flap(self, connection, db):
#        fileno = connection.fileno
#        if self.channel == FLAP_FRAME_SIGNON:
#            if not connection.accepted:
#                connection.accepted = True
##                            else:
##                                epoll.modify(fileno, 0)
##                                connections[fileno].connection.shutdown(socket.SHUT_RDWR)
#            #print "New_connect tail:", tohex(fl.data[4:])
#            tlvc = parse_tlv(self.data[4:])
#            if FL_SIGNON_COOKIE in tlvc:
#                #print "Second connect"
#                a = db.db_get_cookie(tlvc[FL_SIGNON_COOKIE], cnf.getint('general', 'cookie_lifetime'))
#                #print str(a)
#                if a:
#                    connection.uin = a
#                    sn = snac(SN_TYP_GENERIC, SN_GEN_SERVERxFAMILIES, 0, 0, make_fam_list())
#                    fl = flap(FLAP_FRAME_DATA, connection.osequence, sn.make_snac_tlv())
#                    sn = snac(SN_TYP_GENERIC, SN_GEN_WELLxKNOWNxURLS, 0, 0, make_well_known_url())
#                    fl2 = flap(FLAP_FRAME_DATA, connection.osequence + 1, sn.make_snac_tlv())
#                    connection.flap.put((fl.add_make_flap(fl2), 2))
#                    _poll.modify(fileno, _events.EPOLLIN | _events.EPOLLOUT)
#        elif connection.accepted and self.channel == FLAP_FRAME_DATA:
#            parse_snac(self.data, connection, db)
#            _poll.modify(fileno, _events.EPOLLIN | _events.EPOLLOUT)
#        elif self.channel == FLAP_FRAME_SIGNOFF:
#            _poll.modify(fileno, 0)
#            connection.connection.shutdown(socket.SHUT_RDWR)
#    
#def make_fam_list():
#    slist = [struct.pack('!H', x) for x in SUPPORTED_SERVICES.keys()]
#    text = "".join(slist)
#    return text
#
#def make_well_known_url():
#    slist = [struct.pack("!HH %ds" % len(y), x, len(y), y) for x, y in WELL_KNOWN_URL.iteritems()]
#    text = "".join(slist)
#    return text

#def parse_snac(str_, connection, db):
#    sn_family = (ord(str_[0]) << 8) + ord(str_[1])
#    sn_sub = (ord(str_[2]) << 8) + ord(str_[3])
#    #print sn_family, sn_sub
#    if sn_family == SN_TYP_REGISTRATION:
#        snac_families.sn23_registration.parse_snac_registration(sn_sub, connection, db, str_)
#    elif sn_family == SN_TYP_GENERIC:
#        snac_families.sn01_generic.parse_snac_generic(sn_sub,connection,db)
#    elif sn_family == SN_TYP_SSI:
#        snac_families.sn19_ssi.parse_snac_ssi(sn_sub, connection, db)
#            #sn = snac(SN_TYP_SSI, SN_SSI_PARAMxREPLY, 0, 0, make_ssi_param())
#            #fl = flap(FLAP_FRAME_DATA, connections[fileno].osequence, sn.make_snac_tlv())
#            #connections[fileno].flap.put((fl.make_flap(), 1))
#    else:
#        print "unknown snac(%s,%s)" % (sn_family, sn_sub)
            
    