'''
Created on 05.02.2010

@author: danfocus
'''
import struct
from defines import FLAP_STARTMARKER
from snac import snac

import common

class flap(object):
    '''
    classdocs
    '''

    def __init__(self, channel=None, content='', sequence=None):
        self.channel = channel
        self.content = content
        self.sequence = sequence
    
    def parse_hdr(self, str_):
        if len(str_) > 5:
            if ord(str_[0]) != FLAP_STARTMARKER:
                return False
            self.channel = ord(str_[1])
            self.sequence = (ord(str_[2]) << 8) + ord(str_[3])
            return (ord(str_[4]) << 8) + ord(str_[5])
        else:
            return False
    
    def make_flap(self):
        data = ''
        if self.content:
            if isinstance(self.content, snac):
                data = self.content.make_snac()
            else:
                data = self.content
        l = len(data)
        fmt = '!BBHH %ds' % l
        return struct.pack(fmt, FLAP_STARTMARKER, self.channel, self.sequence, l, data)
    
    def __repr__(self):
        if isinstance(self.content, snac):
            data = self.content
        else:
            data = common.hex_data_f(self.content)
        return "------\nFLAP CH(%d): %s" % (self.channel, data)
    

