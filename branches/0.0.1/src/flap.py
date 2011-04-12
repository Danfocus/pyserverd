'''
Created on 05.02.2010

@author: danfocus
'''
import struct
from defines import FLAP_STARTMARKER
from snac import snac

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
        data=''
        if self.content:
            if isinstance(self.content, snac):
                data=self.content.make_snac()
            else:
                data=self.content
        l = len(data)
        fmt = '!BBHH %ds' % l
        return struct.pack(fmt, FLAP_STARTMARKER, self.channel, self.sequence, l, data)
    
    def hex_content(self):
        hex_ = map(lambda x: "%.2x" % ord(x), tuple(self.content))
        return " ".join(hex_)
    
    def __repr__(self):
        if isinstance(self.content, snac):
            data=self.content
        else:
            data=self.hex_content()
        return "FLAP CH(%d): %s" % (self.channel, data)
    
