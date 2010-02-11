'''
Created on 05.02.2010

@author: danfocus
'''
from cnf import cnf
cnf = cnf.cnf

import struct
from defines import FLAP_STARTMARKER

class flap(object):
    '''
    classdocs
    '''

    def __init__(self, channel=None, data='', sequence=None):
        self.channel = channel
        self.data = data
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
        l = len(self.data)
        fmt = '!BBHH %ds' % l
        return struct.pack(fmt, FLAP_STARTMARKER, self.channel, self.sequence, l, self.data)
    
