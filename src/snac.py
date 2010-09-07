'''
Created on 05.02.2010

@author: danfocus
'''

import struct

class snac(object):
    '''
    classdocs
    '''
    family = None
    subtype = None
    flags = 0
    id = 0
    data = 0

    def __init__(self, family, subtype, flags, id, data):
        self.family = family
        self.subtype = subtype
        self.flags = flags
        self.id = id
        self.data = data
    def parse_hdr(self, str_):
        if len(str_) > 3:
            return (ord(str_[0]) << 8) + ord(str_[1]), (ord(str_[2]) << 8) + ord(str_[3])
        else:
            return False
    def make_snac(self):
        l = len(self.data)
        fmt = '!HHHIH %ds' % l
        return struct.pack(fmt, self.family, self.subtype, self.flags, self.id, l, self.data)
    def make_snac_tlv(self):
        l = len(self.data)
        fmt = '!HHHI %ds' % l
        return struct.pack(fmt, self.family, self.subtype, self.flags, self.id, self.data)
        