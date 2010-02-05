'''
Created on 05.02.2010

@author: danfocus
'''

import struct

class snac(object):
    '''
    classdocs
    '''

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
        