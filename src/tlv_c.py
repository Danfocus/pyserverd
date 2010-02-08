'''
Created on 08.02.2010

@author: danfocus
'''
import struct

class tlv_c(object):
    '''
    classdocs
    '''


    def __init__(self, id, value, fmt=None):
        self.id = id
        if (not fmt) or (fmt[-1:] == 's'):
            self.value = str(value)
        else:
            if not value:
                value = 0
            self.value = value
             
        self.fmt = fmt
    def make_tlv_c(self):
        if self.fmt:
            value = struct.pack(self.fmt, self.value)
            l = len(str(value))
        else:
            l = len(self.value)
            value = struct.pack('%ds' % l, self.value)
        return struct.pack('!HH', self.id, l) + value
        