'''
Created on 08.02.2010

@author: danfocus
'''
import struct

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
    
