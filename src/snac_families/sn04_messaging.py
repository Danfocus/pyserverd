'''
Created on 10.02.2010

@author: User
'''
from defines import SN_MSG_PARAMxREQUEST, SN_TYP_MESSAGING,\
    SN_MSG_PARAMxRESPONSE, FLAP_FRAME_DATA

from snac import snac
from flap import flap
import struct

def parse_snac(sn_sub, connection):
    if sn_sub == SN_MSG_PARAMxREQUEST:
        sn = snac(SN_TYP_MESSAGING, SN_MSG_PARAMxRESPONSE, 0, 0, make_msg_param_info())
        fl = flap(FLAP_FRAME_DATA, sn.make_snac_tlv())
        connection.flap.put(fl)
    else:
        print "unknown snac(4,%s)" % sn_sub
        
def make_msg_param_info():
    return struct.pack("!HIHHHI", 4, 3, 512, 900, 999, 1000)