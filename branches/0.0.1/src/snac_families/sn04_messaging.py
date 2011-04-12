'''
Created on 10.02.2010

@author: User
'''
from defines import SN_MSG_PARAMxREQUEST, SN_TYP_MESSAGING,\
    SN_MSG_PARAMxRESPONSE, FLAP_FRAME_DATA, SN_MSG_ADDxICBMxPARAM, ICBM_PARAMS

from snac import snac
from flap import flap
import struct

def parse_snac(sn_sub, connection, str_):
    if sn_sub == SN_MSG_PARAMxREQUEST:
        sn = snac(SN_TYP_MESSAGING, SN_MSG_PARAMxRESPONSE, 0, 0, make_msg_param_info())
        connection.icbm[4] = ICBM_PARAMS.get(4)
        fl = flap(FLAP_FRAME_DATA, sn)
        connection.flap_put(fl)
    elif sn_sub == SN_MSG_ADDxICBMxPARAM:
        if len(str_) == 16:
            connection.icbm[struct.unpack("!H", str_[:2])[0]] = struct.unpack("!IHHHI", str_[2:]) 
    else:
        print "unknown snac(4,%s)" % sn_sub
        
def make_msg_param_info():
    a = ICBM_PARAMS.get(4)
    return struct.pack("!HIHHHI", 4, a[0], a[1], a[2], a[3], a[4])