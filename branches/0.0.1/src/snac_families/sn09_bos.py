'''
Created on 10.02.2010

@author: User
'''
from defines import SN_BOS_RIGHTSxREQUEST, SN_TYP_BOS, SN_BOS_RIGHTSxRESPONSE,\
    FLAP_FRAME_DATA
from snac import snac
from flap import flap
from tlv_procs import make_tlv
from tlv_c import tlv_c

def parse_snac(sn_sub, connection):
    if sn_sub == SN_BOS_RIGHTSxREQUEST:
        sn = snac(SN_TYP_BOS, SN_BOS_RIGHTSxRESPONSE, 0, 0, make_bos_rights_info())
        fl = flap(FLAP_FRAME_DATA, connection.osequence, sn.make_snac_tlv())
        connection.flap.put((fl.make_flap(), 1))
    else:
        print "unknown snac(9,%s)" % sn_sub
        
def make_bos_rights_info():
    return make_tlv([tlv_c(1,1000,"!H"), tlv_c(2,1000,"!H")])