'''
Created on 10.02.2010

@author: User
'''
from defines import SN_LOC_RIGHTSxREQUEST, SN_TYP_LOCATION,\
    SN_LOC_RIGHTSxRESPONSE, FLAP_FRAME_DATA, RIGHTS_INFO

from snac import snac
from flap import flap
from tlv_c import tlv_c
from tlv_procs import make_tlv

def parse_snac(sn_sub, connection):
    if sn_sub == SN_LOC_RIGHTSxREQUEST:
        sn = snac(SN_TYP_LOCATION, SN_LOC_RIGHTSxRESPONSE, 0, 0, make_loc_rights_responce())
        fl = flap(FLAP_FRAME_DATA, connection.osequence, sn.make_snac_tlv())
        connection.flap.put((fl.make_flap(), 1))
    else:
        print "unknown snac(02,%s)" % sn_sub
        
def make_loc_rights_responce():
#    tl = []
#    for x,y in RIGHTS_INFO.iteritems():
#        tl.append(tlv_c(x,y,"!H"))
    tl = [tlv_c(x,y,"!H") for x,y in RIGHTS_INFO.iteritems()]
    return make_tlv(tl)