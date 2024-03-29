'''
Created on 10.02.2010

@author: User
'''

import logging
deflogger = logging.getLogger('Logger')

from defines import SN_LOC_RIGHTSxREQUEST, SN_TYP_LOCATION, \
    SN_LOC_RIGHTSxRESPONSE, FLAP_FRAME_DATA, LOC_RIGHTS_INFO, \
    SN_LOC_SETxUSERINFO

from snac import snac
from flap import flap
from tlv_c import tlv_c
from tlv_procs import make_tlv, parse_tlv

def parse_snac(sn_sub, connection, str_):
    if sn_sub == SN_LOC_RIGHTSxREQUEST:
        sn = snac(SN_TYP_LOCATION, SN_LOC_RIGHTSxRESPONSE, 0, 0, make_loc_rights_response())
        fl = flap(FLAP_FRAME_DATA, sn)
        connection.flap_put(fl)
    elif sn_sub == SN_LOC_SETxUSERINFO:
        tlvs = parse_tlv(str_)
        if 5 in tlvs:
            connection.caps = tlvs[5]
        if 4 in tlvs:
            connection.away = tlvs[4]
    else:
        deflogger.info("UNKNOWN SNAC(02,%02d)" % sn_sub, extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
        
def make_loc_rights_response():
    tl = [tlv_c(x, y, "!H") for x, y in LOC_RIGHTS_INFO.iteritems()]
    return make_tlv(tl)

