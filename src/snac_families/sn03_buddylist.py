'''
Created on 10.02.2010

@author: User
'''

import logging
deflogger = logging.getLogger('Logger')

from defines import SN_BLM_RIGHTSxREQUEST, SN_TYP_BUDDYLIST, \
    SN_BLM_RIGHTSxRESPONSE, FLAP_FRAME_DATA, BLM_RIGHTS_INFO

from snac import snac
from flap import flap
from tlv_c import tlv_c
from tlv_procs import make_tlv

def parse_snac(sn_sub, connection):
    if sn_sub == SN_BLM_RIGHTSxREQUEST:
        sn = snac(SN_TYP_BUDDYLIST, SN_BLM_RIGHTSxRESPONSE, 0, 0, make_blm_rights_response())
        fl = flap(FLAP_FRAME_DATA, sn)
        connection.flap_put(fl)
    else:
        deflogger.info("UNKNOWN SNAC(03,%02d)" % sn_sub, extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
        
def make_blm_rights_response():
    tl = [tlv_c(x, y, "!H") for x, y in BLM_RIGHTS_INFO.iteritems()]
    return make_tlv(tl)
