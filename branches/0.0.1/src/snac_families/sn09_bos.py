'''
Created on 10.02.2010

@author: User
'''

import logging
deflogger = logging.getLogger('Logger')

from defines import SN_BOS_RIGHTSxREQUEST, SN_TYP_BOS, SN_BOS_RIGHTSxRESPONSE,\
    FLAP_FRAME_DATA
    
from snac import snac
from flap import flap
from tlv_procs import make_tlv
from tlv_c import tlv_c

def parse_snac(sn_sub, connection):
    if sn_sub == SN_BOS_RIGHTSxREQUEST:
        sn = snac(SN_TYP_BOS, SN_BOS_RIGHTSxRESPONSE, 0, 0, make_bos_rights_info())
        fl = flap(FLAP_FRAME_DATA, sn)
        connection.flap_put(fl)
    else:
        deflogger.info("UNKNOWN SNAC(09,%02d)" % sn_sub, extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
        
def make_bos_rights_info():
    return make_tlv([tlv_c(1,1000,"!H"), tlv_c(2,1000,"!H")])