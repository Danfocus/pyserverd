'''
Created on 08.02.2010

@author: danfocus
'''

import logging
deflogger = logging.getLogger('Logger')

from defines import MISMATCH_PASSWD, SN_TYP_REGISTRATION, FLAP_FRAME_DATA, \
    AIM_MD5_STRING, SN_REG_AUTHxREQUEST, SN_REG_LOGINxREPLY, SN_REG_AUTHxKEY, \
    SN_REG_AUTHxLOGIN, FLAP_FRAME_SIGNOFF

from tlv_c import tlv_c
from tlv_procs import make_tlv, parse_tlv
from flap import flap
from snac import snac

import struct
import hashlib
import random

from config import Config
cnf = Config()

from dbconn import dbconn
db = dbconn().db


def parse_snac(sn_sub, connection, str_):
    if sn_sub == SN_REG_AUTHxREQUEST:
        if connection.status == 1:
            tlvc = parse_tlv(str_)
            if db.db_select_users_where("uin", tlvc[1])[0]:
                challenge = str(random.randint(1000000000, 9999999999))
                db.db_set_challenge(tlvc[1], challenge)
                sn = snac(SN_TYP_REGISTRATION, SN_REG_AUTHxKEY, 0, 0, challenge, True)
                fl = flap(FLAP_FRAME_DATA, sn)
                connection.flap_put(fl)
                connection.status = 2
            else:
                tl = [tlv_c(1, tlvc[1]), tlv_c(4, MISMATCH_PASSWD), tlv_c(8, 5, '!H')]
                sn = snac(SN_TYP_REGISTRATION, SN_REG_LOGINxREPLY, 0, 0, make_tlv(tl))
                fl = flap(FLAP_FRAME_DATA, sn)
                connection.flap_put(fl)
                fl = flap(FLAP_FRAME_SIGNOFF)
                connection.flap_put(fl)
            return
    elif sn_sub == SN_REG_AUTHxLOGIN:
        if connection.status == 2:
            m = hashlib.md5()
            tlvc = parse_tlv(str_)
            challenge = db.db_get_challenge(tlvc[1], cnf.cookie_lifetime)
            if challenge:
                password = db.db_select_users_where("password", tlvc[1])[0]
                if password:
                    m.update(challenge)
                    if 76 in tlvc:
                        m2 = hashlib.md5()
                        m2.update(password)
                        m.update(m2.digest())
                    else:
                        m.update(password)
                    m.update(AIM_MD5_STRING)
                    
                    if tlvc[37] == m.digest():
                        deflogger.info("Auth - OK", extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
                        cookie = generate_cookie()
                        db.db_set_cookie(tlvc[1], struct.pack("!%ds" % len(cookie), cookie))
                        tl = [tlv_c(1, tlvc[1]), tlv_c(5, cnf.bos_addr), tlv_c(6, cookie)]
                        a = make_tlv(tl)
                        sn = snac(SN_TYP_REGISTRATION, SN_REG_LOGINxREPLY, 0, 0, a)
                        fl = flap(FLAP_FRAME_DATA, sn)
                        connection.flap_put(fl)
                        fl = flap(FLAP_FRAME_SIGNOFF)
                        connection.flap_put(fl)
                        connection.status = 3
                    else:
                        deflogger.info("Auth - Fail - wrong password", extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
            else:
                deflogger.info("Auth - Fail - no challenge", extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
    else:
        deflogger.info("UNKNOWN SNAC(23,%02d)" % sn_sub, extra={'clientip': connection.address[0], 'dirn': '<<--IN--'})
        
def generate_cookie():
    slist = map(lambda x: chr(random.randint(0, 0xFF)),xrange(256))
    return "".join(slist)
        

