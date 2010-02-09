'''
Created on 08.02.2010

@author: danfocus
'''
from defines import MISMATCH_PASSWD, SN_TYP_REGISTRATION, FLAP_FRAME_DATA,\
    AIM_MD5_STRING, SN_REG_AUTHxREQUEST, SN_REG_LOGINxREPLY, SN_REG_AUTHxKEY,\
    SN_REG_AUTHxLOGIN
from tlv_c import tlv_c
from tlv_procs import make_tlv, parse_tlv
#from flap import flap
from flap import flap
from snac import snac
from cnf import cnf
import struct
import hashlib
import random

cnf = cnf.cnf

from db import db
db = db.db

def parse_snac(sn_sub,connection,str_):
    if sn_sub == SN_REG_AUTHxREQUEST:
        challenge = str(random.randint(1000000000, 9999999999))
        tlvc = parse_tlv(str_[10:])
        if not db.db_set_challenge(tlvc[1], challenge):
            tl = [tlv_c(1, tlvc[1]), tlv_c(4, MISMATCH_PASSWD), tlv_c(8, 5, '!H')]
            sn = snac(SN_TYP_REGISTRATION, SN_REG_LOGINxREPLY, 0, 0, make_tlv(tl))
            fl = flap(FLAP_FRAME_DATA, connection.osequence, sn.make_snac_tlv())
            connection.flap.put((fl.make_flap_close(), 1))
            return
        sn = snac(SN_TYP_REGISTRATION, SN_REG_AUTHxKEY, 0, 0, challenge)
        fl = flap(FLAP_FRAME_DATA, connection.osequence, sn.make_snac())
        connection.flap.put((fl.make_flap(), 1))
    elif sn_sub == SN_REG_AUTHxLOGIN:
        m = hashlib.md5()
        tlvc = parse_tlv(str_[10:])
        challenge = db.db_get_challenge(tlvc[1], cnf.getint('general', 'cookie_lifetime'))
        if challenge:
            password = db.db_select_users_where("password", tlvc[1])[0]
            m.update(challenge)
            if 76 in tlvc:
                m2 = hashlib.md5()
                m2.update(password)
                m.update(m2.digest())
            else:
                m.update(password)
            m.update(AIM_MD5_STRING)
            
            if tlvc[37] == m.digest():
                print "Auth - OK"
                cookie = generate_cookie()
                db.db_set_cookie(tlvc[1], struct.pack("!%ds" % len(cookie), cookie))
                tl = [tlv_c(142, 0, 'B'), tlv_c(1, tlvc[1]), tlv_c(5, cnf.get('general', 'bos_addr')), tlv_c(6, cookie)]
                a = make_tlv(tl)
                sn = snac(SN_TYP_REGISTRATION, SN_REG_LOGINxREPLY, 0, 0, a)
                fl = flap(FLAP_FRAME_DATA, connection.osequence, sn.make_snac_tlv())
                connection.flap.put((fl.make_flap_close(), 1))
            else:
                print "Auth - Fail - wrong password"
        else:
            print "Auth - Fail - no challenge"
    else:
        print "unknown snac(23,%s)" % sn_sub
        
def generate_cookie():
    slist = map(lambda x: chr(random.randint(0, 0xFF)), xrange(256))
    return "".join(slist)
        
