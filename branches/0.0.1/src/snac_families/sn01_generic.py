'''
Created on 08.02.2010

@author: danfocus
'''

from snac import snac
from tlv_c import tlv_c
from tlv_procs import make_tlvblock, parse_tlv
from defines import * #@UnusedWildImport
from flap import flap

import socket
import struct

from db import db
db = db.db

def parse_snac(sn_sub, connection, str_):
    if sn_sub == SN_GEN_CLIENTxREADY:
        pass
    elif sn_sub == SN_GEN_REQUESTxVERS:
        sn = snac(SN_TYP_GENERIC, SN_GEN_VERSxRESPONSE, 0, 0, make_fam_vers_list())
        fl = flap(FLAP_FRAME_DATA, sn.make_snac_tlv())
        connection.flap.put(fl)
        sn = snac(SN_TYP_GENERIC, SN_GEN_MOTD, 0, 0, make_motd())
        fl = flap(FLAP_FRAME_DATA, sn.make_snac_tlv())
        connection.flap.put(fl)
    elif sn_sub == SN_GEN_REQUESTxRATE:
        sn = snac(SN_TYP_GENERIC, SN_GEN_RATExRESPONSE, 0, 0, make_rate_info() + make_rate_groups())
        fl = flap(FLAP_FRAME_DATA, sn.make_snac_tlv())
        connection.flap.put(fl)
    elif sn_sub == SN_GEN_RATExACK:
        pass
    elif sn_sub == SN_GEN_SETxSTATUS:
        str_ = str_[10:]
        tlvs = parse_tlv(str_)
        if 6 in tlvs:
            pass
        if 8 in tlvs:
            pass
        if 12 in tlvs:
            pass
        if 31 in tlvs:
            pass
    elif sn_sub == SN_GEN_INFOxREQUEST:
        sn = snac(SN_TYP_GENERIC, SN_GEN_INFOxRESPONSE, 0, 0, make_self_info(connection, db))
        fl = flap(FLAP_FRAME_DATA, sn.make_snac_tlv())
        connection.flap.put(fl)
    else:
        print "unknown snac(1,%s)" % sn_sub
        
def make_fam_vers_list():
    slist = [struct.pack('!HH', x, y) for x, y in SUPPORTED_SERVICES.iteritems()]
    text = "".join(slist)
    return text

def make_motd():
    return struct.pack("!HHHHHHH" , 5, 2, 2, 30, 3, 2, 1200)

def make_rate_info():
    slist = [struct.pack("!HIIIIIIIIB", x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9]) for x in RATE_CLASSES]
    text = "".join(slist)
    return struct.pack("!H", len(RATE_CLASSES)) + text

#def make_rate_gr(tpl):
#    slist = [struct.pack("!HH" , x[0], x[1]) for x in tpl]
#    text = "".join(slist)
#    return text

def make_rate_groups():
    #slist = [struct.pack("!HH %ds" % len(make_rate_gr(y)), x, len(y), make_rate_gr(y)) for x, y in RATE_GROUPS.iteritems()]
    slist = [struct.pack("!HH %ds" % len("".join([struct.pack("!HH" , z[0], z[1]) for z in y])), x, len(y), "".join([struct.pack("!HH" , z[0], z[1]) for z in y])) for x, y in RATE_GROUPS.iteritems()]
    text = "".join(slist)
    return text

def make_self_info(connection, db):
    tl = [tlv_c(1, 81, '!H'),
          tlv_c(12, '', '37s'),
          tlv_c(10, socket.inet_aton(connection.address[0]))]
    tl.append(tlv_c(5, db.db_select_unixtimestamp_users_where("member_since", connection.uin)[0], '!I'))
    tl.append(tlv_c(15, 1, '!I'))
    online_since = db.db_select_unixtimestamp_users_where("online_since", connection.uin)[0]
    if not online_since:
        db.db_update_users_where('online_since', 'NOW()', connection.uin)
        online_since = db.db_select_unixtimestamp_users_where("online_since", connection.uin)[0]
    tl.append(tlv_c(3, online_since, '!I'))
    tl.append(tlv_c(21, 2048, '!I'))
    tl.append(tlv_c(34, 38710, '!H'))
    tl.append(tlv_c(30, 0, '!I'))
    tl.append(tlv_c(40, 0, '!B'))
    tl.append(tlv_c(45, 0, '!I'))
    tl.append(tlv_c(44, 0, '!I'))
    return struct.pack("!B %ds H" % len(str(connection.uin)), len(str(connection.uin)), str(connection.uin), 0) + make_tlvblock(tl)

