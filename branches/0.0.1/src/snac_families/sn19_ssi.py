'''
Created on 08.02.2010

@author: danfocus
'''
from defines import SN_SSI_PARAMxREQUEST, SN_SSI_PARAMxREPLY, SN_TYP_SSI, \
    FLAP_FRAME_DATA, MAX_FOR_ITEMS, SN_SSI_ROASTERxREQUEST, SN_SSI_ROASTERxREPLY,\
    SN_SSI_ITEMxUPDATE

from types import NoneType

from dbconn import dbconn
db = dbconn().db

import struct

from snac import snac
from flap import flap
from tlv_c import tlv_c
from tlv_procs import make_tlv


def parse_snac(sn_sub, connection, str_):
    if sn_sub == SN_SSI_PARAMxREQUEST:
        sn = snac(SN_TYP_SSI, SN_SSI_PARAMxREPLY, 0, 0, make_ssi_param())
        fl = flap(FLAP_FRAME_DATA, sn)
        connection.flap_put(fl)
    elif sn_sub == SN_SSI_ROASTERxREQUEST:
        sn = snac(SN_TYP_SSI, SN_SSI_ROASTERxREPLY, 0, 0, make_ssi_list(connection))
        fl = flap(FLAP_FRAME_DATA, sn)
        connection.flap_put(fl)
    elif sn_sub == SN_SSI_ITEMxUPDATE:
        #sn = snac(SN_TYP_SSI, SN_SSI_CHANGExACK, 0, 0, process_ssi_update(connection, str_))
        #fl = flap(FLAP_FRAME_DATA, sn)
        #connection.flap_put(fl)
        pass
    else:
        print "unknown snac(19,%s)" % sn_sub
        
def make_ssi_param():
    slist = [struct.pack("!H" , x) for x in MAX_FOR_ITEMS]
    tl = [tlv_c(4, "".join(slist)), tlv_c(2, 254, "!H"), tlv_c(3, 1698, "!H"), tlv_c(5, 100, "!H"), tlv_c(6, 97, "!H"),
          tlv_c(7, 200, "!H"), tlv_c(8, 10, "!H"), tlv_c(9, 432000, "!I"), tlv_c(10, 14, "!I"),
          tlv_c(11, 0, "!H"), tlv_c(12, 600, "!H"), tlv_c(13, 0, "!H"), tlv_c(14, 32, "!H")]
    return make_tlv(tl)

def make_ssi_list(connection):
    db.db_check_ssi(connection.uin)
    rows, udate = db.db_get_ssi(connection.uin)
#    for row in rows:
#        struct.pack("!H %ds 4H %s" % (len(row["name"]), len(row["text"])), len(row["name"]), row["name"], row["gid"], row["id"], row["type"], len(row["text"]), row["text"])
    slist = [struct.pack("!H %ds 4H %ds" % (len(row[3]), len(correct_value(row[4]))), len(row[3]), str(row[3]), row[0], row[1], row[2], len(correct_value(row[4])), correct_value(row[4])) for row in rows]
    return struct.pack("!BH", 0, len(rows)) + "".join(slist) + struct.pack("!I", udate)

def correct_value(str_):
    if type(str_) is NoneType:
        str_ = ''
    return str_      

def process_ssi_update(connection, str_):
    pass
