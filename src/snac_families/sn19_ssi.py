'''
Created on 08.02.2010

@author: danfocus
'''
from defines import SN_SSI_PARAMxREQUEST

from db import db
db = db.db

def parse_snac_ssi(sn_sub, connection):
    if sn_sub == SN_SSI_PARAMxREQUEST:
        pass
    else:
        print "unknown snac(19,%s)" % sn_sub