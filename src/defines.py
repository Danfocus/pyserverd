'''
Created on 09.01.2010

@author: danfocus
'''

PACKET_MAX_SIZE = 8192


# FLAP
FLAP_STARTMARKER = 0x2A
FLAP_HDR_SIZE = 6
FLAP_VERSION = 1
FLAP_MAX_SIZE = PACKET_MAX_SIZE - FLAP_HDR_SIZE

#  FLAP frame types
FLAP_FRAME_SIGNON = 1
FLAP_FRAME_DATA = 2
FLAP_FRAME_ERROR = 3
FLAP_FRAME_SIGNOFF = 4
FLAP_FRAME_KEEP_ALIVE = 5

# FLAP signon tags
FL_SIGNON_NAME = 3
FL_SIGNON_COOKIE = 6
FL_SIGNON_COUNTRY = 14
FL_SIGNON_LANGUAGE = 15
FL_SIGNON_DISTR_NUM = 20
FL_SIGNON_ID_NUM = 22
FL_SIGNON_MAJOR_VERSION = 23
FL_SIGNON_MINOR_VERSION = 24
FL_SIGNON_POINT_VERSION = 25
FL_SIGNON_BUILD_NUM = 26
FL_SIGNON_RECONNECT = 148

# SNAC types
SN_TYP_GENERIC = 1
SN_TYP_LOCATION = 2
SN_TYP_BUDDYLIST = 3
SN_TYP_MESSAGING = 4
SN_TYP_BOS = 9
SN_TYP_SSI = 19
SN_TYP_REGISTRATION = 23

# SNAC 1 subtypes
SN_GEN_CLIENTxREADY = 2
SN_GEN_SERVERxFAMILIES = 3
SN_GEN_REQUESTxRATE = 6
SN_GEN_RATExRESPONSE = 7
SN_GEN_RATExACK = 8
SN_GEN_INFOxREQUEST = 14
SN_GEN_INFOxRESPONSE = 15
SN_GEN_MOTD = 19
SN_GEN_WELLxKNOWNxURLS = 21
SN_GEN_REQUESTxVERS = 23
SN_GEN_VERSxRESPONSE = 24
SN_GEN_SETxSTATUS = 30

# SNAC 2 subtypes
SN_LOC_RIGHTSxREQUEST = 2
SN_LOC_RIGHTSxRESPONSE = 3
SN_LOC_SETxUSERINFO = 4

# SNAC 3 subtypes
SN_BLM_RIGHTSxREQUEST = 2
SN_BLM_RIGHTSxRESPONSE = 3

# SNAC 4 subtypes
SN_MSG_ADDxICBMxPARAM = 2
SN_MSG_PARAMxREQUEST = 4
SN_MSG_PARAMxRESPONSE = 5

# SNAC 9 subtypes
SN_BOS_RIGHTSxREQUEST = 2
SN_BOS_RIGHTSxRESPONSE = 3

# SNAC 19 subtypes
SN_SSI_PARAMxREQUEST = 2
SN_SSI_PARAMxREPLY = 3
SN_SSI_ROASTERxREQUEST = 4
SN_SSI_ROASTERxREPLY = 6
SN_SSI_ITEMxUPDATE = 9
SN_SSI_CHANGExACK = 14

# SNAC 23 subtypes
SN_REG_AUTHxLOGIN = 2
SN_REG_LOGINxREPLY = 3
SN_REG_AUTHxREQUEST = 6
SN_REG_AUTHxKEY = 7

AIM_MD5_STRING = "AOL Instant Messenger (SM)"

MISMATCH_PASSWD = "http://www.aim.com/errors/MISMATCH_PASSWD.html?ccode=us&lang=en"

SUPPORTED_SERVICES = {1:4, 2:1, 3:1, 4:1, 8:1, 9:1, 10:1, 11:1, 12:1, 19:6, 21:2, 34:1, 36:1, 37:1}

WELL_KNOWN_URL = {3: 'http://api.icq.net/lifestream/',
                  4: 'http://lifestream.icq.com/lifestream/client/full',
                  5: 'http://lifestream.icq.com/lifestream/client/me',
                  7: 'http://lifestream.icq.com/lifestream/photo/',
                  8: 'http://lifestream.icq.com/photo/upload?',
                  9: 'http://api.icq.net/',
                  10: 'http://lifestream.icq.com/settings',
                  11: 'http://lifestream.icq.com/stream/',
                  15: 'http://lifestream.icq.com/',
                  16: 'http://lifestream.icq.com/photo/lifestream/',
                  17: 'http://files.mail.ru/cgi-bin/files/fajaxcall?ajax_call=1&func_name=cbChooseStorage&data=%5B%22%SIZE%%22%5D'}

RATE_CLASSES = (
                (1, 80, 2500, 2000, 1500, 800, 5855, 6000, 0, 0),
                (2, 80, 3000, 2000, 1500, 1000, 6000, 6000, 374, 0),
                (3, 20, 3100, 2500, 2000, 1500, 3500, 4500, 374, 0),
                (4, 20, 5500, 5300, 4200, 3000, 6000, 8000, 374, 0),
                (5, 10, 5500, 5300, 4200, 3000, 6000, 8000, 374, 0)
                )

RATE_GROUPS = {
                1:((1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8), (1, 9), (1, 10),
                   (1, 11), (1, 12), (1, 13), (1, 14), (1, 15), (1, 16), (1, 17), (1, 18), (1, 19),
                   (1, 20), (1, 21), (1, 22), (1, 23), (1, 24), (1, 25), (1, 26), (1, 27), (1, 28),
                   (1, 29), (1, 31), (1, 32), (1, 33), (1, 34), (1, 35), (1, 36), (1, 37), (1, 38),
                   (1, 39), (1, 40), (2, 1), (2, 2), (2, 3), (2, 4), (2, 6), (2, 7), (2, 8), (2, 10),
                   (2, 12), (2, 13), (2, 14), (2, 15), (2, 16), (2, 17), (2, 18), (2, 19), (2, 20),
                   (2, 21), (2, 22), (2, 23), (2, 24), (2, 25), (3, 1), (3, 2), (3, 3), (3, 6), (3, 7),
                   (3, 8), (3, 9), (3, 10), (3, 11), (3, 12), (3, 13), (3, 14), (3, 15), (3, 16), (3, 17),
                   (3, 18), (3, 19), (3, 20), (4, 1), (4, 2), (4, 3), (4, 4), (4, 5), (4, 7), (4, 8),
                   (4, 9), (4, 10), (4, 11), (4, 12), (4, 13), (4, 14), (4, 15), (4, 16), (4, 17),
                   (4, 18), (4, 19), (4, 20), (4, 21), (4, 22), (4, 23), (4, 24), (4, 25), (6, 1),
                   (6, 2), (6, 3), (8, 1), (8, 2), (9, 1), (9, 2), (9, 3), (9, 4), (9, 9), (9, 10),
                   (9, 11), (10, 1), (10, 2), (10, 3), (11, 1), (11, 2), (11, 3), (11, 4), (12, 1),
                   (12, 2), (12, 3), (19, 1), (19, 2), (19, 3), (19, 4), (19, 5), (19, 6), (19, 7),
                   (19, 8), (19, 9), (19, 10), (19, 11), (19, 12), (19, 13), (19, 14), (19, 15), (19, 16),
                   (19, 17), (19, 18), (19, 19), (19, 20), (19, 21), (19, 22), (19, 23), (19, 24),
                   (19, 25), (19, 26), (19, 27), (19, 28), (19, 29), (19, 30), (19, 31), (19, 32),
                   (19, 33), (19, 34), (19, 35), (19, 36), (19, 37), (19, 38), (19, 39), (19, 40),
                   (19, 41), (19, 42), (19, 43), (19, 44), (19, 45), (19, 46), (19, 47), (19, 48),
                   (19, 49), (19, 50), (19, 51), (19, 52), (19, 53), (19, 54), (19, 55), (19, 56),
                   (19, 57), (19, 58), (19, 59), (19, 60), (19, 61), (19, 62), (19, 63), (19, 64),
                   (19, 65), (19, 66), (19, 67), (19, 68), (19, 69), (19, 70), (19, 71), (19, 72),
                   (19, 73), (19, 74), (19, 75), (19, 76), (19, 77), (19, 78), (19, 79), (19, 80),
                   (19, 81), (19, 82), (21, 1), (21, 2), (21, 3), (34, 1), (34, 2), (34, 3), (36, 1),
                   (36, 2), (36, 3), (36, 4), (36, 5), (36, 6), (36, 7), (36, 8), (36, 9), (36, 10),
                   (36, 11), (36, 12), (36, 13), (36, 14), (36, 15), (36, 16), (36, 17), (36, 18),
                   (36, 19), (36, 20), (36, 21), (36, 22), (36, 23), (36, 24), (36, 25), (36, 26),
                   (36, 27), (36, 28), (36, 29), (36, 30), (36, 31), (36, 32), (36, 33), (36, 34),
                   (36, 35), (36, 36), (36, 37), (36, 38), (36, 39), (36, 40), (36, 41), (36, 42),
                   (36, 43), (36, 44), (36, 45), (36, 46), (36, 47), (36, 48), (36, 49), (36, 50),
                   (36, 51), (36, 52), (36, 53), (36, 54), (36, 55), (36, 56), (36, 57), (36, 58),
                   (36, 59), (36, 60), (36, 61), (36, 62), (36, 63), (36, 64), (36, 65), (36, 66),
                   (36, 67), (36, 68), (36, 69), (36, 70), (36, 71), (36, 72), (36, 73), (36, 74),
                   (36, 75), (36, 76), (36, 77), (36, 78), (36, 79), (36, 80), (36, 81), (36, 82),
                   (36, 83), (36, 84), (36, 85), (36, 86), (36, 87), (36, 88), (36, 89), (36, 90),
                   (36, 91), (36, 92), (37, 2), (37, 4), (37, 6)),
                2:((3, 4), (3, 5), (9, 5), (9, 6), (9, 7), (9, 8)),
                3:((1, 30), (2, 5), (4, 6)),
                4:((2, 9), (2, 11)),
                5:()
               }

MAX_FOR_ITEMS = (3000, 100, 1000, 1000, 1, 1, 50, 0, 0, 3, 0, 0, 0, 128, 1000, 20, 200, 1, 0, 1, 15, 1, 40, 0, 0, 200, 1, 20, 200, 1, 8, 20, 1, 0, 0, 0, 50, 0, 5, 500, 1, 8)

LOC_RIGHTS_INFO = {1:4096, 2:18, 5:128, 3:10, 4:4096}

BLM_RIGHTS_INFO = {2:3000, 1:1000, 3:512, 4:160}

ICBM_PARAMS = {4: (3, 512, 900, 999, 1000)}

