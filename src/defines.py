'''
Created on 09.01.2010

@author: danfocus
'''

# FLAP
FLAP_STARTMARKER = 0x2A
FLAP_HRD_SIZE = 6
FLAP_VERSION = 1

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
SN_TYP_REGISTRATION = 23

# SNAC 1 subtypes
SN_GEN_SERVERxFAMILIES = 3
SN_GEN_MOTD = 19
SN_GEN_WELLxKNOWNxURLS = 21
SN_GEN_REQUESTxVERS = 23
SN_GEN_VERSxRESPONSE = 24

# SNAC 23 subtypes
SN_IES_AUTHxLOGIN = 2
SN_IES_LOGINxREPLY = 3
SN_IES_AUTHxREQUEST = 6
SN_IES_AUTHxKEY = 7

AIM_MD5_STRING = "AOL Instant Messenger (SM)"

MISMATCH_PASSWD = "http://www.aim.com/errors/MISMATCH_PASSWD.html?ccode=us&lang=en"

SUPPORTED_SERVICES = {1:4, 2:1, 3:1, 4:1, 6:1, 8:1, 9:1, 10:1, 11:1, 12:1, 19:5, 21:2, 34:1, 36:1, 37:1}

WELL_KNOWN_URL = {3: 'http://api.oscar.aol.com/lifestream/',
                  4: 'http://o.aolcdn.com/lifestream/client/full',
                  5: 'http://o.aolcdn.com/lifestream/client/me',
                  7: 'http://o.aolcdn.com/lifestream_photos/photo/',
                  8: 'http://photos.lifestream.aim.com/photo/upload?',
                  9: 'http://api.oscar.aol.com/',
                  10: 'http://lifestream.aim.com/settings',
                  11: 'http://lifestream.aim.com/stream/',
                  12: 'https://my.screenname.aol.com',
                  13: 'http://abapi.abweb.aol.com/ABWebApi/',
                  14: 'https://dbr.services.aol.com/'}

