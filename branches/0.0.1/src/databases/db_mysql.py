'''
Created on 11.01.2010

@author: danfocus
'''
from tlv_c import tlv_c
from tlv_procs import make_tlv

import MySQLdb #@UnresolvedImport

import logging
deflogger = logging.getLogger('Logger')
debuglogger = logging.getLogger('Debug_logger')

class sql(object):
    '''
    classdocs
    '''
    
    db_host = None
    db_port = None
    db_user = None
    db_passwd = None
    db_name = None
    db_use_unicode = None
    db_charset = None
    db = None

    def __init__(self, db_host, db_port, db_user, db_passwd, db_name, db_use_unicode, db_charset):
        self.db_host =  db_host
        self.db_port = db_port
        self.db_user = db_user
        self.db_passwd = db_passwd
        self.db_name = db_name
        self.db_use_unicode = db_use_unicode
        self.db_charset = db_charset
        self.db_init()
        
    def db_init(self):
        deflogger.info("MySQL connection init", extra={'clientip': '', 'dirn': ''})
        debuglogger.info("MySQL connection init", extra={'clientip': '', 'dirn': ''})
        self.db = MySQLdb.connect(host=self.db_host, port=self.db_port, user=self.db_user, passwd=self.db_passwd, db=self.db_name, use_unicode=self.db_use_unicode, charset=self.db_charset)
        self.c = self.db.cursor()
        
    def db_check(self):
        try:
            self.db.ping()
        except:
            debuglogger.info("MySQL connection broken", extra={'clientip': '', 'dirn': ''})
            self.db_init()
        
    def db_set_challenge(self, uin, challenge):
        self.db_check()
        self.c.execute("""REPLACE INTO users_challenges SET users_uin = %s, challenge = %s""", (uin, challenge))
        return self.c.rowcount
    
    def db_get_challenge(self, uin, db_cookie_lifetime):
        self.db_check()
        self.db_check_challenge_expired(db_cookie_lifetime)
        self.c.execute("""SELECT challenge FROM users_challenges WHERE users_uin = %s LIMIT 1""", (uin))
        challenge = self.c.fetchone()
            #uin = self.c.fetchone()[0]
        if challenge:
            self.c.execute("""DELETE FROM users_challenges WHERE users_uin = %s""", (uin))
            return challenge[0]
        else:
            return None
    
    def db_check_challenge_expired(self, db_cookie_lifetime):
        self.db_check()
        self.c.execute("""DELETE FROM users_challenges WHERE NOW() > cdate + %s""", db_cookie_lifetime)
               
    def db_set_cookie(self, uin, cookie):
        self.db_check()
        self.c.execute("""REPLACE INTO users_cookies SET users_uin = %s, cookie = %s""", (uin, cookie))
    
    def db_select_users_where(self, sel_, whr_):
        self.db_check()
        str_ = """SELECT """ + sel_ + """ FROM users WHERE uin = %s LIMIT 1"""
        self.c.execute(str_, (whr_))
        result = self.c.fetchone()
        if result:
            return result
        return (None,None)
    
    def db_update_users_where(self, upd_, val_, whr_):
        self.db_check()
        str_ = """UPDATE users SET """ + upd_ + """ = """ + val_ + """ WHERE uin = %s"""
        self.c.execute(str_, (whr_))
    
    
    def db_get_cookie(self, cookie, db_cookie_lifetime):
        self.db_check()
        self.db_check_cookie_expired(db_cookie_lifetime)
        self.c.execute("""SELECT users_uin FROM users_cookies WHERE cookie = %s LIMIT 1""", (cookie))
        uin = self.c.fetchone()
            #uin = self.c.fetchone()[0]
        if uin:
            self.c.execute("""DELETE FROM users_cookies WHERE users_uin = %s""", (uin[0]))
            return uin[0]
        else:
            return None
    
    def db_check_cookie_expired(self, db_cookie_lifetime):
        self.db_check()
        self.c.execute("""DELETE FROM users_cookies WHERE NOW() > cdate + %s""", db_cookie_lifetime)       
    
    def db_select_unixtimestamp_users_where(self, sel_, whr_):
        self.db_check()
        return self.db_select_users_where('UNIX_TIMESTAMP(%s)' % sel_, whr_)
    
    def db_check_ssi(self, uin):
        self.db_check()
        #ssi_changed = False
        self.c.execute("""SELECT COUNT(*) FROM users_ssi_data WHERE gid = 0 AND id = 0 AND type = 1 AND users_uin = %s""", (uin))
        res = self.c.fetchone()
        if (res) and (not res[0]):
            self.c.execute("""INSERT INTO users_ssi_data SET users_uin = %s, gid = 0, id = 0, type = 1""", (uin))
            #ssi_changed = True
        
#        self.c.execute("""SELECT COUNT(*) FROM users_ssi_data WHERE gid = 23488 AND id = 0 AND type = 1 AND users_uin = %s""", (uin))
#        res = self.c.fetchone()
#        if not res:
#            self.c.execute("""INSERT INTO users_ssi_data VALUES(%s,23488,0,1)""", (uin))
#            ssi_changed = True
        
        self.c.execute("""SELECT COUNT(*) FROM users_ssi_data WHERE gid = 0 AND id = 1 AND type = 5 AND users_uin = %s""", (uin))
        res = self.c.fetchone()
        if (res) and (not res[0]):
            tl = [tlv_c(201, 0, "!I"), tlv_c(214, 0, "!I")]
            self.c.execute("""INSERT INTO users_ssi_data SET users_uin = %s, gid = 0, id = 1, type = 5, text = %s""", (uin, make_tlv(tl)))
            #ssi_changed = True
            
        self.c.execute("""SELECT COUNT(*) FROM users_ssi_data WHERE gid = 0 AND id = 2 AND type = 32 AND users_uin = %s""", (uin))
        res = self.c.fetchone()
        if (res) and (not res[0]):
            tl = [tlv_c(348, '\xf5\x28\xfc\x0c\x0b\x80\x48\x53\x83\x34\xb7\x2a\xb9\x2d\x42\x45'),
                  tlv_c(349, '\x40\xe3\x9f\x69\xbf\xe7\xba\x37')]
            self.c.execute("""INSERT INTO users_ssi_data SET users_uin = %s, gid = 0, id = 2, type = 32, name = 'ICQ-MDIR', text = %s""", (uin, make_tlv(tl)))
            #ssi_changed = True
            
        self.c.execute("""SELECT COUNT(*) FROM users_ssi_data WHERE gid = 0 AND id = 3 AND type = 4 AND users_uin = %s""", (uin))
        res = self.c.fetchone()
        if (res) and (not res[0]):
            tl = [tlv_c(366, 2, "!B")]
            self.c.execute("""INSERT INTO users_ssi_data SET users_uin = %s, gid = 0, id = 3, type = 4, text = %s""", (uin, make_tlv(tl)))
            #ssi_changed = True
            
    def db_get_ssi(self, uin):
        self.db_check()
        self.c.execute("""SELECT gid, id, type, name, text FROM users_ssi_data WHERE users_uin = %s ORDER BY gid, id, type""", (uin))
        res = self.c.fetchall()
        
        self.c.execute("""SELECT MAX(UNIX_TIMESTAMP(udate)) FROM users_ssi_data WHERE users_uin = %s""", (uin))
        res2 = self.c.fetchone()[0]
        return res, res2  
            
        
        
        
             
        
