'''
Created on 11.01.2010

@author: danfocus
'''

import MySQLdb

class sql(object):
    '''
    classdocs
    '''

    def __init__(self, db_host, db_port, db_user, db_passwd, db_name, db_use_unicode, db_charset):
        db = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_passwd, db=db_name, use_unicode=db_use_unicode, charset=db_charset)
        self.c = db.cursor()
    
    def db_set_challenge(self, uin, challenge):
        self.c.execute("""REPLACE INTO users_challenges SET users_uin = %s, challenge = %s""", (uin, challenge))
        return self.c.rowcount
    
    def db_get_challenge(self, uin, db_cookie_lifetime):
        self.db_check_challenge_expired(db_cookie_lifetime)
        self.c.execute("""SELECT challenge FROM users_challenges WHERE users_uin = %s""", (uin))
        challenge = self.c.fetchone()
            #uin = self.c.fetchone()[0]
        if challenge:
            self.c.execute("""DELETE FROM users_challenges WHERE users_uin = %s""", (uin))
            return challenge[0]
        else:
            return None
    
    def db_check_challenge_expired(self, db_cookie_lifetime):
        self.c.execute("""DELETE FROM users_challenges WHERE NOW() > cdate + %s""", db_cookie_lifetime)
               
    def db_set_cookie(self, uin, cookie):
        self.c.execute("""REPLACE INTO users_cookies SET users_uin = %s, cookie = %s""", (uin, cookie))
        pass
    
    def db_select_users_where(self, sel_, whr_):
        str_ = """SELECT """ + sel_ + """ FROM users WHERE uin = %s"""
        self.c.execute(str_, (whr_))
        return self.c.fetchone()
    
    def db_update_users_where(self, upd_, val_, whr_):
        str_ = """UPDATE users SET """ + upd_ + """ = """ + val_ + """ WHERE uin = %s"""
        self.c.execute(str_, (whr_))
    
    
    def db_get_cookie(self, cookie, db_cookie_lifetime):
        self.db_check_cookie_expired(db_cookie_lifetime)
        self.c.execute("""SELECT users_uin FROM users_cookies WHERE cookie = %s""", (cookie))
        uin = self.c.fetchone()
            #uin = self.c.fetchone()[0]
        if uin:
            self.c.execute("""DELETE FROM users_cookies WHERE users_uin = %s""", (uin[0]))
            return uin[0]
        else:
            return None
    
    def db_check_cookie_expired(self, db_cookie_lifetime):
        self.c.execute("""DELETE FROM users_cookies WHERE NOW() > cdate + %s""", db_cookie_lifetime)       
    
    def db_select_unixtimestamp_users_where(self, sel_, whr_):
        return self.db_select_users_where('UNIX_TIMESTAMP(%s)' % sel_, whr_)

