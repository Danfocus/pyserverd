'''
Created on 11.01.2010

@author: danfocus
'''

import MySQLdb
from config import *

class db_mysql(object):

    def __init__(self):
        db = MySQLdb.connect(unix_socket=db_socket, user=db_user, passwd=db_passwd, db=db_name, use_unicode=db_use_unicode, charset=db_charset)
        self.c = db.cursor()
    
    def db_set_challenge(self,uin,challenge):
        self.c.execute("""UPDATE users SET challenge = %s WHERE uin = %s""", (challenge, uin))
        return self.c.rowcount
        
    def db_set_cookie(self,uin,cookie):
        self.c.execute("""REPLACE INTO users_cookies SET users_uin = %s, cookie = %s""",(uin, cookie))
        
        pass
    
    def db_select_users_where(self,sel_,whr_):
        str_ = """SELECT """+sel_+""" FROM users WHERE uin = %s"""
        self.c.execute(str_, (whr_))
        return self.c.fetchone()
    
    def db_get_cookie(self,cookie):
        self.db_check_cookie_expired()
        self.c.execute("""SELECT users_uin FROM users_cookies WHERE cookie = %s""", (cookie))
        uin = self.c.fetchone()
            #uin = self.c.fetchone()[0]
        if uin:
            self.c.execute("""DELETE FROM users_cookies WHERE users_uin = %s""", (uin[0]))
            return uin[0]
        else:
            return None
        
    
    def db_check_cookie_expired(self):
        self.c.execute("""DELETE FROM users_cookies WHERE NOW() > cdate + %s""", cookie_lifetime)       
    
