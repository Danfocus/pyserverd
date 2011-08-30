'''
Created on 08.02.2010

@author: danfocus
'''

import ConfigParser
cnf = ConfigParser.ConfigParser()

class Config(object):
    serv_addr = None
    serv_port = None
    bos_addr = None
    connections_listen = None
    cookie_lifetime = None
    new_connection_delay = None
    pool_timeout = None
    db_type = None
    db_host = None
    db_port = None
    db_user = None
    db_passwd = None
    db_name = None
    db_use_unicode = None
    db_charset = None
    
    def __init__(self):
        self.read()
        
    def read(self):
        cnf.read('pyserverd.conf')
        self.serv_addr = cnf.get('general', 'serv_addr')
        self.serv_port = cnf.getint('general', 'serv_port')
        self.bos_addr = cnf.get('general', 'bos_addr')
        self.connections_listen = cnf.getint('general', 'connections_listen')
        self.cookie_lifetime = cnf.getint('general', 'cookie_lifetime')
        self.new_connection_delay = cnf.getfloat('general', 'new_connection_delay')
        self.pool_timeout = cnf.getfloat('general', 'pool_timeout')
        self.db_type = cnf.get('db', 'db_type')
        self.db_host = cnf.get('db', 'db_host')
        self.db_port = cnf.getint('db', 'db_port')
        self.db_user = cnf.get('db', 'db_user')
        self.db_passwd = cnf.get('db', 'db_passwd')
        self.db_name = cnf.get('db', 'db_name')
        self.db_use_unicode = cnf.getboolean('db', 'db_use_unicode')
        self.db_charset = cnf.get('db', 'db_charset')
    
            

