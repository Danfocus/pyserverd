'''
Created on 08.02.2010

@author: danfocus
'''

from config import Config
cnf = Config()

class dbconn(object):
    '''
    classdocs
    '''
    
    
    def __init__(self):
        if cnf.db_type == 'mysql':
            from databases import db_mysql
            _sql = db_mysql.sql
        elif cnf.db_type == 'pgsql':
            from databases import db_pgsql
            _sql = db_pgsql.sql
        else:
            print "Database not supported"
            exit()
    
        
        self.db = _sql(cnf.db_host, cnf.db_port, cnf.db_user, cnf.db_passwd, \
                  cnf.db_name, cnf.db_use_unicode, cnf.db_charset)
    
    
            
