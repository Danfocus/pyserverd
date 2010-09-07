'''
Created on 08.02.2010

@author: danfocus
'''

import ConfigParser
cnf = ConfigParser.ConfigParser()
cnf.read('pyserverd.conf')

class dbconn(object):
    '''
    classdocs
    '''
    
    
    def __init__(self):
        if cnf.get('db', 'db_type') == 'mysql':
            from databases import db_mysql
            _sql = db_mysql.sql
        elif cnf.get('db', 'db_type') == 'pgsql':
            from databases import db_pgsql
            _sql = db_pgsql.sql
        else:
            print "Database not supported"
            exit()
    
        
        self.db = _sql(cnf.get('db', 'db_host'), cnf.getint('db', 'db_port'), \
                  cnf.get('db', 'db_user'), cnf.get('db', 'db_passwd'), \
                  cnf.get('db', 'db_name'), cnf.getboolean('db', 'db_use_unicode'), \
                  cnf.get('db', 'db_charset'))
    
    
            