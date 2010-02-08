'''
Created on 08.02.2010

@author: danfocus
'''
import ConfigParser

class cnf(object):
    '''
    classdocs
    '''
    
    cnf = ConfigParser.ConfigParser()
    cnf.read('pyserverd.conf')


    def __init__(self):
        '''
        Constructor
        '''
        