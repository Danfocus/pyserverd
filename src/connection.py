'''
Created on 31.12.2009

@author: danfocus
'''
import Queue

class Connection(object):
    def __init__(self, connection, address):
        self.connection = connection
        self.address = address
        self.isequence = None
        self.osequence = None
        self.accepted = None
        self.uin = None
        self.fileno = None
        self.flap = Queue.Queue()
        self.caps = None
        self.away = None
        self.icbm = {}

