'''
Created on 31.12.2009

@author: danfocus
'''
import Queue
import socket

class connection(object):
    def __init__(self, connection, address):
        self.connection = connection
        self.address = address
        self.isequence = None
        self.osequence = None
        self.status = 0
        self.uin = None
        self.fileno = None
        self.flap = Queue.Queue()
        self.caps = None
        self.away = None
        self.icbm = {}
        
    def __del__(self):
        self.connection.close()
        
    def shutdown(self):
        self.connection.shutdown(socket.SHUT_RDWR)
        
    def recv(self, lenc):
        try:
            data = self.connection.recv(lenc)
        except:
            data = None
        return data
    
    def send(self, data):
        self.connection.send(data)        
        
    def flap_put(self, fl):
        self.flap.put(fl)
        
    def flap_get(self):
        return self.flap.get()
    
    def flap_empty(self):
        return self.flap.empty()
    
    def flap_qsize(self):
        return self.flap.qsize()

