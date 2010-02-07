'''
Created on 03.02.2010

@author: danfocus
'''

import select

class _kqueue(object):
    '''
    classdocs
    '''
    
    EPOLLIN = 0x001
    EPOLLPRI = 0x002
    EPOLLOUT = 0x004
    EPOLLERR = 0x008
    EPOLLHUP = 0x010
    EPOLLRDHUP = 0x2000
    EPOLLONESHOT = (1 << 30)
    EPOLLET = (1 << 31)
    
    READ = EPOLLIN
    WRITE = EPOLLOUT
    ERROR = EPOLLERR | EPOLLHUP | EPOLLRDHUP

    def __init__(self):
        self._kqueue = select.kqueue() #@UndefinedVariable
        self._filters = {}
 
    def register(self, fd, events):
        filter = 0
        if events & self.WRITE:
            filter |= select.KQ_FILTER_WRITE #@UndefinedVariable
        if events & self.READ or filter == 0:
            filter |= select.KQ_FILTER_READ #@UndefinedVariable
        self._filters[fd] = filter
        kevent = select.kevent(fd, filter=filter) #@UndefinedVariable
        self._kqueue.control([kevent], 0)
 
    def modify(self, fd, events):
        self.unregister(fd)
        self.register(fd, events)
 
    def unregister(self, fd):
        kevent = select.kevent(fd, filter=self._filters[fd], flags=select.KQ_EV_DELETE) #@UndefinedVariable
        self._kqueue.control([kevent], 0)
 
    def poll(self, timeout):
        kevents = self._kqueue.control(None, 1000, timeout)
        events = []
        for kevent in kevents:
            fd = kevent.ident
            flags = 0
            if kevent.filter & select.KQ_FILTER_READ: #@UndefinedVariable
                flags |= self.READ
            if kevent.filter & select.KQ_FILTER_WRITE: #@UndefinedVariable
                flags |= self.WRITE
            if kevent.flags & select.KQ_EV_ERROR: #@UndefinedVariable
                flags |= self.ERROR
            events.append((fd, flags))
        return events