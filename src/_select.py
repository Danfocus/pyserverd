'''
Created on 03.02.2010

@author: danfocus
'''

from select import select

class _select(object):
    
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
        self.read_fds = set()
        self.write_fds = set()
        self.error_fds = set()
        self.fd_sets = (self.read_fds, self.write_fds, self.error_fds)

    def register(self, fd, events):
        if events & self.READ: self.read_fds.add(fd)
        if events & self.WRITE: self.write_fds.add(fd)
        if events & self.ERROR: self.error_fds.add(fd)

    def modify(self, fd, events):
        self.unregister(fd)
        self.register(fd, events)

    def unregister(self, fd):
        self.read_fds.discard(fd)
        self.write_fds.discard(fd)
        self.error_fds.discard(fd)
    
    def close(self):
        del(self)
    
    def poll(self, timeout):
        readable, writeable, errors = select(self.read_fds, self.write_fds, self.error_fds, timeout)
        events = {}
        for fd in readable:
            events[fd] = events.get(fd, 0) | self.READ
        for fd in writeable:
            events[fd] = events.get(fd, 0) | self.WRITE
        for fd in errors:
            events[fd] = events.get(fd, 0) | self.ERROR
        return events.items()

