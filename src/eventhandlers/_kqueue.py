#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This code from project Tornado by Facebook

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
        self._active = {}

    def fileno(self):
        return self._kqueue.fileno()

    def register(self, fd, events):
        self._control(fd, events, select.KQ_EV_ADD) #@UndefinedVariable
        self._active[fd] = events

    def modify(self, fd, events):
        self.unregister(fd)
        self.register(fd, events)

    def unregister(self, fd):
        events = self._active.pop(fd)
        self._control(fd, events, select.KQ_EV_DELETE) #@UndefinedVariable

    def _control(self, fd, events, flags):
        kevents = []
        if events & self.WRITE:
            kevents.append(select.kevent( #@UndefinedVariable
                    fd, filter=select.KQ_FILTER_WRITE, flags=flags)) #@UndefinedVariable
        if events & self.READ or not kevents:
            # Always read when there is not a write
            kevents.append(select.kevent( #@UndefinedVariable
                    fd, filter=select.KQ_FILTER_READ, flags=flags)) #@UndefinedVariable
        # Even though control() takes a list, it seems to return EINVAL
        # on Mac OS X (10.6) when there is more than one event in the list.
        for kevent in kevents:
            self._kqueue.control([kevent], 0)

    def poll(self, timeout):
        kevents = self._kqueue.control(None, 1000, timeout)
        events = {}
        for kevent in kevents:
            fd = kevent.ident
            if kevent.filter == select.KQ_FILTER_READ: #@UndefinedVariable
                events[fd] = events.get(fd, 0) | self.READ
            if kevent.filter == select.KQ_FILTER_WRITE: #@UndefinedVariable
                if kevent.flags & select.KQ_EV_EOF: #@UndefinedVariable
                    # If an asynchronous connection is refused, kqueue
                    # returns a write event with the EOF flag set.
                    # Turn this into an error for consistency with the
                    # other IOLoop implementations.
                    # Note that for read events, EOF may be returned before
                    # all data has been consumed from the socket buffer,
                    # so we only check for EOF on write events.
                    events[fd] = self.ERROR
                else:
                    events[fd] = events.get(fd, 0) | self.WRITE
            if kevent.flags & select.KQ_EV_ERROR: #@UndefinedVariable
                events[fd] = events.get(fd, 0) | self.ERROR
        return events.items()