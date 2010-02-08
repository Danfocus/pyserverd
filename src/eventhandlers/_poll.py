'''
Created on 08.02.2010

@author: danfocus
'''
import select

class _poll(object):
    if hasattr(select, "epoll"):
        # Python 2.6+ on Linux
        _events = select
        _poll = select.epoll()
    elif hasattr(select, "kqueue"):
        # BSD
        from _kqueue import _kqueue
        _events = _kqueue()
        _poll = _kqueue()
    else:
        # All other systems
        from _select import _select
        _events = _select()
        _poll = _select()