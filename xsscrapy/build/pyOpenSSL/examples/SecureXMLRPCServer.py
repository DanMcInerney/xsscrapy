"""
SecureXMLRPCServer module using pyOpenSSL 0.5
Written 0907.2002
by Michal Wallace
http://www.sabren.net/

This acts exactly like SimpleXMLRPCServer
from the standard python library, but
uses secure connections. The technique
and classes should work for any SocketServer
style server. However, the code has not
been extensively tested.

This code is in the public domain.
It is provided AS-IS WITH NO WARRANTY WHATSOEVER.
"""
import SocketServer
import os, socket
import SimpleXMLRPCServer
from OpenSSL import SSL

class SSLWrapper:
    """
    This whole class exists just to filter out a parameter
    passed in to the shutdown() method in SimpleXMLRPC.doPOST()
    """
    def __init__(self, conn):
        """
        Connection is not yet a new-style class,
        so I'm making a proxy instead of subclassing.
        """
        self.__dict__["conn"] = conn
    def __getattr__(self,name):
        return getattr(self.__dict__["conn"], name)
    def __setattr__(self,name, value):
        setattr(self.__dict__["conn"], name, value)
    def shutdown(self, how=1):
        """
        SimpleXMLRpcServer.doPOST calls shutdown(1),
        and Connection.shutdown() doesn't take
        an argument. So we just discard the argument.
        """
        self.__dict__["conn"].shutdown()
    def accept(self):
        """
        This is the other part of the shutdown() workaround.
        Since servers create new sockets, we have to infect
        them with our magic. :)
        """
        c, a = self.__dict__["conn"].accept()
        return (SSLWrapper(c), a)



class SecureTCPServer(SocketServer.TCPServer):
    """
    Just like TCPServer, but use a socket.
    This really ought to let you specify the key and certificate files.
    """
    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.BaseServer.__init__(self, server_address, RequestHandlerClass)

        ## Same as normal, but make it secure:
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)

        dir = os.curdir
        ctx.use_privatekey_file (os.path.join(dir, 'server.pkey'))
        ctx.use_certificate_file(os.path.join(dir, 'server.cert'))

        self.socket = SSLWrapper(SSL.Connection(ctx, socket.socket(self.address_family,
                                                                  self.socket_type)))
        self.server_bind()
        self.server_activate()


class SecureXMLRPCRequestHandler(SimpleXMLRPCServer.SimpleXMLRPCRequestHandler):
    def setup(self):
        """
        We need to use socket._fileobject Because SSL.Connection
        doesn't have a 'dup'. Not exactly sure WHY this is, but
        this is backed up by comments in socket.py and SSL/connection.c
        """
        self.connection = self.request # for doPOST
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)
    

class SecureXMLRPCServer(SimpleXMLRPCServer.SimpleXMLRPCServer, SecureTCPServer):
    def __init__(self, addr,
                 requestHandler=SecureXMLRPCRequestHandler,
                 logRequests=1):
        """
        This is the exact same code as SimpleXMLRPCServer.__init__
        except it calls SecureTCPServer.__init__ instead of plain
        old TCPServer.__init__
        """
        self.funcs = {}
        self.logRequests = logRequests
        self.instance = None
        SecureTCPServer.__init__(self, addr, requestHandler)

