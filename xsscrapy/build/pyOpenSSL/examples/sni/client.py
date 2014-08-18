# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

if __name__ == '__main__':
    import client
    raise SystemExit(client.main())

from sys import argv, stdout
from socket import socket

from OpenSSL.SSL import TLSv1_METHOD, Context, Connection

def main():
    """
    Connect to an SNI-enabled server and request a specific hostname, specified
    by argv[1], of it.
    """
    if len(argv) < 2:
        print 'Usage: %s <hostname>' % (argv[0],)
        return 1

    client = socket()

    print 'Connecting...',
    stdout.flush()
    client.connect(('127.0.0.1', 8443))
    print 'connected', client.getpeername()

    client_ssl = Connection(Context(TLSv1_METHOD), client)
    client_ssl.set_connect_state()
    client_ssl.set_tlsext_host_name(argv[1])
    client_ssl.do_handshake()
    print 'Server subject is', client_ssl.get_peer_certificate().get_subject()
    client_ssl.close()

