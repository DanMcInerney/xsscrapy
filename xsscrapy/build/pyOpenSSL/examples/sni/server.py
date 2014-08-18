# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

if __name__ == '__main__':
    import server
    raise SystemExit(server.main())

from sys import stdout
from socket import SOL_SOCKET, SO_REUSEADDR, socket

from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, load_certificate
from OpenSSL.SSL import TLSv1_METHOD, Context, Connection

def load(domain):
    crt = open(domain + ".crt")
    key = open(domain + ".key")
    result = (
        load_privatekey(FILETYPE_PEM, key.read()),
        load_certificate(FILETYPE_PEM, crt.read()))
    crt.close()
    key.close()
    return result


def main():
    """
    Run an SNI-enabled server which selects between a few certificates in a
    C{dict} based on the handshake request it receives from a client.
    """
    port = socket()
    port.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    port.bind(('', 8443))
    port.listen(3)

    print 'Accepting...',
    stdout.flush()
    server, addr = port.accept()
    print 'accepted', addr

    server_context = Context(TLSv1_METHOD)
    server_context.set_tlsext_servername_callback(pick_certificate)

    server_ssl = Connection(server_context, server)
    server_ssl.set_accept_state()
    server_ssl.do_handshake()
    server.close()


certificates = {
    "example.invalid": load("example.invalid"),
    "another.invalid": load("another.invalid"),
    }


def pick_certificate(connection):
    try:
        key, cert = certificates[connection.get_servername()]
    except KeyError:
        pass
    else:
        new_context = Context(TLSv1_METHOD)
        new_context.use_privatekey(key)
        new_context.use_certificate(cert)
        connection.set_context(new_context)
