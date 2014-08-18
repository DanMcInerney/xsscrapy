"""
Create certificates and private keys for the 'simple' example.
"""

from OpenSSL import crypto
from certgen import *   # yes yes, I know, I'm lazy
cakey = createKeyPair(TYPE_RSA, 1024)
careq = createCertRequest(cakey, CN='Certificate Authority')
cacert = createCertificate(careq, (careq, cakey), 0, (0, 60*60*24*365*5)) # five years
open('simple/CA.pkey', 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey))
open('simple/CA.cert', 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))
for (fname, cname) in [('client', 'Simple Client'), ('server', 'Simple Server')]:
    pkey = createKeyPair(TYPE_RSA, 1024)
    req = createCertRequest(pkey, CN=cname)
    cert = createCertificate(req, (cacert, cakey), 1, (0, 60*60*24*365*5)) # five years
    open('simple/%s.pkey' % (fname,), 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    open('simple/%s.cert' % (fname,), 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
