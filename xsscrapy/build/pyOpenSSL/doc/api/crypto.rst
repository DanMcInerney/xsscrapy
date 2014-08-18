.. _openssl-crypto:

:py:mod:`crypto` --- Generic cryptographic module
=================================================

.. py:module:: OpenSSL.crypto
   :synopsis: Generic cryptographic module


.. py:data:: X509Type

    See :py:class:`X509`.


.. py:class:: X509()

    A class representing X.509 certificates.


.. py:data:: X509NameType

    See :py:class:`X509Name`.


.. py:class:: X509Name(x509name)

    A class representing X.509 Distinguished Names.

    This constructor creates a copy of *x509name* which should be an
    instance of :py:class:`X509Name`.


.. py:data:: X509ReqType

    See :py:class:`X509Req`.


.. py:class:: X509Req()

    A class representing X.509 certificate requests.


.. py:data:: X509StoreType

    A Python type object representing the X509Store object type.


.. py:data:: PKeyType

    See :py:class:`PKey`.


.. py:class:: PKey()

    A class representing DSA or RSA keys.


.. py:data:: PKCS7Type

    A Python type object representing the PKCS7 object type.


.. py:data:: PKCS12Type

    A Python type object representing the PKCS12 object type.


.. py:data:: X509ExtensionType

    See :py:class:`X509Extension`.


.. py:class:: X509Extension(typename, critical, value[, subject][, issuer])

    A class representing an X.509 v3 certificate extensions.  See
    http://openssl.org/docs/apps/x509v3_config.html#STANDARD_EXTENSIONS for
    *typename* strings and their options.  Optional parameters *subject* and
    *issuer* must be X509 objects.


.. py:data:: NetscapeSPKIType

    See :py:class:`NetscapeSPKI`.


.. py:class:: NetscapeSPKI([enc])

    A class representing Netscape SPKI objects.

    If the *enc* argument is present, it should be a base64-encoded string
    representing a NetscapeSPKI object, as returned by the :py:meth:`b64_encode`
    method.


.. py:class:: CRL()

    A class representing Certifcate Revocation List objects.


.. py:class:: Revoked()

    A class representing Revocation objects of CRL.


.. py:data:: FILETYPE_PEM
             FILETYPE_ASN1

    File type constants.


.. py:data:: TYPE_RSA
             TYPE_DSA

    Key type constants.


.. py:exception:: Error

    Generic exception used in the :py:mod:`.crypto` module.


.. py:function:: dump_certificate(type, cert)

    Dump the certificate *cert* into a buffer string encoded with the type
    *type*.


.. py:function:: dump_certificate_request(type, req)

    Dump the certificate request *req* into a buffer string encoded with the
    type *type*.


.. py:function:: dump_privatekey(type, pkey[, cipher, passphrase])

    Dump the private key *pkey* into a buffer string encoded with the type
    *type*, optionally (if *type* is :py:const:`FILETYPE_PEM`) encrypting it
    using *cipher* and *passphrase*.

    *passphrase* must be either a string or a callback for providing the
    pass phrase.


.. py:function:: load_certificate(type, buffer)

    Load a certificate (X509) from the string *buffer* encoded with the
    type *type*.


.. py:function:: load_certificate_request(type, buffer)

    Load a certificate request (X509Req) from the string *buffer* encoded with
    the type *type*.


.. py:function:: load_privatekey(type, buffer[, passphrase])

    Load a private key (PKey) from the string *buffer* encoded with the type
    *type* (must be one of :py:const:`FILETYPE_PEM` and
    :py:const:`FILETYPE_ASN1`).

    *passphrase* must be either a string or a callback for providing the pass
    phrase.


.. py:function:: load_crl(type, buffer)

    Load Certificate Revocation List (CRL) data from a string *buffer*.
    *buffer* encoded with the type *type*.  The type *type* must either
    :py:const:`FILETYPE_PEM` or :py:const:`FILETYPE_ASN1`).


.. py:function:: load_pkcs7_data(type, buffer)

    Load pkcs7 data from the string *buffer* encoded with the type *type*.


.. py:function:: load_pkcs12(buffer[, passphrase])

    Load pkcs12 data from the string *buffer*. If the pkcs12 structure is
    encrypted, a *passphrase* must be included.  The MAC is always
    checked and thus required.

    See also the man page for the C function :py:func:`PKCS12_parse`.


.. py:function:: sign(key, data, digest)

    Sign a data string using the given key and message digest.

    *key* is a :py:class:`PKey` instance.  *data* is a ``str`` instance.
    *digest* is a ``str`` naming a supported message digest type, for example
    :py:const:`sha1`.

    .. versionadded:: 0.11


.. py:function:: verify(certificate, signature, data, digest)

    Verify the signature for a data string.

    *certificate* is a :py:class:`X509` instance corresponding to the private
    key which generated the signature.  *signature* is a *str* instance giving
    the signature itself.  *data* is a *str* instance giving the data to which
    the signature applies.  *digest* is a *str* instance naming the message
    digest type of the signature, for example :py:const:`sha1`.

    .. versionadded:: 0.11


.. _openssl-x509:

X509 objects
------------

X509 objects have the following methods:

.. py:method:: X509.get_issuer()

    Return an X509Name object representing the issuer of the certificate.


.. py:method:: X509.get_pubkey()

    Return a :py:class:`PKey` object representing the public key of the certificate.


.. py:method:: X509.get_serial_number()

    Return the certificate serial number.


.. py:method:: X509.get_signature_algorithm()

    Return the signature algorithm used in the certificate.  If the algorithm is
    undefined, raise :py:data:`ValueError`.

    ..versionadded:: 0.13


.. py:method:: X509.get_subject()

    Return an :py:class:`X509Name` object representing the subject of the certificate.


.. py:method:: X509.get_version()

    Return the certificate version.


.. py:method:: X509.get_notBefore()

    Return a string giving the time before which the certificate is not valid.  The
    string is formatted as an ASN1 GENERALIZEDTIME::

        YYYYMMDDhhmmssZ
        YYYYMMDDhhmmss+hhmm
        YYYYMMDDhhmmss-hhmm

    If no value exists for this field, :py:data:`None` is returned.


.. py:method:: X509.get_notAfter()

    Return a string giving the time after which the certificate is not valid.  The
    string is formatted as an ASN1 GENERALIZEDTIME::

        YYYYMMDDhhmmssZ
        YYYYMMDDhhmmss+hhmm
        YYYYMMDDhhmmss-hhmm

    If no value exists for this field, :py:data:`None` is returned.


.. py:method:: X509.set_notBefore(when)

    Change the time before which the certificate is not valid.  *when* is a
    string formatted as an ASN1 GENERALIZEDTIME::

        YYYYMMDDhhmmssZ
        YYYYMMDDhhmmss+hhmm
        YYYYMMDDhhmmss-hhmm


.. py:method:: X509.set_notAfter(when)

    Change the time after which the certificate is not valid.  *when* is a
    string formatted as an ASN1 GENERALIZEDTIME::

        YYYYMMDDhhmmssZ
        YYYYMMDDhhmmss+hhmm
        YYYYMMDDhhmmss-hhmm



.. py:method:: X509.gmtime_adj_notBefore(time)

    Adjust the timestamp (in GMT) when the certificate starts being valid.


.. py:method:: X509.gmtime_adj_notAfter(time)

    Adjust the timestamp (in GMT) when the certificate stops being valid.


.. py:method:: X509.has_expired()

    Checks the certificate's time stamp against current time. Returns true if the
    certificate has expired and false otherwise.


.. py:method:: X509.set_issuer(issuer)

    Set the issuer of the certificate to *issuer*.


.. py:method:: X509.set_pubkey(pkey)

    Set the public key of the certificate to *pkey*.


.. py:method:: X509.set_serial_number(serialno)

    Set the serial number of the certificate to *serialno*.


.. py:method:: X509.set_subject(subject)

    Set the subject of the certificate to *subject*.


.. py:method:: X509.set_version(version)

    Set the certificate version to *version*.


.. py:method:: X509.sign(pkey, digest)

    Sign the certificate, using the key *pkey* and the message digest algorithm
    identified by the string *digest*.


.. py:method:: X509.subject_name_hash()

    Return the hash of the certificate subject.

.. py:method:: X509.digest(digest_name)

    Return a digest of the certificate, using the *digest_name* method.
    *digest_name* must be a string describing a digest algorithm supported
    by OpenSSL (by EVP_get_digestbyname, specifically).  For example,
    :py:const:`"md5"` or :py:const:`"sha1"`.


.. py:method:: X509.add_extensions(extensions)

    Add the extensions in the sequence *extensions* to the certificate.


.. py:method:: X509.get_extension_count()

    Return the number of extensions on this certificate.

    .. versionadded:: 0.12


.. py:method:: X509.get_extension(index)

    Retrieve the extension on this certificate at the given index.

    Extensions on a certificate are kept in order.  The index parameter selects
    which extension will be returned.  The returned object will be an
    :py:class:`X509Extension` instance.

    .. versionadded:: 0.12


.. _openssl-x509name:

X509Name objects
----------------

X509Name objects have the following methods:

.. py:method:: X509Name.hash()

    Return an integer giving the first four bytes of the MD5 digest of the DER
    representation of the name.


.. py:method:: X509Name.der()

    Return a string giving the DER representation of the name.


.. py:method:: X509Name.get_components()

    Return a list of two-tuples of strings giving the components of the name.


X509Name objects have the following members:

.. py:attribute:: X509Name.countryName

    The country of the entity. :py:attr:`C` may be used as an alias for
    :py:attr:`countryName`.


.. py:attribute:: X509Name.stateOrProvinceName

    The state or province of the entity. :py:attr:`ST` may be used as an alias for
    :py:attr:`stateOrProvinceName`.


.. py:attribute:: X509Name.localityName

    The locality of the entity. :py:attr:`L` may be used as an alias for
    :py:attr:`localityName`.


.. py:attribute:: X509Name.organizationName

    The organization name of the entity. :py:attr:`O` may be used as an alias for
    :py:attr:`organizationName`.


.. py:attribute:: X509Name.organizationalUnitName

    The organizational unit of the entity. :py:attr:`OU` may be used as an alias for
    :py:attr:`organizationalUnitName`.


.. py:attribute:: X509Name.commonName

    The common name of the entity. :py:attr:`CN` may be used as an alias for
    :py:attr:`commonName`.


.. py:attribute:: X509Name.emailAddress

    The e-mail address of the entity.


.. _openssl-x509req:

X509Req objects
---------------

X509Req objects have the following methods:

.. py:method:: X509Req.get_pubkey()

    Return a :py:class:`PKey` object representing the public key of the certificate request.


.. py:method:: X509Req.get_subject()

    Return an :py:class:`X509Name` object representing the subject of the certificate.


.. py:method:: X509Req.set_pubkey(pkey)

    Set the public key of the certificate request to *pkey*.


.. py:method:: X509Req.sign(pkey, digest)

    Sign the certificate request, using the key *pkey* and the message digest
    algorithm identified by the string *digest*.


.. py:method:: X509Req.verify(pkey)

    Verify a certificate request using the public key *pkey*.


.. py:method:: X509Req.set_version(version)

    Set the version (RFC 2459, 4.1.2.1) of the certificate request to
    *version*.


.. py:method:: X509Req.get_version()

    Get the version (RFC 2459, 4.1.2.1) of the certificate request.


.. _openssl-x509store:

X509Store objects
-----------------

The X509Store object has currently just one method:

.. py:method:: X509Store.add_cert(cert)

    Add the certificate *cert* to the certificate store.


.. _openssl-pkey:

PKey objects
------------

The PKey object has the following methods:

.. py:method:: PKey.bits()

    Return the number of bits of the key.


.. py:method:: PKey.generate_key(type, bits)

    Generate a public/private key pair of the type *type* (one of
    :py:const:`TYPE_RSA` and :py:const:`TYPE_DSA`) with the size *bits*.


.. py:method:: PKey.type()

    Return the type of the key.


.. py:method:: PKey.check()

    Check the consistency of this key, returning True if it is consistent and
    raising an exception otherwise.  This is only valid for RSA keys.  See the
    OpenSSL RSA_check_key man page for further limitations.


.. _openssl-pkcs7:

PKCS7 objects
-------------

PKCS7 objects have the following methods:

.. py:method:: PKCS7.type_is_signed()

    FIXME


.. py:method:: PKCS7.type_is_enveloped()

    FIXME


.. py:method:: PKCS7.type_is_signedAndEnveloped()

    FIXME


.. py:method:: PKCS7.type_is_data()

    FIXME


.. py:method:: PKCS7.get_type_name()

    Get the type name of the PKCS7.


.. _openssl-pkcs12:

PKCS12 objects
--------------

PKCS12 objects have the following methods:

.. py:method:: PKCS12.export([passphrase=None][, iter=2048][, maciter=1])

    Returns a PKCS12 object as a string.

    The optional *passphrase* must be a string not a callback.

    See also the man page for the C function :py:func:`PKCS12_create`.


.. py:method:: PKCS12.get_ca_certificates()

    Return CA certificates within the PKCS12 object as a tuple. Returns
    :py:const:`None` if no CA certificates are present.


.. py:method:: PKCS12.get_certificate()

    Return certificate portion of the PKCS12 structure.


.. py:method:: PKCS12.get_friendlyname()

    Return friendlyName portion of the PKCS12 structure.


.. py:method:: PKCS12.get_privatekey()

    Return private key portion of the PKCS12 structure


.. py:method:: PKCS12.set_ca_certificates(cacerts)

    Replace or set the CA certificates within the PKCS12 object with the sequence *cacerts*.

    Set *cacerts* to :py:const:`None` to remove all CA certificates.


.. py:method:: PKCS12.set_certificate(cert)

    Replace or set the certificate portion of the PKCS12 structure.


.. py:method:: PKCS12.set_friendlyname(name)

    Replace or set the friendlyName portion of the PKCS12 structure.


.. py:method:: PKCS12.set_privatekey(pkey)

    Replace or set private key portion of the PKCS12 structure


.. _openssl-509ext:

X509Extension objects
---------------------

X509Extension objects have several methods:

.. py:method:: X509Extension.get_critical()

    Return the critical field of the extension object.


.. py:method:: X509Extension.get_short_name()

    Retrieve the short descriptive name for this extension.

    The result is a byte string like :py:const:`basicConstraints`.

    .. versionadded:: 0.12


.. py:method:: X509Extension.get_data()

    Retrieve the data for this extension.

    The result is the ASN.1 encoded form of the extension data as a byte string.

    .. versionadded:: 0.12


.. _openssl-netscape-spki:

NetscapeSPKI objects
--------------------

NetscapeSPKI objects have the following methods:

.. py:method:: NetscapeSPKI.b64_encode()

    Return a base64-encoded string representation of the object.


.. py:method:: NetscapeSPKI.get_pubkey()

    Return the public key of object.


.. py:method:: NetscapeSPKI.set_pubkey(key)

    Set the public key of the object to *key*.


.. py:method:: NetscapeSPKI.sign(key, digest_name)

    Sign the NetscapeSPKI object using the given *key* and *digest_name*.
    *digest_name* must be a string describing a digest algorithm supported by
    OpenSSL (by EVP_get_digestbyname, specifically).  For example,
    :py:const:`"md5"` or :py:const:`"sha1"`.


.. py:method:: NetscapeSPKI.verify(key)

    Verify the NetscapeSPKI object using the given *key*.


.. _crl:

CRL objects
-----------

CRL objects have the following methods:

.. py:method:: CRL.add_revoked(revoked)

    Add a Revoked object to the CRL, by value not reference.


.. py:method:: CRL.export(cert, key[, type=FILETYPE_PEM][, days=100])

    Use *cert* and *key* to sign the CRL and return the CRL as a string.
    *days* is the number of days before the next CRL is due.


.. py:method:: CRL.get_revoked()

    Return a tuple of Revoked objects, by value not reference.


.. _revoked:

Revoked objects
---------------

Revoked objects have the following methods:

.. py:method:: Revoked.all_reasons()

    Return a list of all supported reasons.


.. py:method:: Revoked.get_reason()

    Return the revocation reason as a str.  Can be
    None, which differs from "Unspecified".


.. py:method:: Revoked.get_rev_date()

    Return the revocation date as a str.
    The string is formatted as an ASN1 GENERALIZEDTIME.


.. py:method:: Revoked.get_serial()

    Return a str containing a hex number of the serial of the revoked certificate.


.. py:method:: Revoked.set_reason(reason)

    Set the revocation reason.  *reason* must be None or a string, but the
    values are limited.  Spaces and case are ignored.  See
    :py:meth:`all_reasons`.


.. py:method:: Revoked.set_rev_date(date)

    Set the revocation date.
    The string is formatted as an ASN1 GENERALIZEDTIME.


.. py:method:: Revoked.set_serial(serial)

    *serial* is a string containing a hex number of the serial of the revoked certificate.
