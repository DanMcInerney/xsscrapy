"""
This module contains general purpose URL functions not found in the standard
library.
"""
import os
import re
import posixpath
import warnings
from six import moves
import w3lib.parse
from w3lib.util import unicode_to_str

# Python 2.x urllib.always_safe become private in Python 3.x;
# its content is copied here
_ALWAYS_SAFE_BYTES = (b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                      b'abcdefghijklmnopqrstuvwxyz'
                      b'0123456789' b'_.-')


def urljoin_rfc(base, ref, encoding='utf-8'):
    r"""
    .. warning::

        This function is deprecated and will be removed in future.
        Please use ``urlparse.urljoin`` instead.

    Same as urlparse.urljoin but supports unicode values in base and ref
    parameters (in which case they will be converted to str using the given
    encoding).

    Always returns a str.

    >>> import w3lib.url
    >>> w3lib.url.urljoin_rfc('http://www.example.com/path/index.html', u'/otherpath/index2.html')
    'http://www.example.com/otherpath/index2.html'
    >>>

    >>> w3lib.url.urljoin_rfc('http://www.example.com/path/index.html', u'fran\u00e7ais/d\u00e9part.htm')
    'http://www.example.com/path/fran\xc3\xa7ais/d\xc3\xa9part.htm'
    >>>


    """

    warnings.warn("w3lib.url.urljoin_rfc is deprecated, use urlparse.urljoin instead",
        DeprecationWarning)

    str_base = unicode_to_str(base, encoding)
    str_ref = unicode_to_str(ref, encoding)
    return moves.urllib.parse.urljoin(str_base, str_ref)

_reserved = b';/?:@&=+$|,#' # RFC 3986 (Generic Syntax)
_unreserved_marks = b"-_.!~*'()" # RFC 3986 sec 2.3
_safe_chars = _ALWAYS_SAFE_BYTES + b'%' + _reserved + _unreserved_marks

def safe_url_string(url, encoding='utf8'):
    """Convert the given url into a legal URL by escaping unsafe characters
    according to RFC-3986.

    If a unicode url is given, it is first converted to bytes using the given
    encoding (which defaults to 'utf-8'). When passing a encoding, you should
    use the encoding of the original page (the page from which the url was
    extracted from).

    Calling this function on an already "safe" url won't change url contents
    (but will encode it to bytes if it was unicode).

    Always returns bytes.
    """
    s = unicode_to_str(url, encoding)
    return moves.urllib.parse.quote(s, _safe_chars).encode('ascii')


_parent_dirs = re.compile(br'/?(\.\./)+')

def safe_download_url(url):
    """ Make a url for download. This will call safe_url_string
    and then strip the fragment, if one exists. The path will
    be normalised.

    If the path is outside the document root, it will be changed
    to be within the document root.
    """
    safe_url = safe_url_string(url)
    scheme, netloc, path, query, _ = moves.urllib.parse.urlsplit(safe_url)
    if path:
        path = _parent_dirs.sub(b'', posixpath.normpath(path))
        if safe_url and safe_url[-1:] == b'/' and path[-1:] != b'/':
            path += b'/'
    else:
        path = b'/'
    return moves.urllib.parse.urlunsplit((scheme, netloc, path, query, b''))


def is_url(text):
    text = unicode_to_str(text)
    return text.partition(b"://")[0] in {b'file', b'http', b'https'}


def url_query_parameter(url, parameter, default=None, keep_blank_values=0):
    """Return the value of a url parameter, given the url and parameter name

    General case:

    >>> import w3lib.url
    >>> w3lib.url.url_query_parameter("product.html?id=200&foo=bar", "id")
    '200'
    >>>

    Return a default value if the parameter is not found:

    >>> w3lib.url.url_query_parameter("product.html?id=200&foo=bar", "notthere", "mydefault")
    'mydefault'
    >>>

    Returns None if `keep_blank_values` not set or 0 (default):

    >>> w3lib.url.url_query_parameter("product.html?id=", "id")
    >>>

    Returns an empty string if `keep_blank_values` set to 1:

    >>> w3lib.url.url_query_parameter("product.html?id=", "id", keep_blank_values=1)
    ''
    >>>

    """

    query = moves.urllib.parse.urlsplit(url).query
    params = w3lib.parse.parse_qs(query, keep_blank_values=keep_blank_values)
    return params.get(parameter, [default])[0]


def url_query_cleaner(url, parameterlist=(), sep=b'&', kvsep=b'=', remove=False, unique=True):
    """Clean URL arguments leaving only those passed in the parameterlist keeping order

    >>> import w3lib.url
    >>> w3lib.url.url_query_cleaner("product.html?id=200&foo=bar&name=wired", ('id',))
    'product.html?id=200'
    >>> w3lib.url.url_query_cleaner("product.html?id=200&foo=bar&name=wired", ['id', 'name'])
    'product.html?id=200&name=wired'
    >>>

    If `unique` is ``False``, do not remove duplicated keys

    >>> w3lib.url.url_query_cleaner("product.html?d=1&e=b&d=2&d=3&other=other", ['d'], unique=False)
    'product.html?d=1&d=2&d=3'
    >>>

    If `remove` is ``True``, leave only those **not in parameterlist**.

    >>> w3lib.url.url_query_cleaner("product.html?id=200&foo=bar&name=wired", ['id'], remove=True)
    'product.html?foo=bar&name=wired'
    >>> w3lib.url.url_query_cleaner("product.html?id=2&foo=bar&name=wired", ['id', 'foo'], remove=True)
    'product.html?name=wired'
    >>>

    """

    url = moves.urllib.parse.urldefrag(url)[0]
    base, _, query = url.partition(b'?')
    seen = set()
    querylist = []
    for ksv in query.split(sep):
        k, _, _ = ksv.partition(kvsep)
        if unique and k in seen:
            continue
        elif remove and k in parameterlist:
            continue
        elif not remove and k not in parameterlist:
            continue
        else:
            querylist.append(ksv)
            seen.add(k)
    return b'?'.join([base, sep.join(querylist)]) if querylist else base


def add_or_replace_parameter(url, name, new_value):
    """Add or remove a parameter to a given url

    >>> import w3lib.url
    >>> w3lib.url.add_or_replace_parameter('http://www.example.com/index.php', 'arg', 'v')
    'http://www.example.com/index.php?arg=v'
    >>> w3lib.url.add_or_replace_parameter('http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3', 'arg4', 'v4')
    'http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3&arg4=v4'
    >>> w3lib.url.add_or_replace_parameter('http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3', 'arg3', 'v3new')
    'http://www.example.com/index.php?arg1=v1&arg2=v2&arg3=v3new'
    >>>

    """
    parsed = moves.urllib.parse.urlsplit(url)
    args = w3lib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    new_args = []
    found = False
    for name_, value_ in args:
        if name_ == name:
            new_args.append((name_, new_value))
            found = True
        else:
            new_args.append((name_, value_))

    if not found:
        new_args.append((name, new_value))

    query = moves.urllib.parse.urlencode(new_args)
    # We want to return the same type used for url argument, but
    # urlencode always returns bytes on py2 and str on py3,
    if isinstance(url, bytes):
        query = unicode_to_str(query)
    return moves.urllib.parse.urlunsplit(parsed._replace(query=query))


def path_to_file_uri(path):
    """Convert local filesystem path to legal File URIs as described in:
    http://en.wikipedia.org/wiki/File_URI_scheme
    """
    x = moves.urllib.request.pathname2url(os.path.abspath(path))
    if os.name == 'nt':
        x = x.replace('|', ':') # http://bugs.python.org/issue5861
    return 'file:///%s' % x.lstrip('/')

def file_uri_to_path(uri):
    """Convert File URI to local filesystem path according to:
    http://en.wikipedia.org/wiki/File_URI_scheme
    """
    uri_path = moves.urllib.parse.urlparse(uri).path
    return moves.urllib.request.url2pathname(uri_path)

def any_to_uri(uri_or_path):
    """If given a path name, return its File URI, otherwise return it
    unmodified
    """
    if os.path.splitdrive(uri_or_path)[0]:
        return path_to_file_uri(uri_or_path)
    u = moves.urllib.parse.urlparse(uri_or_path)
    return uri_or_path if u.scheme else path_to_file_uri(uri_or_path)
