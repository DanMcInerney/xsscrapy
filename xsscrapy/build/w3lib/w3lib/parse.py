import six
from six.moves import urllib
from w3lib.util import str_to_unicode, unicode_to_str


def parse_qs(query, *args, **kwargs):
    if isinstance(query, bytes) and six.PY3:
        query = str_to_unicode(query)
        recode = unicode_to_str
    elif isinstance(query, six.text_type) and six.PY2:
        query = unicode_to_str(query)
        recode = str_to_unicode
    else:
        recode = None

    parsed = urllib.parse.parse_qs(query, *args, **kwargs)
    return parsed if recode is None else \
        {recode(k): [recode(v) for v in vs] for k, vs in six.iteritems(parsed)}


def parse_qsl(query, *args, **kwargs):
    if isinstance(query, bytes) and six.PY3:
        query = str_to_unicode(query)
        recode = unicode_to_str
    elif isinstance(query, six.text_type) and six.PY2:
        query = unicode_to_str(query)
        recode = str_to_unicode
    else:
        recode = None

    parsed = urllib.parse.parse_qsl(query, *args, **kwargs)
    return parsed if recode is None else \
        [(recode(k), recode(v)) for k, v in parsed]
