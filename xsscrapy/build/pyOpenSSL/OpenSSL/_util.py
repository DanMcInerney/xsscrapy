from six import PY3, binary_type, text_type

from cryptography.hazmat.bindings.openssl.binding import Binding
binding = Binding()
ffi = binding.ffi
lib = binding.lib

def exception_from_error_queue(exceptionType):
    def text(charp):
        return native(ffi.string(charp))

    errors = []
    while True:
        error = lib.ERR_get_error()
        if error == 0:
            break
        errors.append((
                text(lib.ERR_lib_error_string(error)),
                text(lib.ERR_func_error_string(error)),
                text(lib.ERR_reason_error_string(error))))

    raise exceptionType(errors)



def native(s):
    """
    Convert :py:class:`bytes` or :py:class:`unicode` to the native
    :py:class:`str` type, using UTF-8 encoding if conversion is necessary.

    :raise UnicodeError: The input string is not UTF-8 decodeable.

    :raise TypeError: The input is neither :py:class:`bytes` nor
        :py:class:`unicode`.
    """
    if not isinstance(s, (binary_type, text_type)):
        raise TypeError("%r is neither bytes nor unicode" % s)
    if PY3:
        if isinstance(s, binary_type):
            return s.decode("utf-8")
    else:
        if isinstance(s, text_type):
            return s.encode("utf-8")
    return s



if PY3:
    def byte_string(s):
        return s.encode("charmap")
else:
    def byte_string(s):
        return s
