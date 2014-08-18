.. _internals:

Internals
=========

We ran into three main problems developing this: Exceptions, callbacks and
accessing socket methods. This is what this chapter is about.


.. _exceptions:

Exceptions
----------

We realized early that most of the exceptions would be raised by the I/O
functions of OpenSSL, so it felt natural to mimic OpenSSL's error code system,
translating them into Python exceptions. This naturally gives us the exceptions
:py:exc:`.SSL.ZeroReturnError`, :py:exc:`.SSL.WantReadError`,
:py:exc:`.SSL.WantWriteError`, :py:exc:`.SSL.WantX509LookupError` and
:py:exc:`.SSL.SysCallError`.

For more information about this, see section :ref:`openssl-ssl`.


.. _callbacks:

Callbacks
---------

Callbacks were more of a problem when pyOpenSSL was written in C.
Having switched to being written in Python using cffi, callbacks are now straightforward.
The problems that originally existed no longer do
(if you are interested in the details you can find descriptions of those problems in the version control history for this document).

.. _socket-methods:

Accessing Socket Methods
------------------------

We quickly saw the benefit of wrapping socket methods in the
:py:class:`.SSL.Connection` class, for an easy transition into using SSL. The
problem here is that the :py:mod:`socket` module lacks a C API, and all the
methods are declared static. One approach would be to have :py:mod:`.OpenSSL` as
a submodule to the :py:mod:`socket` module, placing all the code in
``socketmodule.c``, but this is obviously not a good solution, since you
might not want to import tonnes of extra stuff you're not going to use when
importing the :py:mod:`socket` module. The other approach is to somehow get a
pointer to the method to be called, either the C function, or a callable Python
object. This is not really a good solution either, since there's a lot of
lookups involved.

The way it works is that you have to supply a :py:class:`socket`- **like** transport
object to the :py:class:`.SSL.Connection`. The only requirement of this object is
that it has a :py:meth:`fileno()` method that returns a file descriptor that's
valid at the C level (i.e. you can use the system calls read and write). If you
want to use the :py:meth:`connect()` or :py:meth:`accept()` methods of the
:py:class:`.SSL.Connection` object, the transport object has to supply such
methods too. Apart from them, any method lookups in the :py:class:`.SSL.Connection`
object that fail are passed on to the underlying transport object.

Future changes might be to allow Python-level transport objects, that instead
of having :py:meth:`fileno()` methods, have :py:meth:`read()` and :py:meth:`write()`
methods, so more advanced features of Python can be used. This would probably
entail some sort of OpenSSL **BIOs**, but converting Python strings back and
forth is expensive, so this shouldn't be used unless necessary. Other nice
things would be to be able to pass in different transport objects for reading
and writing, but then the :py:meth:`fileno()` method of :py:class:`.SSL.Connection`
becomes virtually useless. Also, should the method resolution be used on the
read-transport or the write-transport?
