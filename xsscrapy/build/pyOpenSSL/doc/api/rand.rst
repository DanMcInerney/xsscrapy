.. _openssl-rand:

:py:mod:`rand` --- An interface to the OpenSSL pseudo random number generator
=============================================================================

.. py:module:: OpenSSL.rand
   :synopsis: An interface to the OpenSSL pseudo random number generator


This module handles the OpenSSL pseudo random number generator (PRNG) and
declares the following:

.. py:function:: add(string, entropy)

    Mix bytes from *string* into the PRNG state. The *entropy* argument is
    (the lower bound of) an estimate of how much randomness is contained in
    *string*, measured in bytes. For more information, see e.g. :rfc:`1750`.


.. py:function:: bytes(num_bytes)

    Get some random bytes from the PRNG as a string.

    This is a wrapper for the C function :py:func:`RAND_bytes`.


.. py:function:: cleanup()

    Erase the memory used by the PRNG.

    This is a wrapper for the C function :py:func:`RAND_cleanup`.


.. py:function:: egd(path[, bytes])

    Query the `Entropy Gathering Daemon <http://www.lothar.com/tech/crypto/>`_ on
    socket *path* for *bytes* bytes of random data and uses :py:func:`add` to
    seed the PRNG. The default value of *bytes* is 255.


.. py:function:: load_file(path[, bytes])

    Read *bytes* bytes (or all of it, if *bytes* is negative) of data from the
    file *path* to seed the PRNG. The default value of *bytes* is -1.


.. py:function:: screen()

    Add the current contents of the screen to the PRNG state.

    Availability: Windows.


.. py:function:: seed(string)

    This is equivalent to calling :py:func:`add` with *entropy* as the length
    of the string.


.. py:function:: status()

    Returns true if the PRNG has been seeded with enough data, and false otherwise.


.. py:function:: write_file(path)

    Write a number of random bytes (currently 1024) to the file *path*. This
    file can then be used with :py:func:`load_file` to seed the PRNG again.


.. py:exception:: Error

    If the current RAND method supports any errors, this is raised when needed.
    The default method does not raise this when the entropy pool is depleted.

    Whenever this exception is raised directly, it has a list of error messages
    from the OpenSSL error queue, where each item is a tuple *(lib, function,
    reason)*. Here *lib*, *function* and *reason* are all strings, describing
    where and what the problem is. See :manpage:`err(3)` for more information.
