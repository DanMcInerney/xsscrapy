.. module:: cssselect

.. include:: ../README.rst


.. contents:: Contents
    :local:
    :depth: 1

Quickstart
==========

Use :class:`HTMLTranslator` for HTML documents, :class:`GenericTranslator`
for "generic" XML documents. (The former has a more useful translation
for some selectors, based on HTML-specific element types or attributes.)


.. sourcecode:: pycon

    >>> from cssselect import GenericTranslator, SelectorError
    >>> try:
    ...     expression = GenericTranslator().css_to_xpath('div.content')
    ... except SelectorError:
    ...     print('Invalid selector.')
    ...
    >>> print(expression)
    descendant-or-self::div[@class and contains(concat(' ', normalize-space(@class), ' '), ' content ')]

The resulting expression can be used with lxml's `XPath engine`_:

.. _XPath engine: http://lxml.de/xpathxslt.html#xpath

.. sourcecode:: pycon

    >>> from lxml.etree import fromstring
    >>> document = fromstring('''
    ...   <div id="outer">
    ...     <div id="inner" class="content body">text</div>
    ...   </div>
    ... ''')
    >>> [e.get('id') for e in document.xpath(expression)]
    ['inner']

User API
========

In CSS3 Selectors terms, the top-level object is a `group of selectors`_, a
sequence of comma-separated selectors. For example, ``div, h1.title + p``
is a group of two selectors.

.. _group of selectors: http://www.w3.org/TR/selectors/#grouping

.. autofunction:: parse
.. autoclass:: Selector()
    :members:

.. autoclass:: FunctionalPseudoElement

.. autoclass:: GenericTranslator
    :members: css_to_xpath, selector_to_xpath

.. autoclass:: HTMLTranslator

Exceptions
----------

.. autoexception:: SelectorError
.. autoexception:: SelectorSyntaxError
.. autoexception:: ExpressionError


Supported selectors
===================

This library implements CSS3 selectors as described in `the W3C specification
<http://www.w3.org/TR/2011/REC-css3-selectors-20110929/>`_.
In this context however, there is no interactivity or history of visited links.
Therefore, these pseudo-classes are accepted but never match anything:

* ``:hover``
* ``:active``
* ``:focus``
* ``:target``
* ``:visited``

Additionally, these depend on document knowledge and only have a useful
implementation in :class:`HTMLTranslator`. In :class:`GenericTranslator`,
they never match:

* ``:link``
* ``:enabled``
* ``:disabled``
* ``:checked``

These applicable pseudo-classes are not yet implemented:

* ``*:first-of-type``, ``*:last-of-type``, ``*:nth-of-type``,
  ``*:nth-last-of-type``, ``*:only-of-type``.  All of these work when
  you specify an element type, but not with ``*``

On the other hand, *cssselect* supports some selectors that are not
in the Level 3 specification:

* The ``:contains(text)`` pseudo-class that existed in `an early draft`_
  but was then removed.
* The ``!=`` attribute operator. ``[foo!=bar]`` is the same as
  ``:not([foo=bar])``
* ``:not()`` accepts a *sequence of simple selectors*, not just single
  *simple selector*. For example, ``:not(a.important[rel])`` is allowed,
  even though the negation contains 3 *simple selectors*.

.. _an early draft: http://www.w3.org/TR/2001/CR-css3-selectors-20011113/#content-selectors

..
    The following claim was copied from lxml:

    """
    XPath has underspecified string quoting rules (there seems to be no
    string quoting at all), so if you use expressions that contain
    characters that requiring quoting you might have problems with the
    translation from CSS to XPath.
    """

    It seems "string quoting" meant "quote escaping". There is indeed
    no quote escaping, but the xpath_literal method handles this.
    It should not be a problem anymore.


Customizing the translation
===========================

Just like :class:`HTMLTranslator` is a subclass of :class:`GenericTranslator`,
you can make new sub-classes of either of them and override some methods.
This enables you, for example, to customize how some pseudo-class is
implemented without forking or monkey-patching cssselect.

The "customization API" is the set of methods in translation classes
and their signature. You can look at the `source code`_ to see how it works.
However, be aware that this API is not very stable yet. It might change
and break your sub-class.

.. _source code: https://github.com/SimonSapin/cssselect/blob/master/cssselect/xpath.py


Namespaces
==========

In CSS you can use ``namespace-prefix|element``, similar to
``namespace-prefix:element`` in an XPath expression.  In fact, it maps
one-to-one. How prefixes are mapped to namespace URIs depends on the
XPath implementation.

.. include:: ../CHANGES
