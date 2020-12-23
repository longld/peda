# Overview

PEDA supports Python 2 and Python 3 using the
[six](https://pypi.python.org/pypi/six) library. To make sure code runs on both
Python 2 and Python 3, make sure to keep the following in mind. 

## Division

For integer division, use the `//` operator instead of `/`. In Python 3, the `/` operator returns a `float`.

In Python 3:

```python
>>> 5 / 2
2.5
>>> type(5 / 2)
<class 'float'>
```

## Type checking

To check if something is a string:

```python
isinstance(obj, six.string_types)
```

To check if something is an integer type:

```python
isinstance(x, six.integer_types)
```

## Strings

In Python 2, `bytes` is an alias for `str`. In Python 3, `str` is a unicode
type and `bytes` is used for a sequence of arbitrary bytes. Use a leading 'b' to
signify that a string is a `bytes` object.

```python
>>> 'Normal string'
'Normal string'
>>> b'arbitrary bytes \x90\x90'
b'arbitrary bytes \x90\x90'
```

To convert between `str` to `bytes`:

```python
>>> 'hi there'.encode('utf-8')
b'hi there'
>>> b'some string'.decode('utf-8')
'some string'
```

Do not mix `bytes` and `str` with each other with basic string functions. The
following is okay:

```python

>>> "abc".replace("a", "f")
'fbc'
>>> b"abc".replace(b"a", b"f")
b'fbc'
```

Mixing types in Python 3 will throw an exception:

```python
>>> b"abc".replace("a", "f")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
TypeError: expected bytes, bytearray or buffer compatible object

```

In Python 2, indexing into a `str` returns a `str` of length 1. In Python 3, indexing into a `bytes` returns an `int`. This causes a problem when iterating. To solve this, use the `bytes_iterator` from `utils.py`.

```python
# In Python 2:
>>> s = b'hello'
>>> s
'hello'
>>> s[0]
'h'

# In Python 3:
>>> s = b'hello'
>>> s
b'hello'
>>> s[0]
104

# Solution:
>>> for c in bytes_iterator(b'hi'): print(c)
... 
b'h'
b'i'
```

## Encodings

Encode (and decode) strings into hex:

```python
>>> codecs.encode(b'abcdef', 'hex')
b'616263646566'
>>> codecs.decode('616263646566', 'hex')
b'abcdef'
```
