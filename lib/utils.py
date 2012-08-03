#
#       PEDA - Python Exploit Development Assistance for GDB
#
#       Copyright (C) 2012 Long Le Dinh <longld at vnsecurity.net>
#
#       License: see LICENSE file for details
#

import tempfile
import pprint
import inspect
import sys
import struct
import string
import re
import itertools
from subprocess import *
import config

# http://wiki.python.org/moin/PythonDecoratorLibrary#Memoize
# http://stackoverflow.com/questions/8856164/class-decorator-decorating-method-in-python
class memoized(object):
    """
    Decorator. Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).
    """
    def __init__(self, func):
        self.func = func
        self.instance = None # bind with instance class of decorated method
        self.cache = {}
        self.__doc__ = inspect.getdoc(self.func)

    def __call__(self, *args, **kwargs):
        try:
            return self.cache[(self.func, self.instance, args) + tuple(kwargs.items())]
        except KeyError:
            if self.instance is None:
                value = self.func(*args, **kwargs)
            else:
                value = self.func(self.instance, *args, **kwargs)
            self.cache[(self.func, self.instance, args) + tuple(kwargs.items())] = value
            return value
        except TypeError:
            # uncachable -- for instance, passing a list as an argument.
            # Better to not cache than to blow up entirely.
            if self.instance is None:
                return self.func(*args, **kwargs)
            else:
                return self.func(self.instance, *args, **kwargs)

    def __repr__(self):
        """Return the function's docstring."""
        return self.__doc__

    def __get__(self, obj, objtype):
        """Support instance methods."""
        if obj is None:
            return self
        else:
            self.instance = obj
            return self

    def _reset(self):
        """Reset the cache"""
        for cached in self.cache.keys():
            if cached[0] == self.func and cached[1] == self.instance:
                del self.cache[cached]

def reset_cache(module=None):
    """
    Reset memoized caches of an instance/module
    """
    if module is None:
        module = sys.modules['__main__']
        
    for m in dir(module):
        m = getattr(module, m)
        if isinstance(m, memoized):
            m._reset()
        else:
            for f in dir(m):
                f = getattr(m, f)
                if isinstance(f, memoized):
                    f._reset()

    return True

def tmpfile(pref="peda-"):
    """Create and return a temporary file with custom prefix"""
    return tempfile.NamedTemporaryFile(prefix=pref)

def colorize(text, color=None, attrib=None):
    """
    Colorize text using ansicolor
    ref: https://github.com/hellman/libcolors/blob/master/libcolors.py
    """
    # ansicolor definitions
    COLORS = {"black": "30", "red": "31", "green": "32", "yellow": "33",
                "blue": "34", "purple": "35", "cyan": "36", "white": "37"}
    CATTRS = {"regular": "0", "bold": "1", "underline": "4", "strike": "9",
                "light": "1", "dark": "2", "invert": "7"}
    CPRE = '\033['
    CSUF = '\033[0m'

    if config.Option.get("ansicolor") != "on":
        return text
        
    ccode = ""
    if attrib:
        for attr in attrib.lower().split():
            attr = attr.strip(",+|")
            if attr in CATTRS:
                ccode += ";" + CATTRS[attr]
    if color in COLORS:
        ccode += ";" + COLORS[color]
    return CPRE + ccode + "m" + text + CSUF

def green(text, attrib=None):
    """Wrapper for colorize(text, 'green')"""
    return colorize(text, "green", attrib)

def red(text, attrib=None):
    """Wrapper for colorize(text, 'red')"""
    return colorize(text, "red", attrib)

def yellow(text, attrib=None):
    """Wrapper for colorize(text, 'yellow')"""
    return colorize(text, "yellow", attrib)

def blue(text, attrib=None):
    """Wrapper for colorize(text, 'blue')"""
    return colorize(text, "blue", attrib)

def msg(text, color=None, attrib=None, teefd=None):
    """
    Generic pretty printer with redirection
    """
    if not teefd:
        teefd = config.Option.get("_teefd")
        
    if isinstance(text, str) and "\x00" not in text:
        print colorize(text, color, attrib)
        if teefd:
            print >> teefd, colorize(text, color, attrib)
    else:
        pprint.pprint(text)
        if teefd:
            pprint.pprint(text, teefd)

def warning_msg(text):
    """Colorize warning message with prefix"""
    msg(colorize("Warning: " + text, "yellow"))

def error_msg(text):
    """Colorize error message with prefix"""
    msg(colorize("Error: " + text, "red"))

def debug_msg(text):
    """Colorize debug message with prefix"""
    msg(colorize("Debug: " + text, "blue"))

def trim(docstring):
    """
    Handle docstring indentation, ref: PEP257
    """
    if not docstring:
        return ''
    # Convert tabs to spaces (following the normal Python rules)
    # and split into a list of lines:
    lines = docstring.expandtabs().splitlines()
    # Determine minimum indentation (first line doesn't count):
    indent = sys.maxint
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped:
            indent = min(indent, len(line) - len(stripped))
    # Remove indentation (first line is special):
    trimmed = [lines[0].strip()]
    if indent < sys.maxint:
        for line in lines[1:]:
            trimmed.append(line[indent:].rstrip())
    # Strip off trailing and leading blank lines:
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    # Return a single string:
    return '\n'.join(trimmed)

def pager(text, pagesize=None):
    """
    Paging output, mimic external command less/more
    """
    i = 1
    text = text.splitlines()
    l = len(text)

    if not pagesize:
        pagesize = config.Option.get("pagesize")
    for line in text:
        msg(line)
        if i % pagesize == 0:
            ans = raw_input("--More--(%d/%d)" % (i, l))
            if ans.lower().strip() == "q":
                break
        i += 1

    return

def execute_external_command(command, cmd_input=None):
    """
    Execute external command and capture its output

    Args:
        - command (String)

    Returns:
        - output of command (String)
    """
    result = ""
    P = Popen([command], stdout=PIPE, stdin=PIPE, shell=True)
    (result, err) = P.communicate(cmd_input)
    if err:
        msg(err)
    return result

def is_printable(text, printables=""):
    """
    Check if a string is printable
    """
    return (set(str(text)) - set(string.printable + printables) == set())

def is_math_exp(str):
    """
    Check if a string is a math exprssion
    """
    charset = set("0123456789abcdefx+-*/%^")
    opers = set("+-*/%^")
    exp = set(str.lower())
    return (exp & opers != set()) and (exp - charset == set())

def normalize_argv(args, size=0):
    """
    Normalize argv to list with predefined length
    """
    args = list(args)
    for (idx, val) in enumerate(args):
        if to_int(val) is not None:
            args[idx] = to_int(val)
        if size and idx == size:
            return args[:idx]

    if size == 0:
        return args
    for i in range(len(args), size):
        args += [None]
    return args

def to_hexstr(str):
    """
    Convert a string to hex escape represent
    """
    return "".join(["\\x%02x" % ord(i) for i in str])

def to_hex(num):
    """
    Convert a number to hex format
    """
    if num < 0:
        return "-0x%x" % (-num)
    else:
        return "0x%x" % num

def to_address(num):
    """
    Convert a number to address format in hex
    """
    if num < 0:
        return to_hex(num)
    if num > 0xffffffff: # 64 bit
        return "0x%016x" % num
    else:
        return "0x%08x" % num

def to_int(val):
    """
    Convert a string to int number
    """
    try:
        return int(str(val), 0)
    except:
        return None

def str2hex(str):
    """
    Convert a string to hex encoded format
    """
    result = str.encode('hex')
    return result

def hex2str(hexnum):
    """
    Convert a number in hex format to string
    """
    if not isinstance(hexnum, str):
        hexnum = to_hex(hexnum)
    s = hexnum[2:]
    if len(s) % 2 != 0:
        s = "0" + s
    result = s.decode('hex')[::-1]
    return result

def int2hexstr(num, intsize=4):
    """
    Convert a number to hexified string
    """
    if intsize == 8:
        if num < 0:
            result = struct.pack("<q", num)
        else:
            result = struct.pack("<Q", num)
    else:
        if num < 0:
            result = struct.pack("<l", num)
        else:
            result = struct.pack("<L", num)
    return result

def list2hexstr(intlist, intsize=4):
    """
    Convert a list of number/string to hexified string
    """
    result = ""
    for value in intlist:
        if isinstance(value, str):
            result += value
        else:
            result += int2hexstr(value, intsize)
    return result

def str2intlist(data, intsize=4):
    """
    Convert a string to list of int
    """
    result = []
    data = data.decode('string_escape')[::-1]
    l = len(data)
    data = ("\x00" * (intsize - l%intsize) + data) if l%intsize != 0 else data
    for i in range(0, l, intsize):
        if intsize == 8:
            val = struct.unpack(">Q", data[i:i+intsize])[0]
        else:
            val = struct.unpack(">L", data[i:i+intsize])[0]
        result = [val] + result
    return result

@memoized
def check_badchars(data, chars=None):
    """
    Check an address or a value if it contains badchars
    """
    if to_int(data) is None:
        to_search = data
    else:
        data = to_hex(to_int(data))[2:]
        if len(data) % 2 != 0:
            data = "0" + data
        to_search = data.decode('hex')

    if not chars:
        chars = config.Option.get("badchars")
        
    if chars:
        for c in chars:
            if c in to_search:
                return True
    return False

@memoized
def format_address(addr, type):
    """Colorize an address"""
    colorcodes = {
        "data": "blue",
        "code": "red",
        "rodata": "green",
        "value": None
    }
    return colorize(addr, colorcodes[type])

@memoized
def format_reference_chain(chain):
    """
    Colorize a chain of references
    """
    v = t = vn = None
    text = ""
    if not chain:
        text += "Cannot access memory address"
    else:
        first = 1
        for (v, t, vn) in chain:
            if t != "value":
                text += "%s%s " % ("--> " if not first else "", format_address(v, t))
            else:
                text += "%s%s " % ("--> " if not first else "", v)
            first = 0

        if vn:
            text += "(%s)" % vn
        else:
            if v != "0x0":
                s = hex2str(v)
                if is_printable(s, "\x00"):
                    text += "(%s)" % repr(s.split("\x00")[0])
    return text

# vulnerable C functions, source: rats/flawfinder
VULN_FUNCTIONS = [
    "exec", "system", "gets", "popen", "getenv", "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "bcopy", "printf", "sprintf", "snprintf", "scanf",  "getchar", "getc", "read",
    "recv", "tmp", "temp"
]
@memoized
def format_disasm_code(code, nearby=None):
    """
    Format output of disassemble command with colors to highlight:
        - dangerous functions (rats/flawfinder)
        - branching: jmp, call, ret
        - testing: cmp, test

    Args:
        - code: input asm code (String)
        - nearby: address for nearby style format (Int)

    Returns:
        - colorized text code (String)
    """
    colorcodes = {
        "cmp": "red",
        "test": "red",
        "call": "green",
        "j": "yellow", # jump
        "ret": "blue",
    }
    result = ""

    if not code:
        return result

    if to_int(nearby) is not None:
        target = to_int(nearby)
    else:
        target = 0

    for line in code.splitlines():
        if ":" not in line: # not an assembly line
            result += line + "\n"
        else:
            color = style = None
            m = re.search(".*(0x[^ ]*).*:\s*([^ ]*)", line)
            if not m: # failed to parse
                result += line + "\n"
                continue
            addr, opcode = to_int(m.group(1)), m.group(2)
            for c in colorcodes:
                if c in opcode:
                    color = colorcodes[c]
                    if c == "call":
                        for f in VULN_FUNCTIONS:
                            if f in line.split(":", 1)[1]:
                                style = "bold, underline"
                                color = "red"
                                break
                    break

            prefix = line.split(":")[0]
            addr = re.search("(0x[^\s]*)", prefix)
            if addr:
                addr = to_int(addr.group(1))
            else:
                addr = -1
            line = line.split(":", 1)[1]
            if addr < target:
                style = "dark"
            elif addr == target:
                style = "bold"
                color = "green"

            code = colorize(line.split(";")[0], color, style)
            if ";" in line:
                comment = colorize(";" + line.split(";", 1)[1], color, "dark")
            else:
                comment = ""
            line = "%s:%s%s" % (prefix, code, comment)
            result += line + "\n"

    return result.rstrip()

@memoized
def cyclic_pattern(size=None, type=None):
    """
    Generate a Metasploit style cyclic pattern

    Args:
        - size: size of generated pattern (Int)
        - type: charset type
            0: basic type
            1: extended type (default)

    Returns:
        - pattern text (String)
    """
    char1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    char2 = "abcdefghijklmnopqrstuvwxyz"
    char3 = "0123456789"
    char2_ext = "%$-"
    char3_ext = "sn();"

    if size is None:
        size = 20000

    if not type:
        type = config.Option.get("pattern")

    if type == 1: # extended type
        char2 = char2_ext + char2
        char3 = char3_ext + char3

    pattern = ""
    allchars = itertools.product(char1, char2, char3)
    count = 0
    for p in allchars:
        pattern += "".join(p)
        if count > size:
            break
        count += 3

    return pattern[:size]

@memoized
def cyclic_pattern_offset(value, size=None, type=None):
    """
    Search a value if it is a part of Metasploit style cyclic pattern

    Args:
        - value: value to search for (String/Int)
        - size: size of generated pattern (Int)
        - type: charset type
            0: basic type
            1: extended type (default)

    Returns:
        - offset in pattern if found
    """
    pattern = cyclic_pattern(size, type)
    if to_int(value) is None:
        search = value
    else:
        search = hex2str(to_int(value))
        
    pos = pattern.find(search)
    return pos if pos != -1 else None
