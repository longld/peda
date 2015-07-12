#
#       PEDA - Python Exploit Development Assistance for GDB
#
#       Copyright (C) 2012 Long Le Dinh <longld at vnsecurity.net>
#
#       License: see LICENSE file for details
#

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

# change below settings to match your needs
## BEGIN OF SETTINGS ##

# external binaries, required for some commands
READELF      = "/usr/bin/readelf"
OBJDUMP      = "/usr/bin/objdump"
NASM         = "/usr/bin/nasm"
NDISASM      = "/usr/bin/ndisasm"

# PEDA global options
OPTIONS = {
    "badchars"  : ("", "bad characters to be filtered in payload/output, e.g: '\\x0a\\x00'"),
    "pattern"   : (1, "pattern type, 0 = basic, 1 = extended, 2 = maximum"),
    "p_charset" : ("", "custom charset for pattern_create"),
    "indent"    : (4, "number of ident spaces for output python payload, e.g: 0|4|8"),
    "ansicolor" : ("on", "enable/disable colorized output, e.g: on|off"),    
    "pagesize"  : (25, "number of lines to display per page, 0 = disable paging"),
    "session"   : ("peda-session-#FILENAME#.txt", "target file to save peda session"),
    "tracedepth": (0, "max depth for calls/instructions tracing, 0 means no limit"),
    "tracelog"  : ("peda-trace-#FILENAME#.txt", "target file to save tracecall output"),
    "crashlog"  : ("peda-crashdump-#FILENAME#.txt", "target file to save crash dump of fuzzing"),
    "snapshot"  : ("peda-snapshot-#FILENAME#.raw", "target file to save crash dump of fuzzing"),
    "autosave"  : ("on", "auto saving peda session, e.g: on|off"),
    "payload"   : ("peda-payload-#FILENAME#.txt", "target file to save output of payload command"),
    "context"   : ("register,code,stack", "context display setting, e.g: register, code, stack, all"),
    "verbose"   : ("off", "show detail execution of commands, e.g: on|off"),
    "debug"     : ("off", "show detail error of peda commands, e.g: on|off"),
    "_teefd"    : ("", "internal use only for tracelog/crashlog writing")
}

## END OF SETTINGS ##

class Option(object):
    """
    Class to access global options of PEDA commands and functions
    TODO: save/load option to/from file
    """
    options = OPTIONS.copy()
    def __init__(self):
        """option format: name = (value, 'help message')"""
        pass


    @staticmethod
    def reset():
        """reset to default options"""
        Option.options = OPTIONS.copy()
        return True

    @staticmethod
    def show(name=""):
        """display options"""
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][0]
        return result

    @staticmethod
    def get(name):
        """get option"""
        if name in Option.options:
            return Option.options[name][0]
        else:
            return None

    @staticmethod
    def set(name, value):
        """set option"""
        if name in Option.options:
            Option.options[name] = (value, Option.options[name][1])
            return True
        else:
            return False

    @staticmethod
    def help(name=""):
        """display help info of options"""
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][1]
        return result
