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

import os
import ConfigParser

# change below settings to match your needs
## BEGIN OF SETTINGS ##

# external binaries, required for some commands
READELF      = "/usr/bin/readelf"
OBJDUMP      = "/usr/bin/objdump"
NASM         = "/usr/bin/nasm"
NDISASM      = "/usr/bin/ndisasm"

# PEDA global options
OPTIONS = {
    "badchars"  : ("", str, "bad characters to be filtered in payload/output, e.g: '\\x0a\\x00'"),
    "pattern"   : (1, int, "pattern type, 0 = basic, 1 = extended, 2 = maximum"),
    "p_charset" : ("", str, "custom charset for pattern_create"),
    "indent"    : (4, int, "number of ident spaces for output python payload, e.g: 0|4|8"),
    "ansicolor" : ("on", str, "enable/disable colorized output, e.g: on|off"),
    "pagesize"  : (25, int, "number of lines to display per page, 0 = disable paging"),
    "session"   : ("peda-session-#FILENAME#.txt", str, "target file to save peda session"),
    "tracedepth": (0, int, "max depth for calls/instructions tracing, 0 means no limit"),
    "tracelog"  : ("peda-trace-#FILENAME#.txt", str, "target file to save tracecall output"),
    "crashlog"  : ("peda-crashdump-#FILENAME#.txt", str, "target file to save crash dump of fuzzing"),
    "snapshot"  : ("peda-snapshot-#FILENAME#.raw", str, "target file to save crash dump of fuzzing"),
    "autosave"  : ("on", str, "auto saving peda session, e.g: on|off"),
    "payload"   : ("peda-payload-#FILENAME#.txt", str, "target file to save output of payload command"),
    "context"   : ("register,code,stack", str, "context display setting, e.g: register, code, stack, all"),
    "verbose"   : ("off", str, "show detail execution of commands, e.g: True|False"),
    "debug"     : ("off", str, "show detail error of peda commands, e.g. True|False"),
    "code_size" : (8, int, "default number of lines to show for the code context"),
    "stack_size": (8, int, "default number of lines to show for the stack context"),
    "clearscr"  : ("on", str, "clear screen after each step"),
    "_teefd"    : ("", str, "internal use only for tracelog/crashlog writing")
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
    def save():
        """save settings to config file"""
        home = os.path.expanduser('~')
        cfgdir = os.path.join(home, '.config', 'peda')

        if not os.path.exists(cfgdir):
            os.mkdir(cfgdir)

        config = os.path.join(cfgdir, 'config.ini')
        Config = ConfigParser.ConfigParser()

        cfgfile = open(config, 'w')

        # add the settings to the structure of the file, and lets write it out...
        Config.add_section('Options')

        for key, value in Option.options.items():
            if not key.startswith("_"):
                value = Option.get(key)
                Config.set('Options', key, value)

        Config.write(cfgfile)
        cfgfile.close()

    @staticmethod
    def load():
        """load settings from config file"""
        home = os.path.expanduser('~')
        config = os.path.join(home, '.config', 'peda', 'config.ini')

        Config = ConfigParser.ConfigParser()
        if not os.path.exists(config):
            return

        Config.read(config)
        for option in Config.options('Options'):
            if option in Option.options.keys():
                if Option.options[option][1] == int:
                    Option.set(option, Config.getint('Options', option))
                if Option.options[option][1] == str:
                    Option.set(option, Config.get('Options', option))

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
            Option.options[name] = (value, Option.options[name][1], Option.options[name][2])
            return True
        else:
            return False

    @staticmethod
    def help(name=""):
        """display help info of options"""
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][2]
        return result
