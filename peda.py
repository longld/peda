#       PEDA - Python Exploit Development Assistance for GDB
#
#       Copyright (C) 2012 Long Le Dinh <longld at vnsecurity.net>
#
#       License: see LICENSE file for details
#

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import os
import sys
import shlex
import string
import time
import signal
import traceback
import codecs

# point to absolute path of peda.py
PEDAFILE = os.path.abspath(os.path.expanduser(__file__))
if os.path.islink(PEDAFILE):
    PEDAFILE = os.readlink(PEDAFILE)
sys.path.insert(0, os.path.dirname(PEDAFILE) + "/lib/")

# Use six library to provide Python 2/3 compatibility
import six
from six.moves import range
from six.moves import input
try:
    import six.moves.cPickle as pickle
except ImportError:
    import pickle



from skeleton import *
from shellcode import *
from utils import *
import config
from nasm import *

if sys.version_info.major == 3:
    from urllib.request import urlopen
    from urllib.parse import urlencode
    pyversion = 3
else:
    from urllib import urlopen
    from urllib import urlencode
    pyversion = 2

REGISTERS = {
    8 : ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"],
    16: ["ax", "bx", "cx", "dx"],
    32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"],
    64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
}

###########################################################################
class PEDA(object):
    """
    Class for actual functions of PEDA commands
    """
    def __init__(self):
        self.SAVED_COMMANDS = {} # saved GDB user's commands


    ####################################
    #   GDB Interaction / Misc Utils   #
    ####################################
    def execute(self, gdb_command):
        """
        Wrapper for gdb.execute, catch the exception so it will not stop python script

        Args:
            - gdb_command (String)

        Returns:
            - True if execution succeed (Bool)
        """
        try:
            gdb.execute(gdb_command)
            return True
        except Exception as e:
            if config.Option.get("debug") == "on":
                msg('Exception (%s): %s' % (gdb_command, e), "red")
                traceback.print_exc()
            return False

    def execute_redirect(self, gdb_command, silent=False):
        """
        Execute a gdb command and capture its output

        Args:
            - gdb_command (String)
            - silent: discard command's output, redirect to /dev/null (Bool)

        Returns:
            - output of command (String)
        """
        result = None
        #init redirection
        if silent:
            logfd = open(os.path.devnull, "r+")
        else:
            logfd = tmpfile()
        logname = logfd.name
        gdb.execute('set logging off') # prevent nested call
        gdb.execute('set height 0') # disable paging
        gdb.execute('set logging file %s' % logname)
        gdb.execute('set logging overwrite on')
        gdb.execute('set logging redirect on')
        gdb.execute('set logging on')
        try:
            gdb.execute(gdb_command)
            gdb.flush()
            gdb.execute('set logging off')
            if not silent:
                logfd.flush()
                result = logfd.read()
            logfd.close()
        except Exception as e:
            gdb.execute('set logging off') #to be sure
            if config.Option.get("debug") == "on":
                msg('Exception (%s): %s' % (gdb_command, e), "red")
                traceback.print_exc()
            logfd.close()
        if config.Option.get("verbose") == "on":
            msg(result)
        return result

    def parse_and_eval(self, exp):
        """
        Work around implementation for gdb.parse_and_eval with enhancements

        Args:
            - exp: expression to evaluate (String)

        Returns:
            - value of expression
        """

        regs = sum(REGISTERS.values(), [])
        for r in regs:
            if "$"+r not in exp and "e"+r not in exp and "r"+r not in exp:
                exp = exp.replace(r, "$%s" % r)

        p = re.compile("(.*)\[(.*)\]") # DWORD PTR [esi+eax*1]
        matches = p.search(exp)
        if not matches:
            p = re.compile("(.*).s:(0x.*)") # DWORD PTR ds:0xdeadbeef
            matches = p.search(exp)

        if matches:
            mod = "w"
            if "BYTE" in matches.group(1):
                mod = "b"
            elif "QWORD" in matches.group(1):
                mod = "g"
            elif "DWORD" in matches.group(1):
                mod = "w"
            elif "WORD" in matches.group(1):
                mod = "h"

            out = self.execute_redirect("x/%sx %s" % (mod, matches.group(2)))
            if not out:
                return None
            else:
                return out.split(":\t")[-1].strip()

        else:
            out = self.execute_redirect("print %s" % exp)
        if not out:
            return None
        else:
            out = gdb.history(0).__str__()
            out = out.encode('ascii', 'ignore')
            out = decode_string_escape(out)
            return out.strip()

    def string_to_argv(self, str):
        """
        Convert a string to argv list, pre-processing register and variable values

        Args:
            - str: input string (String)

        Returns:
            - argv list (List)
        """
        try:
            str = str.encode('ascii', 'ignore')
        except:
            pass
        args = list(map(lambda x: decode_string_escape(x), shlex.split(str.decode())))
        # need more processing here
        for idx, a in enumerate(args):
            a = a.strip(",")
            if a.startswith("$"): # try to get register/variable value
                v = self.parse_and_eval(a)
                if v != None and v != "void":
                    if v.startswith("0x"): # int
                        args[idx] = v.split()[0] # workaround for 0xdeadbeef <symbol+x>
                    else: # string, complex data
                        args[idx] = v
            elif a.startswith("+"): # relative value to prev arg
                adder = to_int(self.parse_and_eval(a[1:]))
                if adder is not None:
                    args[idx] = "%s" % to_hex(to_int(args[idx-1]) + adder)
            elif is_math_exp(a):
                try:
                    v = eval("%s" % a)
                    # XXX hack to avoid builtin functions/types
                    if not isinstance(v, six.string_types + six.integer_types):
                        continue
                    args[idx] = "%s" % (to_hex(v) if to_int(v) != None else v)
                except:
                    pass
        if config.Option.get("verbose") == "on":
            msg(args)
        return args


    ################################
    #   GDB User-Defined Helpers   #
    ################################
    def save_user_command(self, cmd):
        """
        Save user-defined command and deactivate it

        Args:
            - cmd: user-defined command (String)

        Returns:
            - True if success to save (Bool)
        """
        commands = self.execute_redirect("show user %s" % cmd)
        if not commands:
            return False

        commands = "\n".join(commands.splitlines()[1:])
        commands = "define %s\n" % cmd + commands + "end\n"
        self.SAVED_COMMANDS[cmd] = commands
        tmp = tmpfile()
        tmp.write("define %s\nend\n" % cmd)
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    def define_user_command(self, cmd, code):
        """
        Define a user-defined command, overwrite the old content

        Args:
            - cmd: user-defined command (String)
            - code: gdb script code to append (String)

        Returns:
            - True if success to define (Bool)
        """
        commands = "define %s\n" % cmd + code + "\nend\n"
        tmp = tmpfile(is_binary_file=False)
        tmp.write(commands)
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    def append_user_command(self, cmd, code):
        """
        Append code to a user-defined command, define new command if not exist

        Args:
            - cmd: user-defined command (String)
            - code: gdb script code to append (String)

        Returns:
            - True if success to append (Bool)
        """

        commands = self.execute_redirect("show user %s" % cmd)
        if not commands:
            return self.define_user_command(cmd, code)
        # else
        commands = "\n".join(commands.splitlines()[1:])
        if code in commands:
            return True

        commands = "define %s\n" % cmd + commands + code + "\nend\n"
        tmp = tmpfile()
        tmp.write(commands)
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    def restore_user_command(self, cmd):
        """
        Restore saved user-defined command

        Args:
            - cmd: user-defined command (String)

        Returns:
            - True if success to restore (Bool)
        """
        if cmd == "all":
            commands = "\n".join(self.SAVED_COMMANDS.values())
            self.SAVED_COMMANDS = {}
        else:
            if cmd not in self.SAVED_COMMANDS:
                return False
            else:
                commands = self.SAVED_COMMANDS[cmd]
                self.SAVED_COMMANDS.pop(cmd)
        tmp = tmpfile()
        tmp.write(commands)
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()

        return result

    def run_gdbscript_code(self, code):
        """
        Run basic gdbscript code as it is typed in interactively

        Args:
            - code: gdbscript code, lines are splitted by "\n" or ";" (String)

        Returns:
            - True if success to run (Bool)
        """
        tmp = tmpfile()
        tmp.write(code.replace(";", "\n"))
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    #########################
    #   Debugging Helpers   #
    #########################
    @memoized
    def is_target_remote(self):
        """
        Check if current target is remote

        Returns:
            - True if target is remote (Bool)
        """
        out = self.execute_redirect("info program")
        if out and "serial line" in out: # remote target
            return True

        return False

    @memoized
    def getfile(self):
        """
        Get exec file of debugged program

        Returns:
            - full path to executable file (String)
        """
        result = None
        out = self.execute_redirect('info files')
        if out and '"' in out:
            p = re.compile(".*exec file:\s*`(.*)'")
            m = p.search(out)
            if m:
                result = m.group(1)
            else: # stripped file, get symbol file
                p = re.compile("Symbols from \"([^\"]*)")
                m = p.search(out)
                if m:
                    result = m.group(1)

        return result

    def get_status(self):
        """
        Get execution status of debugged program

        Returns:
            - current status of program (String)
                STOPPED - not being run
                BREAKPOINT - breakpoint hit
                SIGXXX - stopped by signal XXX
                UNKNOWN - unknown, not implemented
        """
        status = "UNKNOWN"
        out = self.execute_redirect("info program")
        for line in out.splitlines():
            if line.startswith("It stopped"):
                if "signal" in line: # stopped by signal
                    status = line.split("signal")[1].split(",")[0].strip()
                    break
                if "breakpoint" in line: # breakpoint hit
                    status = "BREAKPOINT"
                    break
            if "not being run" in line:
                status = "STOPPED"
                break
        return status

    @memoized
    def getpid(self):
        """
        Get PID of the debugged process

        Returns:
            - pid (Int)
        """

        out = None
        status = self.get_status()
        if not status or status == "STOPPED":
            return None
        pid = gdb.selected_inferior().pid
        return int(pid) if pid else None

    def getos(self):
        """
        Get running OS info

        Returns:
            - os version (String)
        """
        # TODO: get remote os by calling uname()
        return os.uname()[0]

    @memoized
    def getarch(self):
        """
        Get architecture of debugged program

        Returns:
            - tuple of architecture info (arch (String), bits (Int))
        """
        arch = "unknown"
        bits = 32
        out = self.execute_redirect('maintenance info sections ?').splitlines()
        for line in out:
            if "file type" in line:
                arch = line.split()[-1][:-1]
                break
        if "64" in arch:
            bits = 64
        return (arch, bits)

    def intsize(self):
        """
        Get dword size of debugged program

        Returns:
            - size (Int)
                + intsize = 4/8 for 32/64-bits arch
        """

        (arch, bits) = self.getarch()
        return bits // 8

    def getregs(self, reglist=None):
        """
        Get value of some or all registers

        Returns:
            - dictionary of {regname(String) : value(Int)}
        """
        if reglist:
            reglist = reglist.replace(",", " ")
        else:
            reglist = ""
        regs = self.execute_redirect("info registers %s" % reglist)
        if not regs:
            return None

        result = {}
        if regs:
            for r in regs.splitlines():
                r = r.split()
                if len(r) > 1 and to_int(r[1]) is not None:
                    result[r[0]] = to_int(r[1])

        return result

    def getreg(self, register):
        """
        Get value of a specific register

        Args:
            - register: register name (String)

        Returns:
            - register value (Int)
        """
        r = register.lower()
        regs = self.execute_redirect("info registers %s" % r)
        if regs:
            regs = regs.splitlines()
            if len(regs) > 1:
                return None
            else:
                result = to_int(regs[0].split()[1])
                return result

        return None

    def set_breakpoint(self, location, temp=0, hard=0):
        """
        Wrapper for GDB break command
            - location: target function or address (String ot Int)

        Returns:
            - True if can set breakpoint
        """
        cmd = "break"
        if hard:
            cmd = "h" + cmd
        if temp:
            cmd = "t" + cmd

        if to_int(location) is not None:
            return peda.execute("%s *0x%x" % (cmd, to_int(location)))
        else:
            return peda.execute("%s %s" % (cmd, location))

    def get_breakpoint(self, num):
        """
        Get info of a specific breakpoint
        TODO: support catchpoint, watchpoint

        Args:
            - num: breakpoint number

        Returns:
            - tuple (Num(Int), Type(String), Disp(Bool), Enb(Bool), Address(Int), What(String), commands(String))
        """
        out = self.execute_redirect("info breakpoints %d" % num)
        if not out or "No breakpoint" in out:
            return None

        lines = out.splitlines()[1:]
        # breakpoint regex
        p = re.compile("^(\d*)\s*(.*breakpoint)\s*(keep|del)\s*(y|n)\s*(0x[^ ]*)\s*(.*)")
        m = p.match(lines[0])
        if not m:
            # catchpoint/watchpoint regex
            p = re.compile("^(\d*)\s*(.*point)\s*(keep|del)\s*(y|n)\s*(.*)")
            m = p.match(lines[0])
            if not m:
                return None
            else:
                (num, type, disp, enb, what) = m.groups()
                addr = ''
        else:
            (num, type, disp, enb, addr, what) = m.groups()

        disp = True if disp == "keep" else False
        enb = True if enb == "y" else False
        addr = to_int(addr)
        m = re.match("in.*at(.*:\d*)", what)
        if m:
            what = m.group(1)
        else:
            if addr: # breakpoint
                what = ""

        commands = ""
        if len(lines) > 1:
            for line in lines[1:]:
                if "already hit" in line: continue
                commands += line + "\n"

        return (num, type, disp, enb, addr, what, commands.rstrip())

    def get_breakpoints(self):
        """
        Get list of current breakpoints

        Returns:
            - list of tuple (Num(Int), Type(String), Disp(Bool), Nnb(Bool), Address(Int), commands(String))
        """
        result = []
        out = self.execute_redirect("info breakpoints")
        if not out:
            return []

        bplist = []
        for line in out.splitlines():
            m = re.match("^(\d*).*", line)
            if m and to_int(m.group(1)):
                bplist += [to_int(m.group(1))]

        for num in bplist:
            r = self.get_breakpoint(num)
            if r:
                result += [r]
        return result

    def save_breakpoints(self, filename):
        """
        Save current breakpoints to file as a script

        Args:
            - filename: target file (String)

        Returns:
            - True if success to save (Bool)
        """
        # use built-in command for gdb 7.2+
        result = self.execute_redirect("save breakpoints %s" % filename)
        if result == '':
            return True

        bplist = self.get_breakpoints()
        if not bplist:
            return False

        try:
            fd = open(filename, "w")
            for (num, type, disp, enb, addr, what, commands) in bplist:
                m = re.match("(.*)point", type)
                if m:
                    cmd = m.group(1).split()[-1]
                else:
                    cmd = "break"
                if "hw" in type and cmd == "break":
                    cmd = "h" + cmd
                if "read" in type:
                    cmd = "r" + cmd
                if "acc" in type:
                    cmd = "a" + cmd

                if not disp:
                    cmd = "t" + cmd
                if what:
                    location = what
                else:
                    location = "*0x%x" % addr
                text = "%s %s" % (cmd, location)
                if commands:
                    if "stop only" not in commands:
                        text += "\ncommands\n%s\nend" % commands
                    else:
                        text += commands.split("stop only", 1)[1]
                fd.write(text + "\n")
            fd.close()
            return True
        except:
            return False

    def get_config_filename(self, name):
        filename = peda.getfile()
        if not filename:
            filename = peda.getpid()
            if not filename:
                filename = 'unknown'

        filename = os.path.basename("%s" % filename)
        tmpl_name = config.Option.get(name)
        if tmpl_name:
            return tmpl_name.replace("#FILENAME#", filename)
        else:
            return "peda-%s-%s" % (name, filename)

    def save_session(self, filename=None):
        """
        Save current working gdb session to file as a script

        Args:
            - filename: target file (String)

        Returns:
            - True if success to save (Bool)
        """
        session = ""
        if not filename:
            filename = self.get_config_filename("session")

        # exec-wrapper
        out = self.execute_redirect("show exec-wrapper")
        wrapper = out.split('"')[1]
        if wrapper:
            session += "set exec-wrapper %s\n" % wrapper

        try:
            # save breakpoints
            self.save_breakpoints(filename)
            fd = open(filename, "a+")
            fd.write("\n" + session)
            fd.close()
            return True
        except:
            return False

    def restore_session(self, filename=None):
        """
        Restore previous saved working gdb session from file

        Args:
            - filename: source file (String)

        Returns:
            - True if success to restore (Bool)
        """
        if not filename:
            filename = self.get_config_filename("session")

        # temporarily save and clear breakpoints
        tmp = tmpfile()
        self.save_breakpoints(tmp.name)
        self.execute("delete")
        result = self.execute("source %s" % filename)
        if not result:
            self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    @memoized
    def assemble(self, asmcode, bits=None):
        """
        Assemble ASM instructions using NASM
            - asmcode: input ASM instructions, multiple instructions are separated by ";" (String)

        Returns:
            - bin code (raw bytes)
        """
        if bits is None:
            (arch, bits) = self.getarch()
        return Nasm.assemble(asmcode, bits)

    def disassemble(self, *arg):
        """
        Wrapper for disassemble command
            - arg: args for disassemble command

        Returns:
            - text code (String)
        """
        code = ""
        modif = ""
        arg = list(arg)
        if len(arg) > 1:
            if "/" in arg[0]:
                modif = arg[0]
                arg = arg[1:]
        if len(arg) == 1 and to_int(arg[0]) != None:
            arg += [to_hex(to_int(arg[0]) + 32)]

        self.execute("set disassembly-flavor intel")
        out = self.execute_redirect("disassemble %s %s" % (modif, ",".join(arg)))
        if not out:
            return None
        else:
            code = out

        return code

    @memoized
    def prev_inst(self, address, count=1):
        """
        Get previous instructions at an address

        Args:
            - address: address to get previous instruction (Int)
            - count: number of instructions to read (Int)

        Returns:
            - list of tuple (address(Int), code(String))
        """
        result = []
        backward = 64+16*count
        for i in range(backward):
            if self.getpid() and not self.is_address(address-backward+i):
                continue

            code = self.execute_redirect("disassemble %s, %s" % (to_hex(address-backward+i), to_hex(address+1)))
            if code and ("%x" % address) in code:
                lines = code.strip().splitlines()[1:-1]
                if len(lines) > count and "(bad)" not in " ".join(lines):
                    for line in lines[-count-1:-1]:
                        (addr, code) = line.split(":", 1)
                        addr = re.search("(0x[^ ]*)", addr).group(1)
                        result += [(to_int(addr), code)]
                    return result
        return None

    @memoized
    def current_inst(self, address):
        """
        Parse instruction at an address

        Args:
            - address: address to get next instruction (Int)

        Returns:
            - tuple of (address(Int), code(String))
        """
        out = self.execute_redirect("x/i 0x%x" % address)
        if not out:
            return None

        (addr, code) = out.split(":", 1)
        addr = re.search("(0x[^ ]*)", addr).group(1)
        addr = to_int(addr)
        code = code.strip()

        return (addr, code)

    @memoized
    def next_inst(self, address, count=1):
        """
        Get next instructions at an address

        Args:
            - address: address to get next instruction (Int)
            - count: number of instructions to read (Int)

        Returns:
            - - list of tuple (address(Int), code(String))
        """
        result = []
        code = self.execute_redirect("x/%di 0x%x" % (count+1, address))
        if not code:
            return None

        lines = code.strip().splitlines()
        for i in range(1, count+1):
            (addr, code) = lines[i].split(":", 1)
            addr = re.search("(0x[^ ]*)", addr).group(1)
            result += [(to_int(addr), code)]
        return result

    @memoized
    def disassemble_around(self, address, count=8):
        """
        Disassemble instructions nearby current PC or an address

        Args:
            - address: start address to disassemble around (Int)
            - count: number of instructions to disassemble

        Returns:
            - text code (String)
        """
        count = min(count, 256)
        pc = address
        if pc is None:
            return None

        # check if address is reachable
        if not self.execute_redirect("x/x 0x%x" % pc):
            return None

        prev_code = self.prev_inst(pc, count//2-1)
        if prev_code:
            start = prev_code[0][0]
        else:
            start = pc
        if start == pc:
            count = count//2

        code = self.execute_redirect("x/%di 0x%x" % (count, start))
        if "0x%x" % pc not in code:
            code = self.execute_redirect("x/%di 0x%x" % (count//2, pc))

        return code.rstrip()

    @memoized
    def xrefs(self, search="", filename=None):
        """
        Search for all call references or data access to a function/variable

        Args:
            - search: function or variable to search for (String)
            - filename: binary/library to search (String)

        Returns:
            - list of tuple (address(Int), asm instruction(String))
        """
        result = []
        if not filename:
            filename = self.getfile()

        if not filename:
            return None
        vmap = self.get_vmmap(filename)
        elfbase = vmap[0][0] if vmap else 0

        if to_int(search) is not None:
            search = "%x" % to_int(search)

        search_data = 1
        if search == "":
            search_data = 0

        out = execute_external_command("%s -M intel -z --prefix-address -d '%s' | grep '%s'" % (config.OBJDUMP, filename, search))

        for line in out.splitlines():
            if not line: continue
            addr = to_int("0x" + line.split()[0].strip())
            if not addr: continue

            # update with runtime values
            if addr < elfbase:
                addr += elfbase
            out = self.execute_redirect("x/i 0x%x" % addr)
            if out:
                line = out
                p = re.compile("\s*(0x[^ ]*).*?:\s*([^ ]*)\s*(.*)")
            else:
                p = re.compile("(.*?)\s*<.*?>\s*([^ ]*)\s*(.*)")

            m = p.search(line)
            if m:
                (address, opcode, opers) = m.groups()
                if "call" in opcode and search in opers:
                    result += [(addr, line.strip())]
                if search_data:
                     if "mov" in opcode and search in opers:
                         result += [(addr, line.strip())]

        return result

    def _get_function_args_32(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - i386
        """
        if not argc:
            argc = 0
            p = re.compile(".*mov.*\[esp(.*)\],")
            matches = p.findall(code)
            if matches:
                l = len(matches)
                for v in matches:
                    if v.startswith("+"):
                        offset = to_int(v[1:])
                        if offset is not None and (offset//4) > l:
                            continue
                    argc += 1
            else: # try with push style
                argc = code.count("push")

        argc = min(argc, 6)
        if argc == 0:
            return []

        args = []
        sp = self.getreg("sp")
        mem = self.dumpmem(sp, sp+4*argc)
        for i in range(argc):
            args += [struct.unpack("<L", mem[i*4:(i+1)*4])[0]]

        return args

    def _get_function_args_64(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - x86_64
        """

        # just retrieve max 6 args
        arg_order = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        p = re.compile(":\s*([^ ]*)\s*(.*),")
        matches = p.findall(code)
        regs = [r for (_, r) in matches]
        p = re.compile(("di|si|dx|cx|r8|r9"))
        m = p.findall(" ".join(regs))
        m = list(set(m)) # uniqify
        argc = 0
        if "si" in m and "di" not in m: # dirty fix
            argc += 1
        argc += m.count("di")
        if argc > 0:
            argc += m.count("si")
        if argc > 1:
            argc += m.count("dx")
        if argc > 2:
            argc += m.count("cx")
        if argc > 3:
            argc += m.count("r8")
        if argc > 4:
            argc += m.count("r9")

        if argc == 0:
            return []

        args = []
        regs = self.getregs()
        for i in range(argc):
            args += [regs[arg_order[i]]]

        return args

    def get_function_args(self, argc=None):
        """
        Get the guessed arguments passed to a function when stopped at a call instruction

        Args:
            - argc: force to get specific number of arguments (Int)

        Returns:
            - list of arguments (List)
        """

        args = []
        regs = self.getregs()
        if regs is None:
            return []

        (arch, bits) = self.getarch()
        pc = self.getreg("pc")
        prev_insts = self.prev_inst(pc, 12)

        code = ""
        if not prev_insts:
            return []

        for (addr, inst) in prev_insts[::-1]:
            if "call" in inst.strip().split()[0]:
                break
            code = "0x%x:%s\n" % (addr, inst) + code

        if "i386" in arch:
            args = self._get_function_args_32(code, argc)
        if "64" in arch:
            args = self._get_function_args_64(code, argc)

        return args

    @memoized
    def backtrace_depth(self, sp=None):
        """
        Get number of frames in backtrace

        Args:
            - sp: stack pointer address, for caching (Int)

        Returns:
            - depth: number of frames (Int)
        """
        backtrace = self.execute_redirect("backtrace")
        return backtrace.count("#")

    def stepuntil(self, inst, mapname=None, depth=None):
        """
        Step execution until next "inst" instruction within a specific memory range

        Args:
            - inst: the instruction to reach (String)
            - mapname: name of virtual memory region to check for the instruction (String)
            - depth: backtrace depth (Int)

        Returns:
            - tuple of (depth, instruction)
                + depth: current backtrace depth (Int)
                + instruction: current instruction (String)
        """

        if not self.getpid():
            return None

        maxdepth = to_int(config.Option.get("tracedepth"))
        if not maxdepth:
            maxdepth = 0xffffffff

        maps = self.get_vmmap()
        binname = self.getfile()
        if mapname is None:
            mapname = binname
        mapname = mapname.replace(" ", "").split(",") + [binname]
        targetmap = []
        for m in mapname:
            targetmap += self.get_vmmap(m)
        binmap = self.get_vmmap("binary")

        current_instruction = ""
        pc = self.getreg("pc")

        if depth is None:
            current_depth = self.backtrace_depth(self.getreg("sp"))
        else:
            current_depth = depth
        old_status = self.get_status()

        while True:
            status = self.get_status()
            if status != old_status:
                if "SIG" in status and status[3:] not in ["TRAP"] and not to_int(status[3:]): # ignore TRAP and numbered signals
                    current_instruction = "Interrupted: %s" % status
                    call_depth = current_depth
                    break
                if "STOP" in status:
                    current_instruction = "End of execution"
                    call_depth = current_depth
                    break

            call_depth = self.backtrace_depth(self.getreg("sp"))
            current_instruction = self.execute_redirect("x/i $pc")
            if not current_instruction:
                current_instruction = "End of execution"
                break

            p = re.compile(".*?(0x[^ :]*)")
            addr = p.search(current_instruction).group(1)
            addr = to_int(addr)
            if addr is None:
                break

            #p = re.compile(".*?:\s*([^ ]*)")
            p = re.compile(".*?:\s*(.*)")
            code = p.match(current_instruction).group(1)
            found = 0
            for i in inst.replace(",", " ").split():
                if re.match(i.strip(), code.strip()):
                    if self.is_address(addr, targetmap) and addr != pc:
                        found = 1
                        break
            if found != 0:
                break
            self.execute_redirect("stepi", silent=True)
            if not self.is_address(addr, targetmap) or call_depth > maxdepth:
                self.execute_redirect("finish", silent=True)
            pc = 0

        return (call_depth - current_depth, current_instruction.strip())

    def get_eflags(self):
        """
        Get flags value from EFLAGS register

        Returns:
            - dictionary of named flags
        """

        # Eflags bit masks, source vdb
        EFLAGS_CF = 1 << 0
        EFLAGS_PF = 1 << 2
        EFLAGS_AF = 1 << 4
        EFLAGS_ZF = 1 << 6
        EFLAGS_SF = 1 << 7
        EFLAGS_TF = 1 << 8
        EFLAGS_IF = 1 << 9
        EFLAGS_DF = 1 << 10
        EFLAGS_OF = 1 << 11

        flags = {"CF":0, "PF":0, "AF":0, "ZF":0, "SF":0, "TF":0, "IF":0, "DF":0, "OF":0}
        eflags = self.getreg("eflags")
        if not eflags:
            return None
        flags["CF"] = bool(eflags & EFLAGS_CF)
        flags["PF"] = bool(eflags & EFLAGS_PF)
        flags["AF"] = bool(eflags & EFLAGS_AF)
        flags["ZF"] = bool(eflags & EFLAGS_ZF)
        flags["SF"] = bool(eflags & EFLAGS_SF)
        flags["TF"] = bool(eflags & EFLAGS_TF)
        flags["IF"] = bool(eflags & EFLAGS_IF)
        flags["DF"] = bool(eflags & EFLAGS_DF)
        flags["OF"] = bool(eflags & EFLAGS_OF)

        return flags

    def set_eflags(self, flagname, value):
        """
        Set/clear/toggle value of a flag register

        Returns:
            - True if success (Bool)
        """

        # Eflags bit masks, source vdb
        EFLAGS_CF = 1 << 0
        EFLAGS_PF = 1 << 2
        EFLAGS_AF = 1 << 4
        EFLAGS_ZF = 1 << 6
        EFLAGS_SF = 1 << 7
        EFLAGS_TF = 1 << 8
        EFLAGS_IF = 1 << 9
        EFLAGS_DF = 1 << 10
        EFLAGS_OF = 1 << 11

        flags = {"carry": "CF", "parity": "PF", "adjust": "AF", "zero": "ZF", "sign": "SF",
                    "trap": "TF", "interrupt": "IF", "direction": "DF", "overflow": "OF"}

        flagname = flagname.lower()

        if flagname not in flags:
            return False

        eflags = self.get_eflags()
        if not eflags:
            return False

        # If value doesn't match the current, or we want to toggle, toggle
        if value is None or eflags[flags[flagname]] != value:
            reg_eflags = self.getreg("eflags")
            reg_eflags ^= eval("EFLAGS_%s" % flags[flagname])
            result = self.execute("set $eflags = 0x%x" % reg_eflags)
            return result

        return True

    def eval_target(self, inst):
        """
        Evaluate target address of an instruction, used for jumpto decision

        Args:
            - inst: ASM instruction text (String)

        Returns:
            - target address (Int)
        """

        target = None
        inst = inst.strip()
        opcode = inst.split(":\t")[-1].split()[0]
        # this regex includes x86_64 RIP relateive address reference
        p = re.compile(".*?:\s*[^ ]*\s*(.* PTR ).*(0x[^ ]*)")
        m = p.search(inst)
        if not m:
            p = re.compile(".*?:\s.*\s(0x[^ ]*|\w+)")
            m = p.search(inst)
            if m:
                target = m.group(1)
                target = self.parse_and_eval(target)
            else:
                target = None
        else:
            if "]" in m.group(2): # e.g DWORD PTR [ebx+0xc]
                p = re.compile(".*?:\s*[^ ]*\s*(.* PTR ).*\[(.*)\]")
                m = p.search(inst)
            target = self.parse_and_eval("%s[%s]" % (m.group(1), m.group(2).strip()))

        return to_int(target)

    def testjump(self, inst=None):
        """
        Test if jump instruction is taken or not

        Returns:
            - (status, address of target jumped instruction)
        """

        flags = self.get_eflags()
        if not flags:
            return None

        if not inst:
            pc = self.getreg("pc")
            inst = self.execute_redirect("x/i 0x%x" % pc)
            if not inst:
                return None

        opcode = inst.split(":\t")[-1].split()[0]
        next_addr = self.eval_target(inst)
        if next_addr is None:
            next_addr = 0

        if opcode == "jmp":
            return next_addr
        if opcode == "je" and flags["ZF"]:
            return next_addr
        if opcode == "jne" and not flags["ZF"]:
            return next_addr
        if opcode == "jg" and not flags["ZF"] and (flags["SF"] == flags["OF"]):
            return next_addr
        if opcode == "jge" and (flags["SF"] == flags["OF"]):
            return next_addr
        if opcode == "ja" and not flags["CF"] and not flags["ZF"]:
            return next_addr
        if opcode == "jae" and not flags["CF"]:
            return next_addr
        if opcode == "jl" and (flags["SF"] != flags["OF"]):
            return next_addr
        if opcode == "jle" and (flags["ZF"] or (flags["SF"] != flags["OF"])):
            return next_addr
        if opcode == "jb" and flags["CF"]:
            return next_addr
        if opcode == "jbe" and (flags["CF"] or flags["ZF"]):
            return next_addr
        if opcode == "jo" and flags["OF"]:
            return next_addr
        if opcode == "jno" and not flags["OF"]:
            return next_addr
        if opcode == "jz" and flags["ZF"]:
            return next_addr
        if opcode == "jnz" and flags["OF"]:
            return next_addr

        return None

    def take_snapshot(self):
        """
        Take a snapshot of current process
        Warning: this is not thread safe, do not use with multithread program

        Returns:
            - dictionary of snapshot data
        """
        if not self.getpid():
            return None

        maps =  self.get_vmmap()
        if not maps:
            return None

        snapshot = {}
        # get registers
        snapshot["reg"] = self.getregs()
        # get writable memory regions
        snapshot["mem"] = {}
        for (start, end, perm, _) in maps:
            if "w" in perm:
                snapshot["mem"][start] = self.dumpmem(start, end)

        return snapshot

    def save_snapshot(self, filename=None):
        """
        Save a snapshot of current process to file
        Warning: this is not thread safe, do not use with multithread program

        Args:
            - filename: target file to save snapshot

        Returns:
            - Bool
        """
        if not filename:
            filename = self.get_config_filename("snapshot")

        snapshot = self.take_snapshot()
        if not snapshot:
            return False
        # dump to file
        fd = open(filename, "wb")
        pickle.dump(snapshot, fd, pickle.HIGHEST_PROTOCOL)
        fd.close()

        return True

    def give_snapshot(self, snapshot):
        """
        Restore a saved snapshot of current process
        Warning: this is not thread safe, do not use with multithread program

        Returns:
            - Bool
        """
        if not snapshot or not self.getpid():
            return False

        # restore memory regions
        for (addr, buf) in snapshot["mem"].items():
            self.writemem(addr, buf)

        # restore registers, SP will be the last one
        for (r, v) in snapshot["reg"].items():
            self.execute("set $%s = 0x%x" % (r, v))
            if r.endswith("sp"):
                sp = v
        self.execute("set $sp = 0x%x" % sp)

        return True

    def restore_snapshot(self, filename=None):
        """
        Restore a saved snapshot of current process from file
        Warning: this is not thread safe, do not use with multithread program

        Args:
            - file: saved snapshot

        Returns:
            - Bool
        """
        if not filename:
            filename = self.get_config_filename("snapshot")

        fd = open(filename, "rb")
        snapshot = pickle.load(fd)
        return self.give_snapshot(snapshot)


    #########################
    #   Memory Operations   #
    #########################
    @memoized
    def get_vmmap(self, name=None):
        """
        Get virtual memory mapping address ranges of debugged process

        Args:
            - name: name/address of binary/library to get mapping range (String)
                + name = "binary" means debugged program
                + name = "all" means all virtual maps

        Returns:
            - list of virtual mapping ranges (start(Int), end(Int), permission(String), mapname(String))

        """
        def _get_offline_maps():
            name = self.getfile()
            if not name:
                return None
            headers = self.elfheader()
            binmap = []
            hlist = [x for x in headers.items() if x[1][2] == 'code']
            hlist = sorted(hlist, key=lambda x:x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "rx-p", name)]

            hlist = [x for x in headers.items() if x[1][2] == 'rodata']
            hlist = sorted(hlist, key=lambda x:x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "r--p", name)]

            hlist = [x for x in headers.items() if x[1][2] == 'data']
            hlist = sorted(hlist, key=lambda x:x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "rw-p", name)]

            return binmap

        def _get_allmaps_osx(pid, remote=False):
            maps = []
            #_DATA                 00007fff77975000-00007fff77976000 [    4K] rw-/rw- SM=COW  /usr/lib/system/libremovefile.dylib
            pattern = re.compile("([^\n]*)\s*  ([0-9a-f][^-\s]*)-([^\s]*) \[.*\]\s([^/]*).*  (.*)")

            if remote: # remote target, not yet supported
                return maps
            else: # local target
                try:  out = execute_external_command("/usr/bin/vmmap -w %s" % self.getpid())
                except: error_msg("could not read vmmap of process")

            matches = pattern.findall(out)
            if matches:
                for (name, start, end, perm, mapname) in matches:
                    if name.startswith("Stack"):
                        mapname = "[stack]"
                    start = to_int("0x%s" % start)
                    end = to_int("0x%s" % end)
                    if mapname == "":
                        mapname = name.strip()
                    maps += [(start, end, perm, mapname)]
            return maps


        def _get_allmaps_freebsd(pid, remote=False):
            maps = []
            mpath = "/proc/%s/map" % pid
            # 0x8048000 0x8049000 1 0 0xc36afdd0 r-x 1 0 0x1000 COW NC vnode /path/to/file NCH -1
            pattern = re.compile("0x([0-9a-f]*) 0x([0-9a-f]*)(?: [^ ]*){3} ([rwx-]*)(?: [^ ]*){6} ([^ ]*)")

            if remote: # remote target, not yet supported
                return maps
            else: # local target
                try:  out = open(mpath).read()
                except: error_msg("could not open %s; is procfs mounted?" % mpath)

            matches = pattern.findall(out)
            if matches:
                for (start, end, perm, mapname) in matches:
                    if start[:2] in ["bf", "7f", "ff"] and "rw" in perm:
                        mapname = "[stack]"
                    start = to_int("0x%s" % start)
                    end = to_int("0x%s" % end)
                    if mapname == "-":
                        if start == maps[-1][1] and maps[-1][-1][0] == "/":
                            mapname = maps[-1][-1]
                        else:
                            mapname = "mapped"
                    maps += [(start, end, perm, mapname)]
            return maps

        def _get_allmaps_linux(pid, remote=False):
            maps = []
            mpath = "/proc/%s/maps" % pid
            #00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
            pattern = re.compile("([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)")

            if remote: # remote target
                tmp = tmpfile()
                self.execute("remote get %s %s" % (mpath, tmp.name))
                tmp.seek(0)
                out = tmp.read()
                tmp.close()
            else: # local target
                out = open(mpath).read()

            matches = pattern.findall(out)
            if matches:
                for (start, end, perm, mapname) in matches:
                    start = to_int("0x%s" % start)
                    end = to_int("0x%s" % end)
                    if mapname == "":
                        mapname = "mapped"
                    maps += [(start, end, perm, mapname)]
            return maps

        result = []
        pid = self.getpid()
        if not pid: # not running, try to use elfheader()
            try:
                return _get_offline_maps()
            except:
                return []

        # retrieve all maps
        os   = self.getos()
        rmt  = self.is_target_remote()
        maps = []
        try:
            if   os == "FreeBSD": maps = _get_allmaps_freebsd(pid, rmt)
            elif os == "Linux"  : maps = _get_allmaps_linux(pid, rmt)
            elif os == "Darwin" : maps = _get_allmaps_osx(pid, rmt)
        except Exception as e:
            if config.Option.get("debug") == "on":
                msg("Exception: %s" %e)
                traceback.print_exc()

        # select maps matched specific name
        if name == "binary":
            name = self.getfile()
        if name is None or name == "all":
            name = ""

        if to_int(name) is None:
            for (start, end, perm, mapname) in maps:
                if name in mapname:
                    result += [(start, end, perm, mapname)]
        else:
            addr = to_int(name)
            for (start, end, perm, mapname) in maps:
                if start <= addr and addr < end:
                    result += [(start, end, perm, mapname)]

        return result

    @memoized
    def get_vmrange(self, address, maps=None):
        """
        Get virtual memory mapping range of an address

        Args:
            - address: target address (Int)
            - maps: only find in provided maps (List)

        Returns:
            - tuple of virtual memory info (start, end, perm, mapname)
        """
        if address is None:
            return None
        if maps is None:
            maps = self.get_vmmap()
        if maps:
            for (start, end, perm, mapname) in maps:
                if start <= address and end > address:
                    return (start, end, perm, mapname)
        # failed to get the vmmap
        else:
            try:
                gdb.selected_inferior().read_memory(address, 1)
                start = address & 0xfffffffffffff000
                end = start + 0x1000
                return (start, end, 'rwx', 'unknown')
            except:
                return None


    @memoized
    def is_executable(self, address, maps=None):
        """
        Check if an address is executable

        Args:
            - address: target address (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if address belongs to an executable address range (Bool)
        """
        vmrange = self.get_vmrange(address, maps)
        if vmrange and "x" in vmrange[2]:
            return True
        else:
            return False

    @memoized
    def is_writable(self, address, maps=None):
        """
        Check if an address is writable

        Args:
            - address: target address (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if address belongs to a writable address range (Bool)
        """
        vmrange = self.get_vmrange(address, maps)
        if vmrange and "w" in vmrange[2]:
            return True
        else:
            return False

    @memoized
    def is_address(self, value, maps=None):
        """
        Check if a value is a valid address (belongs to a memory region)

        Args:
            - value (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if value belongs to an address range (Bool)
        """
        vmrange = self.get_vmrange(value, maps)
        return vmrange is not None

    @memoized
    def get_disasm(self, address, count=1):
        """
        Get the ASM code of instruction at address

        Args:
            - address: address to read instruction (Int)
            - count: number of code lines (Int)

        Returns:
            - asm code (String)
        """
        code = self.execute_redirect("x/%di 0x%x" % (count, address))
        if code:
            return code.rstrip()
        else:
            return ""

    def dumpmem(self, start, end):
        """
        Dump process memory from start to end

        Args:
            - start: start address (Int)
            - end: end address (Int)

        Returns:
            - memory content (raw bytes)
        """
        mem = None
        logfd = tmpfile(is_binary_file=True)
        logname = logfd.name
        out = self.execute_redirect("dump memory %s 0x%x 0x%x" % (logname, start, end))
        if out is None:
            return None
        else:
            logfd.flush()
            mem = logfd.read()
            logfd.close()

        return mem

    def readmem(self, address, size):
        """
        Read content of memory at an address

        Args:
            - address: start address to read (Int)
            - size: bytes to read (Int)

        Returns:
            - memory content (raw bytes)
        """
        # try fast dumpmem if it works
        mem = self.dumpmem(address, address+size)
        if mem is not None:
            return mem

        # failed to dump, use slow x/gx way
        mem = ""
        out = self.execute_redirect("x/%dbx 0x%x" % (size, address))
        if out:
            for line in out.splitlines():
                bytes = line.split(":\t")[-1].split()
                mem += "".join([chr(int(c, 0)) for c in bytes])

        return mem

    def read_int(self, address, intsize=None):
        """
        Read an interger value from memory

        Args:
            - address: address to read (Int)
            - intsize: force read size (Int)

        Returns:
            - mem value (Int)
        """
        if not intsize:
            intsize = self.intsize()
        value = self.readmem(address, intsize)
        if value:
            value = to_int("0x" + codecs.encode(value[::-1], 'hex'))
            return value
        else:
            return None


    def read_long(self, address):
        """
        Read a long long value from memory

        Args:
            - address: address to read (Int)

        Returns:
            - mem value (Long Long)
        """
        return self.read_int(address, 8)

    def writemem(self, address, buf):
        """
        Write buf to memory start at an address

        Args:
            - address: start address to write (Int)
            - buf: data to write (raw bytes)

        Returns:
            - number of written bytes (Int)
        """
        out = None
        if not buf:
            return 0

        if self.getpid():
            # try fast restore mem
            tmp = tmpfile(is_binary_file=True)
            tmp.write(buf)
            tmp.flush()
            out = self.execute_redirect("restore %s binary 0x%x" % (tmp.name, address))
            tmp.close()
        if not out: # try the slow way
            for i in range(len(buf)):
                if not self.execute("set {char}0x%x = 0x%x" % (address+i, ord(buf[i]))):
                    return i
            return i+1
        elif "error" in out: # failed to write the whole buf, find written byte
            for i in range(0, len(buf), 1):
                if not self.is_address(address+i):
                    return i
        else:
            return len(buf)

    def write_int(self, address, value, intsize=None):
        """
        Write an interger value to memory

        Args:
            - address: address to read (Int)
            - value: int to write to (Int)
            - intsize: force write size (Int)

        Returns:
            - Bool
        """
        if not intsize:
            intsize = self.intsize()
        buf = hex2str(value, intsize).ljust(intsize, "\x00")[:intsize]
        saved = self.readmem(address, intsize)
        if not saved:
            return False

        ret = self.writemem(address, buf)
        if ret != intsize:
            self.writemem(address, saved)
            return False
        return True

    def write_long(self, address, value):
        """
        Write a long long value to memory

        Args:
            - address: address to read (Int)
            - value: value to write to

        Returns:
            - Bool
        """
        return self.write_int(address, value, 8)

    def cmpmem(self, start, end, buf):
        """
        Compare contents of a memory region with a buffer

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - buf: raw bytes

        Returns:
            - dictionary of array of diffed bytes in hex (Dictionary)
            {123: [("A", "B"), ("C", "C"))]}
        """
        line_len = 32
        if end < start:
            (start, end) = (end, start)

        mem = self.dumpmem(start, end)
        if mem is None:
            return None

        length = min(len(mem), len(buf))
        result = {}
        lineno = 0
        for i in range(length//line_len):
            diff = 0
            bytes_ = []
            for j in range(line_len):
                offset = i*line_len+j
                bytes_ += [(mem[offset:offset + 1], buf[offset:offset + 1])]
                if mem[offset] != buf[offset]:
                    diff = 1
            if diff == 1:
                result[start+lineno] = bytes_
            lineno += line_len

        bytes_ = []
        diff = 0
        for i in range(length % line_len):
            offset = lineno+i
            bytes_ += [(mem[offset:offset + 1], buf[offset:offset + 1])]
            if mem[offset] != buf[offset]:
                diff = 1
        if diff == 1:
            result[start+lineno] = bytes_

        return result

    def xormem(self, start, end, key):
        """
        XOR a memory region with a key

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - key: XOR key (String)

        Returns:
            - xored memory content (raw bytes)
        """
        mem = self.dumpmem(start, end)
        if mem is None:
            return None

        if to_int(key) != None:
            key = hex2str(to_int(key), self.intsize())
        mem = list(bytes_iterator(mem))
        for index, char in enumerate(mem):
            key_idx = index % len(key)
            mem[index] = chr(ord(char) ^ ord(key[key_idx]))

        buf = b"".join([to_binary_string(x) for x in mem])
        bytes = self.writemem(start, buf)
        return buf

    def searchmem(self, start, end, search, mem=None):
        """
        Search for all instances of a pattern in memory from start to end

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - search: string or python regex pattern (String)
            - mem: cached mem to not re-read for repeated searches (raw bytes)

        Returns:
            - list of found result: (address(Int), hex encoded value(String))

        """

        result = []
        if end < start:
            (start, end) = (end, start)

        if mem is None:
            mem = self.dumpmem(start, end)

        if not mem:
            return result

        if isinstance(search, six.string_types) and search.startswith("0x"):
            # hex number
            search = search[2:]
            if len(search) %2 != 0:
                search = "0" + search
            search = codecs.decode(search, 'hex')[::-1]
            search = re.escape(search)

        # Convert search to bytes if is not already
        if not isinstance(search, bytes):
            search = search.encode('utf-8')

        try:
            p = re.compile(search)
        except:
            search = re.escape(search)
            p = re.compile(search)

        found = list(p.finditer(mem))
        for m in found:
            index = 1
            if m.start() == m.end() and m.lastindex:
                index = m.lastindex+1
            for i in range(0,index):
                if m.start(i) != m.end(i):
                    result += [(start + m.start(i), codecs.encode(mem[m.start(i):m.end(i)], 'hex'))]

        return result

    def searchmem_by_range(self, mapname, search):
        """
        Search for all instances of a pattern in virtual memory ranges

        Args:
            - search: string or python regex pattern (String)
            - mapname: name of virtual memory range (String)

        Returns:
            - list of found result: (address(Int), hex encoded value(String))
        """

        result = []
        ranges = self.get_vmmap(mapname)
        if ranges:
            for (start, end, perm, name) in ranges:
                if "r" in perm:
                    result += self.searchmem(start, end, search)

        return result

    @memoized
    def search_reference(self, search, mapname=None):
        """
        Search for all references to a value in memory ranges

        Args:
            - search: string or python regex pattern (String)
            - mapname: name of target virtual memory range (String)

        Returns:
            - list of found result: (address(int), hex encoded value(String))
        """

        maps = self.get_vmmap()
        ranges = self.get_vmmap(mapname)
        result = []
        search_result = []
        for (start, end, perm, name) in maps:
            if "r" in perm:
                search_result += self.searchmem(start, end, search)

        for (start, end, perm, name) in ranges:
            for (a, v) in search_result:
                result += self.searchmem(start, end, to_address(a))

        return result

    @memoized
    def search_address(self, searchfor="stack", belongto="binary"):
        """
        Search for all valid addresses in memory ranges

        Args:
            - searchfor: memory region to search for addresses (String)
            - belongto: memory region that target addresses belong to (String)

        Returns:
            - list of found result: (address(Int), value(Int))
        """

        result = []
        maps = self.get_vmmap()
        if maps is None:
            return result

        searchfor_ranges = self.get_vmmap(searchfor)
        belongto_ranges = self.get_vmmap(belongto)
        step = self.intsize()
        for (start, end, _, _) in searchfor_ranges[::-1]: # dirty trick, to search in rw-p mem first
            mem = self.dumpmem(start, end)
            if not mem:
                continue
            for i in range(0, len(mem), step):
                search = "0x" + codecs.encode(mem[i:i+step][::-1], 'hex').decode('utf-8')
                addr = to_int(search)
                if self.is_address(addr, belongto_ranges):
                    result += [(start+i, addr)]

        return result

    @memoized
    def search_pointer(self, searchfor="stack", belongto="binary"):
        """
        Search for all valid pointers in memory ranges

        Args:
            - searchfor: memory region to search for pointers (String)
            - belongto: memory region that pointed addresses belong to (String)

        Returns:
            - list of found result: (address(Int), value(Int))
        """

        search_result = []
        result = []
        maps = self.get_vmmap()
        searchfor_ranges = self.get_vmmap(searchfor)
        belongto_ranges = self.get_vmmap(belongto)
        step = self.intsize()
        for (start, end, _, _) in searchfor_ranges[::-1]:
            mem = self.dumpmem(start, end)
            if not mem:
                continue
            for i in range(0, len(mem), step):
                search = "0x" + codecs.encode(mem[i:i+step][::-1], 'hex').decode('utf-8')
                addr = to_int(search)
                if self.is_address(addr):
                    (v, t, vn) = self.examine_mem_value(addr)
                    if t != 'value':
                        if self.is_address(to_int(vn), belongto_ranges):
                            if (to_int(v), v) not in search_result:
                                search_result += [(to_int(v), v)]

            for (a, v) in search_result:
                result += self.searchmem(start, end, to_address(a), mem)

        return result

    @memoized
    def examine_mem_value(self, value):
        """
        Examine a value in memory for its type and reference

        Args:
            - value: value to examine (Int)

        Returns:
            - tuple of (value(Int), type(String), next_value(Int))
        """
        def examine_data(value, bits=32):
            out = self.execute_redirect("x/%sx 0x%x" % ("g" if bits == 64 else "w", value))
            if out:
                v = out.split(":\t")[-1].strip()
                if is_printable(int2hexstr(to_int(v), bits//8)):
                    out = self.execute_redirect("x/s 0x%x" % value)
            return out

        result = (None, None, None)
        if value is None:
            return result

        maps = self.get_vmmap()
        binmap = self.get_vmmap("binary")

        (arch, bits) = self.getarch()
        if not self.is_address(value): # a value
            result = (to_hex(value), "value", "")
            return result
        else:
            (_, _, _, mapname) = self.get_vmrange(value)

        # check for writable first so rwxp mem will be treated as data
        if self.is_writable(value): # writable data address
            out = examine_data(value, bits)
            if out:
                result = (to_hex(value), "data", out.split(":", 1)[1].strip())

        elif self.is_executable(value): # code/rodata address
            if self.is_address(value, binmap):
                headers = self.elfheader()
            else:
                headers = self.elfheader_solib(mapname)

            if headers:
                headers = sorted(headers.items(), key=lambda x: x[1][1])
                for (k, (start, end, type)) in headers:
                    if value >= start and value < end:
                        if type == "code":
                            out = self.get_disasm(value)
                            p = re.compile(".*?0x[^ ]*?\s(.*)")
                            m = p.search(out)
                            result = (to_hex(value), "code", m.group(1))
                        else: # rodata address
                            out = examine_data(value, bits)
                            result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
                        break

                if result[0] is None: # not fall to any header section
                    out = examine_data(value, bits)
                    result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())

            else: # not belong to any lib: [heap], [vdso], [vsyscall], etc
                out = self.get_disasm(value)
                if "(bad)" in out:
                    out = examine_data(value, bits)
                    result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
                else:
                    p = re.compile(".*?0x[^ ]*?\s(.*)")
                    m = p.search(out)
                    result = (to_hex(value), "code", m.group(1))

        else: # readonly data address
            out = examine_data(value, bits)
            if out:
                result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
            else:
                result = (to_hex(value), "rodata", "MemError")

        return result

    @memoized
    def examine_mem_reference(self, value, depth=5):
        """
        Deeply examine a value in memory for its references

        Args:
            - value: value to examine (Int)

        Returns:
            - list of tuple of (value(Int), type(String), next_value(Int))
        """
        result = []
        if depth <= 0:
            depth = 0xffffffff

        (v, t, vn) = self.examine_mem_value(value)
        while vn is not None:
            if len(result) > depth:
                _v, _t, _vn = result[-1]
                result[-1] = (_v, _t, "--> ...")
                break

            result += [(v, t, vn)]
            if v == vn or to_int(v) == to_int(vn): # point to self
                break
            if to_int(vn) is None:
                break
            if to_int(vn) in [to_int(v) for (v, _, _) in result]: # point back to previous value
                break
            (v, t, vn) = self.examine_mem_value(to_int(vn))

        return result

    @memoized
    def format_search_result(self, result, display=256):
        """
        Format the result from various memory search commands

        Args:
            - result: result of search commands (List)
            - display: number of items to display

        Returns:
            - text: formatted text (String)
        """

        text = ""
        if not result:
            text = "Not found"
        else:
            maxlen = 0
            maps = self.get_vmmap()
            shortmaps = []
            for (start, end, perm, name) in maps:
                shortname = os.path.basename(name)
                if shortname.startswith("lib"):
                    shortname = shortname.split("-")[0]
                shortmaps += [(start, end, perm, shortname)]

            count = len(result)
            if display != 0:
                count = min(count, display)
            text += "Found %d results, display max %d items:\n" % (len(result), count)
            for (addr, v) in result[:count]:
                vmrange = self.get_vmrange(addr, shortmaps)
                maxlen = max(maxlen, len(vmrange[3]))

            for (addr, v) in result[:count]:
                vmrange = self.get_vmrange(addr, shortmaps)
                chain = self.examine_mem_reference(addr)
                text += "%s : %s" % (vmrange[3].rjust(maxlen), format_reference_chain(chain) + "\n")

        return text


    ##########################
    #     Exploit Helpers    #
    ##########################
    @memoized
    def elfentry(self):
        """
        Get entry point address of debugged ELF file

        Returns:
            - entry address (Int)
        """
        out = self.execute_redirect("info files")
        p = re.compile("Entry point: ([^\s]*)")
        if out:
            m = p.search(out)
            if m:
                return to_int(m.group(1))
        return None

    @memoized
    def elfheader(self, name=None):
        """
        Get headers information of debugged ELF file

        Args:
            - name: specific header name (String)

        Returns:
            - dictionary of headers {name(String): (start(Int), end(Int), type(String))}
        """
        elfinfo = {}
        elfbase = 0
        if self.getpid():
            binmap = self.get_vmmap("binary")
            elfbase = binmap[0][0] if binmap else 0

        out = self.execute_redirect("maintenance info sections")
        if not out:
            return {}

        p = re.compile("\s*(0x[^-]*)->(0x[^ ]*) at (0x[^:]*):\s*([^ ]*)\s*(.*)")
        matches = p.findall(out)

        for (start, end, offset, hname, attr) in matches:
            start, end, offset = to_int(start), to_int(end), to_int(offset)
            # skip unuseful header
            if start < offset:
                continue
            # if PIE binary, update with runtime address
            if start < elfbase:
                start += elfbase
                end += elfbase

            if "CODE" in attr:
                htype = "code"
            elif "READONLY" in attr:
                htype = "rodata"
            else:
                htype = "data"

            elfinfo[hname.strip()] = (start, end, htype)

        result = {}
        if name is None:
            result = elfinfo
        else:
            if name in elfinfo:
                result[name] = elfinfo[name]
            else:
                for (k, v) in elfinfo.items():
                    if name in k:
                        result[k] = v
        return result

    @memoized
    def elfsymbols(self, pattern=None):
        """
        Get all non-debugging symbol information of debugged ELF file

        Returns:
            - dictionary of (address(Int), symname(String))
        """
        headers = self.elfheader()
        if ".plt" not in headers: # static binary
            return {}

        binmap = self.get_vmmap("binary")
        elfbase = binmap[0][0] if binmap else 0

        # get the .dynstr header
        headers = self.elfheader()
        if ".dynstr" not in headers:
            return {}
        (start, end, _) = headers[".dynstr"]
        mem = self.dumpmem(start, end)
        if not mem and self.getfile():
            fd = open(self.getfile())
            fd.seek(start, 0)
            mem = fd.read(end-start)
            fd.close()

        # Convert names into strings
        dynstrings = [name.decode('utf-8') for name in mem.split(b"\x00")]

        if pattern:
            dynstrings = [s for s in dynstrings if re.search(pattern, s)]

        # get symname@plt info
        symbols = {}
        for symname in dynstrings:
            if not symname: continue
            symname += "@plt"
            out = self.execute_redirect("info functions %s" % symname)
            if not out: continue
            m = re.findall(".*(0x[^ ]*)\s*%s" % re.escape(symname), out)
            for addr in m:
                addr = to_int(addr)
                if self.is_address(addr, binmap):
                    if symname not in symbols:
                        symbols[symname] = addr
                        break

        # if PIE binary, update with runtime address
        for (k, v) in symbols.items():
            if v < elfbase:
                symbols[k] = v + elfbase

        return symbols

    @memoized
    def elfsymbol(self, symname=None):
        """
        Get non-debugging symbol information of debugged ELF file

        Args:
            - name: target function name (String), special cases:
                + "data": data transfer functions
                + "exec": exec helper functions

        Returns:
            - if exact name is not provided: dictionary of tuple (symname, plt_entry)
            - if exact name is provided: dictionary of tuple (symname, plt_entry, got_entry, reloc_entry)
        """
        datafuncs = ["printf", "puts", "gets", "cpy"]
        execfuncs = ["system", "exec", "mprotect", "mmap", "syscall"]
        result = {}
        if not symname or symname in ["data", "exec"]:
            symbols = self.elfsymbols()
        else:
            symbols = self.elfsymbols(symname)

        if not symname:
            result = symbols
        else:
            sname = symname.replace("@plt", "") + "@plt"
            if sname in symbols:
                plt_addr = symbols[sname]
                result[sname] = plt_addr # plt entry
                out = self.get_disasm(plt_addr, 2)
                for line in out.splitlines():
                    if "jmp" in line:
                        addr = to_int("0x" + line.strip().rsplit("0x")[-1].split()[0])
                        result[sname.replace("@plt","@got")] = addr # got entry
                    if "push" in line:
                        addr = to_int("0x" + line.strip().rsplit("0x")[-1])
                        result[sname.replace("@plt","@reloc")] = addr # reloc offset
            else:
                keywords = [symname]
                if symname == "data":
                    keywords = datafuncs
                if symname == "exec":
                    keywords = execfuncs
                for (k, v) in symbols.items():
                    for f in keywords:
                        if f in k:
                            result[k] = v

        return result

    @memoized
    def main_entry(self):
        """
        Get address of main function of stripped ELF file

        Returns:
            - main function address (Int)
        """
        refs = self.xrefs("__libc_start_main@plt")
        if refs:
            inst = self.prev_inst(refs[0][0])
            if inst:
                addr = re.search(".*(0x.*)", inst[0][1])
                if addr:
                    return to_int(addr.group(1))
        return None

    @memoized
    def readelf_header(self, filename, name=None):
        """
        Get headers information of an ELF file using 'readelf'

        Args:
            - filename: ELF file (String)
            - name: specific header name (String)

        Returns:
            - dictionary of headers (name(String), value(Int)) (Dict)
        """
        elfinfo = {}
        vmap = self.get_vmmap(filename)
        elfbase = vmap[0][0] if vmap else 0
        out = execute_external_command("%s -W -S %s" % (config.READELF, filename))
        if not out:
            return {}
        p = re.compile(".*\[.*\] (\.[^ ]*) [^0-9]* ([^ ]*) [^ ]* ([^ ]*)(.*)")
        matches = p.findall(out)
        if not matches:
            return result

        for (hname, start, size, attr) in matches:
            start, end = to_int("0x"+start), to_int("0x"+start) + to_int("0x"+size)
            # if PIE binary or DSO, update with runtime address
            if start < elfbase:
                start += elfbase
            if end < elfbase:
                end += elfbase

            if "X" in attr:
                htype = "code"
            elif "W" in attr:
                htype = "data"
            else:
                htype = "rodata"
            elfinfo[hname.strip()] = (start, end, htype)

        result = {}
        if name is None:
            result = elfinfo
        else:
            if name in elfinfo:
                result[name] = elfinfo[name]
            else:
                for (k, v) in elfinfo.items():
                    if name in k:
                        result[k] = v
        return result

    @memoized
    def elfheader_solib(self, solib=None, name=None):
        """
        Get headers information of Shared Object Libraries linked to target

        Args:
            - solib: shared library name (String)
            - name: specific header name (String)

        Returns:
            - dictionary of headers {name(String): start(Int), end(Int), type(String))
        """
        # hardcoded ELF header type
        header_type = {"code": [".text", ".fini", ".init", ".plt", "__libc_freeres_fn"],
            "data": [".dynamic", ".data", ".ctors", ".dtors", ".jrc", ".got", ".got.plt",
                    ".bss", ".tdata", ".tbss", ".data.rel.ro", ".fini_array",
                    "__libc_subfreeres", "__libc_thread_subfreeres"]
        }

        @memoized
        def _elfheader_solib_all():
            out = self.execute_redirect("info files")
            if not out:
                return None

            p = re.compile("[^\n]*\s*(0x[^ ]*) - (0x[^ ]*) is (\.[^ ]*) in (.*)")
            soheaders = p.findall(out)

            result = []
            for (start, end, hname, libname) in soheaders:
                start, end = to_int(start), to_int(end)
                result += [(start, end, hname, os.path.realpath(libname))] # tricky, return the realpath version of libraries
            return result

        elfinfo = {}

        headers = _elfheader_solib_all()
        if not headers:
            return {}

        if solib is None:
            return headers

        vmap = self.get_vmmap(solib)
        elfbase = vmap[0][0] if vmap else 0

        for (start, end, hname, libname) in headers:
            if solib in libname:
                # if PIE binary or DSO, update with runtime address
                if start < elfbase:
                    start += elfbase
                if end < elfbase:
                    end += elfbase
                # determine the type
                htype = "rodata"
                if hname in header_type["code"]:
                    htype = "code"
                elif hname in header_type["data"]:
                    htype = "data"
                elfinfo[hname.strip()] = (start, end, htype)

        result = {}
        if name is None:
            result = elfinfo
        else:
            if name in elfinfo:
                result[name] = elfinfo[name]
            else:
                for (k, v) in elfinfo.items():
                    if name in k:
                        result[k] = v
        return result

    def checksec(self, filename=None):
        """
        Check for various security options of binary (ref: http://www.trapkit.de/tools/checksec.sh)

        Args:
            - file: path name of file to check (String)

        Returns:
            - dictionary of (setting(String), status(Int)) (Dict)
        """
        result = {}
        result["RELRO"] = 0
        result["CANARY"] = 0
        result["NX"] = 1
        result["PIE"] = 0
        result["FORTIFY"] = 0

        if filename is None:
            filename = self.getfile()

        if not filename:
            return None

        out =  execute_external_command("%s -W -a \"%s\" 2>&1" % (config.READELF, filename))
        if "Error:" in out:
            return None

        for line in out.splitlines():
            if "GNU_RELRO" in line:
                result["RELRO"] |= 2
            if "BIND_NOW" in line:
                result["RELRO"] |= 1
            if "__stack_chk_fail" in line:
                result["CANARY"] = 1
            if "GNU_STACK" in line and "RWE" in line:
                result["NX"] = 0
            if "Type:" in line and "DYN (" in line:
                result["PIE"] = 4 # Dynamic Shared Object
            if "(DEBUG)" in line and result["PIE"] == 4:
                result["PIE"] = 1
            if "_chk@" in line:
                result["FORTIFY"] = 1

        if result["RELRO"] == 1:
            result["RELRO"] = 0 # ? | BIND_NOW + NO GNU_RELRO = NO PROTECTION
        # result["RELRO"] == 2 # Partial | NO BIND_NOW + GNU_RELRO
        # result["RELRO"] == 3 # Full | BIND_NOW + GNU_RELRO
        return result

    def _verify_rop_gadget(self, start, end, depth=5):
        """
        Verify ROP gadget code from start to end with max number of instructions

        Args:
            - start: start address (Int)
            - end: end addres (Int)
            - depth: number of instructions (Int)

        Returns:
            - list of valid gadgets (address(Int), asmcode(String))
        """

        result = []
        valid = 0
        out = self.execute_redirect("disassemble 0x%x, 0x%x" % (start, end+1))
        if not out:
            return []

        code = out.splitlines()[1:-1]
        for line in code:
            if "bad" in line:
                return []
            (addr, code) = line.strip().split(":", 1)
            addr = to_int(addr.split()[0])
            result += [(addr, " ".join(code.strip().split()))]
            if "ret" in code:
                return result
            if len(result) > depth:
                break

        return []

    @memoized
    def search_asm(self, start, end, asmcode, rop=0):
        """
        Search for ASM instructions in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - asmcode: assembly instruction (String)
                + multiple instructions are separated by ";"
                + wildcard ? supported, will be replaced by registers or multi-bytes

        Returns:
            - list of (address(Int), hexbyte(String))
        """
        wildcard = asmcode.count('?')
        magic_bytes = ["0x00", "0xff", "0xdead", "0xdeadbeef", "0xdeadbeefdeadbeef"]

        ops = [x for x in asmcode.split(';') if x]
        def buildcode(code=b"", pos=0, depth=0):
            if depth == wildcard and pos == len(ops):
                yield code
                return

            c = ops[pos].count('?')
            if c > 2: return
            elif c == 0:
                asm = self.assemble(ops[pos])
                if asm:
                    for code in buildcode(code + asm, pos+1, depth):
                        yield code
            else:
                save = ops[pos]
                for regs in REGISTERS.values():
                    for reg in regs:
                        ops[pos] = save.replace("?", reg, 1)
                        for asmcode_reg in buildcode(code, pos, depth+1):
                            yield asmcode_reg
                for byte in magic_bytes:
                    ops[pos] = save.replace("?", byte, 1)
                    for asmcode_mem in buildcode(code, pos, depth+1):
                        yield asmcode_mem
                ops[pos] = save

        searches = []

        def decode_hex_escape(str_):
            """Decode string as hex and escape for regex"""
            return re.escape(codecs.decode(str_, 'hex'))

        for machine_code in buildcode():
            search = re.escape(machine_code)
            search = search.replace(decode_hex_escape(b"dead"), b"..")\
                .replace(decode_hex_escape(b"beef"), b"..")\
                .replace(decode_hex_escape(b"00"), b".")\
                .replace(decode_hex_escape(b"ff"), b".")

            if rop and 'ret' not in asmcode:
                search += b".{0,24}\\xc3"
            searches.append(search)

        if not searches:
            warning_msg("invalid asmcode: '%s'" % asmcode)
            return []

        search = b"(?=(" + b"|".join(searches) + b"))"
        candidates = self.searchmem(start, end, search)

        if rop:
            result = {}
            for (a, v) in candidates:
                gadget = self._verify_rop_gadget(a, a+len(v)//2 - 1)
                # gadget format: [(address, asmcode), (address, asmcode), ...]
                if gadget != []:
                    blen = gadget[-1][0] - gadget[0][0] + 1
                    bytes = v[:2*blen]
                    asmcode_rs = "; ".join([c for _, c in gadget])
                    if re.search(re.escape(asmcode).replace("\ ",".*").replace("\?",".*"), asmcode_rs)\
                        and a not in result:
                        result[a] = (bytes, asmcode_rs)
            result = list(result.items())
        else:
            result = []
            for (a, v) in candidates:
                asmcode = self.execute_redirect("disassemble 0x%x, 0x%x" % (a, a+(len(v)//2)))
                if asmcode:
                    asmcode = "\n".join(asmcode.splitlines()[1:-1])
                    matches = re.findall(".*:([^\n]*)", asmcode)
                    result += [(a, (v, ";".join(matches).strip()))]

        return result

    def dumprop(self, start, end, keyword=None, depth=5):
        """
        Dump unique ROP gadgets in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - keyword: to match start of gadgets (String)

        Returns:
            - dictionary of (address(Int), asmcode(String))
        """

        EXTRA_WORDS = ["BYTE ", " WORD", "DWORD ", "FWORD ", "QWORD ", "PTR ", "FAR "]
        result = {}
        mem = self.dumpmem(start, end)
        if mem is None:
            return {}

        if keyword:
            search = keyword
        else:
            search = ""

        if len(mem) > 20000: # limit backward depth if searching in large mem
            depth = 3
        found = re.finditer(b"\xc3", mem)
        found = list(found)
        for m in found:
            idx = start+m.start()
            for i in range(1, 24):
                gadget = self._verify_rop_gadget(idx-i, idx, depth)
                if gadget != []:
                    k = "; ".join([v for (a, v) in gadget])
                    if k.startswith(search):
                        for w in EXTRA_WORDS:
                            k = k.replace(w, "")
                        if k not in result:
                            result[k] = gadget[0][0]
        return result

    def common_rop_gadget(self, mapname=None):
        """
        Get common rop gadgets in binary: ret, popret, pop2ret, pop3ret, add [mem] reg, add reg [mem]

        Returns:
            - dictionary of (gadget(String), address(Int))
        """

        def _valid_register_opcode(bytes_):
            if not bytes_:
                return False

            for c in bytes_iterator(bytes_):
                if ord(c) not in list(range(0x58, 0x60)):
                    return False
            return True

        result = {}
        if mapname is None:
            mapname = "binary"
        maps = self.get_vmmap(mapname)
        if maps is None:
            return result

        for (start, end, _, _) in maps:
            if not self.is_executable(start, maps): continue

            mem = self.dumpmem(start, end)
            found = self.searchmem(start, end, b"....\xc3", mem)
            for (a, v) in found:
                v = codecs.decode(v, 'hex')
                if "ret" not in result:
                    result["ret"] = a+4
                if "leaveret" not in result:
                    if v[-2] == "\xc9":
                        result["leaveret"] = a+3
                if "popret" not in result:
                    if _valid_register_opcode(v[-2:-1]):
                        result["popret"] = a+3
                if "pop2ret" not in result:
                    if _valid_register_opcode(v[-3:-1]):
                        result["pop2ret"] = a+2
                if "pop3ret" not in result:
                    if _valid_register_opcode(v[-4:-1]):
                        result["pop3ret"] = a+1
                if "pop4ret" not in result:
                    if _valid_register_opcode(v[-5:-1]):
                        result["pop4ret"] = a

            # search for add esp, byte 0xNN
            found = self.searchmem(start, end, b"\x83\xc4([^\xc3]){0,24}\xc3", mem)
            # search for add esp, 0xNNNN
            found += self.searchmem(start, end, b"\x81\xc4([^\xc3]){0,24}\xc3", mem)
            for (a, v) in found:
                if v.startswith(b"81"):
                    offset = to_int("0x" + codecs.encode(codecs.decode(v, 'hex')[2:5][::-1], 'hex').decode('utf-8'))
                elif v.startswith(b"83"):
                    offset = to_int("0x" + v[4:6].decode('utf-8'))
                gg = self._verify_rop_gadget(a, a+len(v)//2-1)
                for (_, c) in gg:
                    if "pop" in c:
                        offset += 4
                gadget = "addesp_%d" % offset
                if gadget not in result:
                    result[gadget] = a

        return result

    def search_jmpcall(self, start, end, regname=None):
        """
        Search memory for jmp/call reg instructions

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - reg: register name (String)

        Returns:
            - list of (address(Int), instruction(String))
        """

        result = []
        REG = {0: "eax", 1: "ecx", 2: "edx", 3: "ebx", 4: "esp", 5: "ebp", 6: "esi", 7:"edi"}
        P2REG = {0: "[eax]", 1: "[ecx]", 2: "[edx]", 3: "[ebx]", 6: "[esi]", 7:"[edi]"}
        OPCODE = {0xe: "jmp", 0xd: "call"}
        P2OPCODE = {0x1: "call", 0x2: "jmp"}
        JMPREG = [b"\xff" + bytes_chr(i) for i in range(0xe0, 0xe8)]
        JMPREG += [b"\xff" + bytes_chr(i) for i in range(0x20, 0x28)]
        CALLREG = [b"\xff" + bytes_chr(i) for i in range(0xd0, 0xd8)]
        CALLREG += [b"\xff" + bytes_chr(i) for i in range(0x10, 0x18)]
        JMPCALL = JMPREG + CALLREG

        if regname is None:
            regname = ""
        regname = regname.lower()
        pattern = re.compile(b'|'.join(JMPCALL).replace(b' ', b'\ '))
        mem = self.dumpmem(start, end)
        found = pattern.finditer(mem)
        (arch, bits) = self.getarch()
        for m in list(found):
            inst = ""
            addr = start + m.start()
            opcode = codecs.encode(m.group()[1:2], 'hex')
            type = int(opcode[0:1], 16)
            reg = int(opcode[1:2], 16)
            if type in OPCODE:
                inst = OPCODE[type] + " " + REG[reg]

            if type in P2OPCODE and reg in P2REG:
                inst = P2OPCODE[type] + " " + P2REG[reg]

            if inst != "" and regname[-2:] in inst.split()[-1]:
                if bits == 64:
                    inst = inst.replace("e", "r")
                result += [(addr, inst)]

        return result

    def search_substr(self, start, end, search, mem=None):
        """
        Search for substrings of a given string/number in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - search: string to search for (String)
            - mem: cached memory (raw bytes)

        Returns:
            - list of tuple (substr(String), address(Int))
        """
        def substr(s1, s2):
            "Search for a string in another string"
            s1 = to_binary_string(s1)
            s2 = to_binary_string(s2)
            i = 1
            found = 0
            while i <= len(s1):
                if s2.find(s1[:i]) != -1:
                    found = 1
                    i += 1
                    if s1[:i-1][-1:] == b"\x00":
                        break
                else:
                    break
            if found == 1:
                return i-1
            else:
                return -1

        result = []
        if end < start:
            start, end = end, start

        if mem is None:
            mem = self.dumpmem(start, end)

        if search[:2] == "0x": # hex number
            search = search[2:]
            if len(search) %2 != 0:
                search = "0" + search
            search = codecs.decode(search, 'hex')[::-1]
        search = to_binary_string(decode_string_escape(search))
        while search:
            l = len(search)
            i = substr(search, mem)
            if i != -1:
                sub = search[:i]
                addr = start + mem.find(sub)
                if not check_badchars(addr):
                    result.append((sub, addr))
            else:
                result.append((search, -1))
                return result
            search = search[i:]
        return result


    ##############################
    #   ROP Payload Generation   #
    ##############################
    def payload_copybytes(self, target=None, data=None, template=0):
        """
        Suggest function for ret2plt exploit and generate payload for it

        Args:
            - target: address to copy data to (Int)
            - data: (String)
        Returns:
            - python code template (String)
        """
        result = ""
        funcs = ["strcpy", "sprintf", "strncpy", "snprintf", "memcpy"]

        symbols = self.elfsymbols()
        transfer = ""
        for f in funcs:
            if f+"@plt" in symbols:
                transfer = f
                break
        if transfer == "":
            warning_msg("No copy function available")
            return None

        headers = self.elfheader()
        start = min([v[0] for (k, v) in headers.items() if v[0] > 0])
        end = max([v[1] for (k, v) in headers.items() if v[2] != "data"])
        symbols = self.elfsymbol(transfer)
        if not symbols:
            warning_msg("Unable to find symbols")
            return None

        plt_func = transfer + "_plt"
        plt_addr = symbols[transfer+"@plt"]
        gadgets = self.common_rop_gadget()
        function_template = "\n".join([
            "popret = 0x%x" % gadgets["popret"],
            "pop2ret = 0x%x" % gadgets["pop2ret"],
            "pop3ret = 0x%x" % gadgets["pop3ret"],
            "def %s_payload(target, bytes):" % transfer,
            "    %s = 0x%x" % (plt_func, plt_addr),
            "    payload = []",
            "    offset = 0",
            "    for (str, addr) in bytes:",
            "",
            ])
        if "ncp" in transfer or "mem" in transfer: # memcpy() style
            function_template += "\n".join([
                "        payload += [%s, pop3ret, target+offset, addr, len(str)]" % plt_func,
                "        offset += len(str)",
                ])
        elif "snp" in transfer: # snprintf()
            function_template += "\n".join([
                "        payload += [%s, pop3ret, target+offset, len(str)+1, addr]" % plt_func,
                "        offset += len(str)",
                ])
        else:
            function_template += "\n".join([
            "        payload += [%s, pop2ret, target+offset, addr]" % plt_func,
            "        offset += len(str)",
            ])
        function_template += "\n".join(["",
            "    return payload",
            "",
            "payload = []"
            ])

        if target is None:
            if template != 0:
                return function_template
            else:
                return ""

        #text = "\n_payload = []\n"
        text = "\n"
        mem = self.dumpmem(start, end)
        bytes = self.search_substr(start, end, data, mem)

        if to_int(target) is not None:
            target = to_hex(target)
        text += "# %s <= %s\n" % (target, repr(data))
        if not bytes:
            text += "***Failed***\n"
        else:
            text += "bytes = [\n"
            for (s, a) in bytes:
                if a != -1:
                    text += "    (%s, %s),\n" % (repr(s), to_hex(a))
                else:
                    text += "    (%s, ***Failed***),\n" % repr(s)
            text += "\n".join([
                "]",
                "payload += %s_payload(%s, bytes)" % (transfer, target),
                "",
                ])

        return text


###########################################################################
class PEDACmd(object):
    """
    Class for PEDA commands that interact with GDB
    """
    commands = []
    def __init__(self):
        # list of all available commands
        self.commands = [c for c in dir(self) if callable(getattr(self, c)) and not c.startswith("_")]

    ##################
    #   Misc Utils   #
    ##################
    def _missing_argument(self):
        """
        Raise exception for missing argument, for internal use
        """
        text = "missing argument"
        error_msg(text)
        raise Exception(text)

    def _is_running(self):
        """
        Check if program is running, for internal use
        """
        pid = peda.getpid()
        if pid is None:
            text = "not running"
            warning_msg(text)
            return None
            #raise Exception(text)
        else:
            return pid

    def reload(self, *arg):
        """
        Reload PEDA sources, keep current options untouch
        Usage:
            MYNAME [name]
        """
        (modname,) = normalize_argv(arg, 1)
        # save current PEDA options
        saved_opt = config.Option
        peda_path = os.path.dirname(PEDAFILE) + "/lib/"
        if not modname:
            modname = "PEDA" # just for notification
            ret = peda.execute("source %s" % PEDAFILE)
        else:
            if not modname.endswith(".py"):
                modname = modname + ".py"
            filepath = "%s/%s" % (peda_path, modname)
            if os.path.exists(filepath):
                ret = peda.execute("source %s" % filepath)
                peda.execute("source %s" % PEDAFILE)
            else:
                ret = False

        config.Option = saved_opt
        if ret:
            msg("%s reloaded!" % modname, "blue")
        else:
            msg("Failed to reload %s source from: %s" % (modname, peda_path))
        return

    def _get_helptext(self, *arg):
        """
        Get the help text, for internal use by help command and other aliases
        """

        (cmd,) = normalize_argv(arg, 1)
        helptext = ""
        if cmd is None:
            helptext = red("PEDA", "bold") + blue(" - Python Exploit Development Assistance for GDB", "bold") + "\n"
            helptext += "For latest update, check peda project page: %s\n" % green("https://github.com/longld/peda/")
            helptext += "List of \"peda\" subcommands, type the subcommand to invoke it:\n"
            i = 0
            for cmd in self.commands:
                if cmd.startswith("_"): continue # skip internal use commands
                func = getattr(self, cmd)
                helptext += "%s -- %s\n" % (cmd, green(trim(func.__doc__.strip("\n").splitlines()[0])))
            helptext += "\nType \"help\" followed by subcommand for full documentation."
        else:
            if cmd in self.commands:
                func = getattr(self, cmd)
                lines = trim(func.__doc__).splitlines()
                helptext += green(lines[0]) + "\n"
                for line in lines[1:]:
                    if "Usage:" in line:
                        helptext += blue(line) + "\n"
                    else:
                        helptext += line + "\n"
            else:
                for c in self.commands:
                    if not c.startswith("_") and cmd in c:
                        func = getattr(self, c)
                        helptext += "%s -- %s\n" % (c, green(trim(func.__doc__.strip("\n").splitlines()[0])))

        return helptext

    def help(self, *arg):
        """
        Print the usage manual for PEDA commands
        Usage:
            MYNAME
            MYNAME command
        """

        msg(self._get_helptext(*arg))

        return
    help.options = commands

    def pyhelp(self, *arg):
        """
        Wrapper for python built-in help
        Usage:
            MYNAME (enter interactive help)
            MYNAME help_request
        """
        (request,) = normalize_argv(arg, 1)
        if request is None:
            help()
            return

        peda_methods = ["%s" % c for c in dir(PEDA) if callable(getattr(PEDA, c)) and \
                                not c.startswith("_")]

        if request in peda_methods:
            request = "peda.%s" % request
        try:
            if request.lower().startswith("peda"):
                request = eval(request)
                help(request)
                return

            if "." in request:
                module, _, function = request.rpartition('.')
                if module:
                    module = module.split(".")[0]
                    __import__(module)
                    mod = sys.modules[module]
                    if function:
                        request = getattr(mod, function)
                    else:
                        request = mod
            else:
                mod = sys.modules['__main__']
                request = getattr(mod, request)

            # wrapper for python built-in help
            help(request)
        except: # fallback to built-in help
            try:
                help(request)
            except Exception as e:
                if config.Option.get("debug") == "on":
                    msg('Exception (%s): %s' % ('pyhelp', e), "red")
                    traceback.print_exc()
                msg("no Python documentation found for '%s'" % request)

        return
    pyhelp.options = ["%s" % c for c in dir(PEDA) if callable(getattr(PEDA, c)) and \
                        not c.startswith("_")]

    # show [option | args | env]
    def show(self, *arg):
        """
        Show various PEDA options and other settings
        Usage:
            MYNAME option [optname]
            MYNAME (show all options)
            MYNAME args
            MYNAME env [envname]
        """
        # show options
        def _show_option(name=None):
            if name is None:
                name = ""
            filename = peda.getfile()
            if filename:
               filename = os.path.basename(filename)
            else:
                filename = None
            for (k, v) in sorted(config.Option.show(name).items()):
                if filename and isinstance(v, str) and "#FILENAME#" in v:
                    v = v.replace("#FILENAME#", filename)
                msg("%s = %s" % (k, repr(v)))
            return

        # show args
        def _show_arg():
            arg = peda.execute_redirect("show args")
            arg = arg.split("started is ")[1][1:-3]
            arg = (peda.string_to_argv(arg))
            if not arg:
                msg("No argument")
            for (i, a) in enumerate(arg):
                text = "arg[%d]: %s" % ((i+1), a if is_printable(a) else to_hexstr(a))
                msg(text)
            return

        # show envs
        def _show_env(name=None):
            if name is None:
                name = ""
            env = peda.execute_redirect("show env")
            for line in env.splitlines():
                (k, v) = line.split("=", 1)
                if k.startswith(name):
                    msg("%s = %s" % (k, v if is_printable(v) else to_hexstr(v)))
            return

        (opt, name) = normalize_argv(arg, 2)

        if opt is None or opt.startswith("opt"):
            _show_option(name)
        elif opt.startswith("arg"):
            _show_arg()
        elif opt.startswith("env"):
            _show_env(name)
        else:
            msg("Unknown show option: %s" % opt)
        return
    show.options = ["option", "arg", "env"]

    # set [option | arg | env]
    def set(self, *arg):
        """
        Set various PEDA options and other settings
        Usage:
            MYNAME option name value
            MYNAME arg string
            MYNAME env name value
                support input non-printable chars, e.g MYNAME env EGG "\\x90"*1000
        """
        # set options
        def _set_option(name, value):
            if name in config.Option.options:
                config.Option.set(name, value)
                msg("%s = %s" % (name, repr(value)))
            else:
                msg("Unknown option: %s" % name)
            return

        # set args
        def _set_arg(*arg):
            cmd = "set args"
            for a in arg:
                try:
                    s = eval('%s' % a)
                    if isinstance(s, six.integer_types + six.string_types):
                        a = s
                except:
                    pass
                cmd += " '%s'" % a
            peda.execute(cmd)
            return

        # set env
        def _set_env(name, value):
            env = peda.execute_redirect("show env")
            cmd = "set env %s " % name
            try:
                value = eval('%s' % value)
            except:
                pass
            cmd += '%s' % value
            peda.execute(cmd)

            return

        (opt, name, value) = normalize_argv(arg, 3)
        if opt is None:
            self._missing_argument()

        if opt.startswith("opt"):
            if value is None:
                self._missing_argument()
            _set_option(name, value)
        elif opt.startswith("arg"):
            _set_arg(*arg[1:])
        elif opt.startswith("env"):
            _set_env(name, value)
        else:
            msg("Unknown set option: %s" % known_args.opt)
        return
    set.options = ["option", "arg", "env"]

    def hexprint(self, *arg):
        """
        Display hexified of data in memory
        Usage:
            MYNAME address (display 16 bytes from address)
            MYNAME address count
            MYNAME address /count (display "count" lines, 16-bytes each)
        """
        (address, count) = normalize_argv(arg, 2)
        if address is None:
            self._missing_argument()

        if count is None:
            count = 16

        if not to_int(count) and count.startswith("/"):
            count = to_int(count[1:])
            count = count * 16 if count else None

        bytes_ = peda.dumpmem(address, address+count)
        if bytes_ is None:
            warning_msg("cannot retrieve memory content")
        else:
            hexstr = to_hexstr(bytes_)
            linelen = 16 # display 16-bytes per line
            i = 0
            text = ""
            while hexstr:
                text += '%s : "%s"\n' % (blue(to_address(address+i*linelen)), hexstr[:linelen*4])
                hexstr = hexstr[linelen*4:]
                i += 1
            pager(text)

        return

    def hexdump(self, *arg):
        """
        Display hex/ascii dump of data in memory
        Usage:
            MYNAME address (dump 16 bytes from address)
            MYNAME address count
            MYNAME address /count (dump "count" lines, 16-bytes each)
        """
        def ascii_char(ch):
            if ord(ch) >= 0x20 and ord(ch) < 0x7e:
                return chr(ord(ch))  # Ensure we return a str
            else:
                return "."

        (address, count) = normalize_argv(arg, 2)
        if address is None:
            self._missing_argument()

        if count is None:
            count = 16

        if not to_int(count) and count.startswith("/"):
            count = to_int(count[1:])
            count = count * 16 if count else None

        bytes_ = peda.dumpmem(address, address+count)
        if bytes_ is None:
            warning_msg("cannot retrieve memory content")
        else:
            linelen = 16 # display 16-bytes per line
            i = 0
            text = ""
            while bytes_:
                buf = bytes_[:linelen]
                hexbytes = " ".join(["%02x" % ord(c) for c in bytes_iterator(buf)])
                asciibytes = "".join([ascii_char(c) for c in bytes_iterator(buf)])
                text += '%s : %s  %s\n' % (blue(to_address(address+i*linelen)), hexbytes.ljust(linelen*3), asciibytes)
                bytes_ = bytes_[linelen:]
                i += 1
            pager(text)

        return

    def aslr(self, *arg):
        """
        Show/set ASLR setting of GDB
        Usage:
            MYNAME [on|off]
        """
        (option,) = normalize_argv(arg, 1)
        if option is None:
            out = peda.execute_redirect("show disable-randomization")
            if not out:
                warning_msg("ASLR setting is unknown or not available")
                return

            if "is off" in out:
                msg("ASLR is %s" % green("ON"))
            if "is on" in out:
                msg("ASLR is %s" % red("OFF"))
        else:
            option = option.strip().lower()
            if option in ["on", "off"]:
                peda.execute("set disable-randomization %s" % ("off" if option == "on" else "on"))

        return

    def xprint(self, *arg):
        """
        Extra support to GDB's print command
        Usage:
            MYNAME expression
        """
        text = ""
        exp = " ".join(list(arg))
        m = re.search(".*\[(.*)\]|.*?s:(0x[^ ]*)", exp)
        if m:
            addr = peda.parse_and_eval(m.group(1))
            if to_int(addr):
                text += "[0x%x]: " % to_int(addr)

        out = peda.parse_and_eval(exp)
        if to_int(out):
            chain = peda.examine_mem_reference(to_int(out))
            text += format_reference_chain(chain)
        msg(text)
        return

    def distance(self, *arg):
        """
        Calculate distance between two addresses
        Usage:
            MYNAME address (calculate from current $SP to address)
            MYNAME address1 address2
        """
        (start, end) = normalize_argv(arg, 2)
        if to_int(start) is None or (to_int(end) is None and not self._is_running()):
            self._missing_argument()

        sp = None
        if end is None:
            sp = peda.getreg("sp")
            end = start
            start = sp

        dist = end - start
        text = "From 0x%x%s to 0x%x: " % (start, " (SP)" if start == sp else "",  end)
        text += "%d bytes, %d dwords%s" % (dist, dist//4, " (+%d bytes)" % (dist%4) if (dist%4 != 0) else "")
        msg(text)

        return

    def session(self, *arg):
        """
        Save/restore a working gdb session to file as a script
        Usage:
            MYNAME save [filename]
            MYNAME restore [filename]
        """
        options = ["save", "restore", "autosave"]
        (option, filename) = normalize_argv(arg, 2)
        if option not in options:
            self._missing_argument()

        if not filename:
            filename = peda.get_config_filename("session")

        if option == "save":
            if peda.save_session(filename):
                msg("Saved GDB session to file %s" % filename)
            else:
                msg("Failed to save GDB session")

        if option == "restore":
            if peda.restore_session(filename):
                msg("Restored GDB session from file %s" % filename)
            else:
                msg("Failed to restore GDB session")

        if option == "autosave":
            if config.Option.get("autosave") == "on":
                peda.save_session(filename)

        return
    session.options = ["save", "restore"]

    #################################
    #   Debugging Helper Commands   #
    #################################
    def procinfo(self, *arg):
        """
        Display various info from /proc/pid/
        Usage:
            MYNAME [pid]
        """
        options = ["exe", "fd", "pid", "ppid", "uid", "gid"]

        if peda.getos() != "Linux":
            warning_msg("this command is only available on Linux")

        (pid,) = normalize_argv(arg, 1)

        if not pid:
            pid = peda.getpid()

        if not pid:
            return

        info = {}
        try:
            info["exe"] = os.path.realpath("/proc/%d/exe" % pid)
        except:
            warning_msg("cannot access /proc/%d/" % pid)
            return

        # fd list
        info["fd"] = {}
        fdlist = os.listdir("/proc/%d/fd" % pid)
        for fd in fdlist:
            rpath = os.readlink("/proc/%d/fd/%s" % (pid, fd))
            sock = re.search("socket:\[(.*)\]", rpath)
            if sock:
                spath = execute_external_command("netstat -aen | grep %s" % sock.group(1))
                if spath:
                    rpath = spath.strip()
            info["fd"][to_int(fd)] = rpath

        # uid/gid, pid, ppid
        info["pid"] = pid
        status = open("/proc/%d/status" % pid).read()
        ppid = re.search("PPid:\s*([^\s]*)", status).group(1)
        info["ppid"] = to_int(ppid) if ppid else -1
        uid = re.search("Uid:\s*([^\n]*)", status).group(1)
        info["uid"] = [to_int(id) for id in uid.split()]
        gid = re.search("Gid:\s*([^\n]*)", status).group(1)
        info["gid"] = [to_int(id) for id in gid.split()]

        for opt in options:
            if opt == "fd":
                for (fd, path) in info[opt].items():
                    msg("fd[%d] -> %s" % (fd, path))
            else:
                msg("%s = %s" % (opt, info[opt]))
        return

    # getfile()
    def getfile(self):
        """
        Get exec filename of current debugged process
        Usage:
            MYNAME
        """
        filename = peda.getfile()
        if filename == None:
            msg("No file specified")
        else:
            msg(filename)
        return

    # getpid()
    def getpid(self):
        """
        Get PID of current debugged process
        Usage:
            MYNAME
        """
        pid = self._is_running()
        msg(pid)
        return

    # disassemble()
    def pdisass(self, *arg):
        """
        Format output of gdb disassemble command with colors
        Usage:
            MYNAME "args for gdb disassemble command"
            MYNAME address /NN: equivalent to "x/NNi address"
        """
        (address, fmt_count) = normalize_argv(arg, 2)
        if isinstance(fmt_count, str) and fmt_count.startswith("/"):
            count = to_int(fmt_count[1:])
            if not count or to_int(address) is None:
                self._missing_argument()
            else:
                code = peda.get_disasm(address, count)
        else:
            code = peda.disassemble(*arg)
        msg(format_disasm_code(code))

        return

    # disassemble_around
    def nearpc(self, *arg):
        """
        Disassemble instructions nearby current PC or given address
        Usage:
            MYNAME [count]
            MYNAME address [count]
                count is maximum 256
        """
        (address, count) = normalize_argv(arg, 2)
        address = to_int(address)

        count = to_int(count)
        if address is not None and address < 0x40000:
            count = address
            address = None

        if address is None:
            address = peda.getreg("pc")

        if count is None:
            code = peda.disassemble_around(address)
        else:
            code = peda.disassemble_around(address, count)

        if code:
            msg(format_disasm_code(code, address))
        else:
            error_msg("invalid $pc address or instruction count")
        return

    def waitfor(self, *arg):
        """
        Try to attach to new forked process; mimic "attach -waitfor"
        Usage:
            MYNAME [cmdname]
            MYNAME [cmdname] -c (auto continue after attached)
        """
        (name, opt) = normalize_argv(arg, 2)
        if name == "-c":
            opt = name
            name = None

        if name is None:
            filename = peda.getfile()
            if filename is None:
                warning_msg("please specify the file to debug or process name to attach")
                return
            else:
                name = os.path.basename(filename)

        msg("Trying to attach to new forked process (%s), Ctrl-C to stop..." % name)
        cmd = "ps axo pid,command | grep %s | grep -v grep" % name
        getpids = []
        out = execute_external_command(cmd)
        for line in out.splitlines():
            getpids += [line.split()[0].strip()]

        while True:
            found = 0
            out = execute_external_command(cmd)
            for line in out.splitlines():
                line = line.split()
                pid = line[0].strip()
                cmdname = line[1].strip()
                if name not in cmdname: continue
                if pid not in getpids:
                    found = 1
                    break

            if found == 1:
                msg("Attching to pid: %s, cmdname: %s" % (pid, cmdname))
                if peda.getpid():
                    peda.execute("detach")
                out = peda.execute_redirect("attach %s" % pid)
                msg(out)
                out = peda.execute_redirect("file %s" % cmdname) # reload symbol file
                msg(out)
                if opt == "-c":
                    peda.execute("continue")
                return
            time.sleep(0.5)
        return

    def pltbreak(self, *arg):
        """
        Set breakpoint at PLT functions match name regex
        Usage:
            MYNAME [name]
        """
        (name,) = normalize_argv(arg, 1)
        if not name:
            name = ""
        headers = peda.elfheader()
        end = headers[".bss"]
        symbols = peda.elfsymbol(name)
        if len(symbols) == 0:
            msg("File not specified or PLT symbols not found")
            return
        else:
            # Traverse symbols in order to have more predictable output
            for symname in sorted(symbols):
                if "plt" not in symname: continue
                if name in symname:  # fixme(longld) bounds checking?
                    line = peda.execute_redirect("break %s" % symname)
                    msg("%s (%s)" % (line.strip("\n"), symname))
        return

    def xrefs(self, *arg):
        """
        Search for all call/data access references to a function/variable
        Usage:
            MYNAME pattern
            MYNAME pattern file/mapname
        """
        (search, filename) = normalize_argv(arg, 2)
        if search is None:
            search = "" # search for all call references
        else:
            search = arg[0]

        if filename is not None: # get full path to file if mapname is provided
            vmap = peda.get_vmmap(filename)
            if vmap:
                filename = vmap[0][3]

        result = peda.xrefs(search, filename)
        if result:
            if search != "":
                msg("All references to '%s':" % search)
            else:
                msg("All call references")
            for (addr, code) in result:
                msg("%s" % (code))
        else:
            msg("Not found")
        return

    def deactive(self, *arg):
        """
        Bypass a function by ignoring its execution (eg sleep/alarm)
        Usage:
            MYNAME function
            MYNAME function del (re-active)
        """
        (function, action) = normalize_argv(arg, 2)
        if function is None:
            self._missing_argument()

        if to_int(function):
            function = "0x%x" % function

        bnum = "$deactive_%s_bnum" % function
        if action and "del" in action:
            peda.execute("delete %s" % bnum)
            peda.execute("set %s = \"void\"" % bnum)
            msg("'%s' re-activated" % function)
            return

        if "void" not in peda.execute_redirect("p %s" % bnum):
            out = peda.execute_redirect("info breakpoints %s" % bnum)
            if out:
                msg("Already deactivated '%s'" % function)
                msg(out)
                return
            else:
                peda.execute("set %s = \"void\"" % bnum)

        (arch, bits) = peda.getarch()
        if not function.startswith("0x"): # named function
            symbol = peda.elfsymbol(function)
            if not symbol:
                warning_msg("cannot retrieve info of function '%s'" % function)
                return
            peda.execute("break *0x%x" % symbol[function + "@plt"])

        else: # addressed function
            peda.execute("break *%s" % function)

        peda.execute("set %s = $bpnum" % bnum)
        tmpfd = tmpfile()
        if "i386" in arch:
            tmpfd.write("\n".join([
                "commands $bpnum",
                "silent",
                "set $eax = 0",
                "return",
                "continue",
                "end"]))
        if "64" in arch:
            tmpfd.write("\n".join([
                "commands $bpnum",
                "silent",
                "set $rax = 0",
                "return",
                "continue",
                "end"]))
        tmpfd.flush()
        peda.execute("source %s" % tmpfd.name)
        tmpfd.close()
        out = peda.execute_redirect("info breakpoints %s" % bnum)
        if out:
            msg("'%s' deactivated" % function)
            msg(out)
        return

    def unptrace(self, *arg):
        """
        Disable anti-ptrace detection
        Usage:
            MYNAME
            MYNAME del
        """
        (action,) = normalize_argv(arg, 1)

        self.deactive("ptrace", action)

        if not action and "void" in peda.execute_redirect("p $deactive_ptrace_bnum"):
        # cannot deactive vi plt entry, try syscall method
            msg("Try to patch 'ptrace' via syscall")
            peda.execute("catch syscall ptrace")
            peda.execute("set $deactive_ptrace_bnum = $bpnum")
            tmpfd = tmpfile()
            (arch, bits) = peda.getarch()
            if "i386" in arch:
                tmpfd.write("\n".join([
                    "commands $bpnum",
                    "silent",
                    "if (*(int*)($esp+4) == 0 || $ebx == 0)",
                    "    set $eax = 0",
                    "end",
                    "continue",
                    "end"]))
            if "64" in arch:
                tmpfd.write("\n".join([
                    "commands $bpnum",
                    "silent",
                    "if ($rdi == 0)",
                    "    set $rax = 0",
                    "end",
                    "continue",
                    "end"]))
            tmpfd.flush()
            peda.execute("source %s" % tmpfd.name)
            tmpfd.close()
            out = peda.execute_redirect("info breakpoints $deactive_ptrace_bnum")
            if out:
                msg("'ptrace' deactivated")
                msg(out)
        return

    # get_function_args()
    def dumpargs(self, *arg):
        """
        Display arguments passed to a function when stopped at a call instruction
        Usage:
            MYNAME [count]
                count: force to display "count args" instead of guessing
        """

        (count,) = normalize_argv(arg, 1)
        if not self._is_running():
            return

        args = peda.get_function_args(count)
        if args:
            msg("Guessed arguments:")
            for (i, a) in enumerate(args):
                chain = peda.examine_mem_reference(a)
                msg("arg[%d]: %s" % (i, format_reference_chain(chain)))
        else:
            msg("No argument")

        return

    def xuntil(self, *arg):
        """
        Continue execution until an address or function
        Usage:
            MYNAME address | function
        """
        (address,) = normalize_argv(arg, 1)
        if to_int(address) is None:
            peda.execute("tbreak %s" % address)
        else:
            peda.execute("tbreak *0x%x" % address)
        pc = peda.getreg("pc")
        if pc is None:
            peda.execute("run")
        else:
            peda.execute("continue")
        return

    def goto(self, *arg):
        """
        Continue execution at an address
        Usage:
            MYNAME address
        """
        (address,) = normalize_argv(arg, 1)
        if to_int(address) is None:
            self._missing_argument()

        peda.execute("set $pc = 0x%x" % address)
        peda.execute("stop")
        return

    def skipi(self, *arg):
        """
        Skip execution of next count instructions
        Usage:
            MYNAME [count]
        """
        (count,) = normalize_argv(arg, 1)
        if to_int(count) is None:
            count = 1

        if not self._is_running():
            return

        next_code = peda.next_inst(peda.getreg("pc"), count)
        if not next_code:
            warning_msg("failed to get next instructions")
            return
        last_addr = next_code[-1][0]
        peda.execute("set $pc = 0x%x" % last_addr)
        peda.execute("stop")
        return

    def start(self, *arg):
        """
        Start debugged program and stop at most convenient entry
        Usage:
            MYNAME
        """
        entries = ["main"]
        main_addr = peda.main_entry()
        if main_addr:
            entries += ["*0x%x" % main_addr]
        entries += ["__libc_start_main@plt"]
        entries += ["_start"]
        entries += ["_init"]

        started = 0
        for e in entries:
            out = peda.execute_redirect("tbreak %s" % e)
            if out and "breakpoint" in out:
                peda.execute("run %s" % ' '.join(arg))
                started = 1
                break

        if not started: # try ELF entry point or just "run" as the last resort
            elf_entry = peda.elfentry()
            if elf_entry:
                out = peda.execute_redirect("tbreak *%s" % elf_entry)

            peda.execute("run")

        return

    # stepuntil()
    def stepuntil(self, *arg):
        """
        Step until a desired instruction in specific memory range
        Usage:
            MYNAME "inst1,inst2" (step to next inst in binary)
            MYNAME "inst1,inst2" mapname1,mapname2
        """
        (insts, mapname) = normalize_argv(arg, 2)
        if insts is None:
            self._missing_argument()

        if not self._is_running():
            return

        peda.save_user_command("hook-stop") # disable hook-stop to speedup
        msg("Stepping through, Ctrl-C to stop...")
        result = peda.stepuntil(insts, mapname)
        peda.restore_user_command("hook-stop")

        if result:
            peda.execute("stop")
        return

    # wrapper for stepuntil("call")
    def nextcall(self, *arg):
        """
        Step until next 'call' instruction in specific memory range
        Usage:
            MYNAME [keyword] [mapname1,mapname2]
        """
        (keyword, mapname) = normalize_argv(arg, 2)

        if keyword:
            self.stepuntil("call.*%s" % keyword, mapname)
        else:
            self.stepuntil("call", mapname)
        return

    # wrapper for stepuntil("j")
    def nextjmp(self, *arg):
        """
        Step until next 'j*' instruction in specific memory range
        Usage:
            MYNAME [keyword] [mapname1,mapname2]
        """
        (keyword, mapname) = normalize_argv(arg, 2)

        if keyword:
            self.stepuntil("j.*%s" % keyword, mapname)
        else:
            self.stepuntil("j", mapname)
        return

    #stepuntil()
    def tracecall(self, *arg):
        """
        Trace function calls made by the program
        Usage:
            MYNAME ["func1,func2"] [mapname1,mapname2]
            MYNAME ["-func1,func2"] [mapname1,mapname2] (inverse)
                default is to trace internal calls made by the program
        """
        (funcs, mapname) = normalize_argv(arg, 2)

        if not self._is_running():
            return

        if not mapname:
            mapname = "binary"

        fnames = [""]
        if funcs:
            if to_int(funcs):
                funcs = "0x%x" % funcs
            fnames = funcs.replace(",", " ").split()
        for (idx, fn) in enumerate(fnames):
            if to_int(fn):
                fnames[idx] = "0x%x" % to_int(fn)

        inverse = 0
        for (idx, fn) in enumerate(fnames):
            if fn.startswith("-"): # inverse trace
                fnames[idx] = fn[1:]
                inverse = 1

        binname = peda.getfile()
        logname = peda.get_config_filename("tracelog")

        if mapname is None:
            mapname = binname

        peda.save_user_command("hook-stop") # disable hook-stop to speedup
        msg("Tracing calls %s '%s', Ctrl-C to stop..." % ("match" if not inverse else "not match", ",".join(fnames)))
        prev_depth = peda.backtrace_depth(peda.getreg("sp"))

        logfd = open(logname, "w")
        while True:
            result = peda.stepuntil("call", mapname, prev_depth)
            if result is None:
                break
            (call_depth, code) = result
            prev_depth += call_depth
            if not code.startswith("=>"):
                break

            if not inverse:
                matched = False
                for fn in fnames:
                    fn = fn.strip()
                    if re.search(fn, code.split(":\t")[-1]):
                        matched = True
                        break
            else:
                matched = True
                for fn in fnames:
                    fn = fn.strip()
                    if re.search(fn, code.split(":\t")[-1]):
                        matched = False
                        break

            if matched:
                code = format_disasm_code(code)
                msg("%s%s%s" % (" "*(prev_depth-1), " dep:%02d " % (prev_depth-1), colorize(code.strip())), teefd=logfd)
                args = peda.get_function_args()
                if args:
                    for (i, a) in enumerate(args):
                        chain = peda.examine_mem_reference(a)
                        text = "%s        |-- arg[%d]: %s" % (" "*(prev_depth-1), i, format_reference_chain(chain))
                        msg(text, teefd=logfd)

        msg(code, "red")
        peda.restore_user_command("hook-stop")
        if "STOP" not in peda.get_status():
            peda.execute("stop")
        logfd.close()
        msg("Saved trace information in file %s, view with 'less -r file'" % logname)
        return

    # stepuntil()
    def traceinst(self, *arg):
        """
        Trace specific instructions executed by the program
        Usage:
            MYNAME ["inst1,inst2"] [mapname1,mapname2]
            MYNAME count (trace execution of next count instrcutions)
                default is to trace instructions inside the program
        """
        (insts, mapname) = normalize_argv(arg, 2)

        if not self._is_running():
            return

        if not mapname:
            mapname = "binary"

        instlist = [".*"]
        count = -1
        if insts:
            if to_int(insts):
                count = insts
            else:
                instlist = insts.replace(",", " ").split()

        binname = peda.getfile()
        logname = peda.get_config_filename("tracelog")

        if mapname is None:
            mapname = binname

        peda.save_user_command("hook-stop") # disable hook-stop to speedup
        msg("Tracing instructions match '%s', Ctrl-C to stop..." % (",".join(instlist)))
        prev_depth = peda.backtrace_depth(peda.getreg("sp"))
        logfd = open(logname, "w")

        p = re.compile(".*?:\s*[^ ]*\s*([^,]*),(.*)")
        while count:
            result = peda.stepuntil(",".join(instlist), mapname, prev_depth)
            if result is None:
                break
            (call_depth, code) = result
            prev_depth += call_depth
            if not code.startswith("=>"):
                break

            # special case for JUMP inst
            prev_code = ""
            if re.search("j[^m]", code.split(":\t")[-1].split()[0]):
                prev_insts = peda.prev_inst(peda.getreg("pc"))
                if prev_insts:
                    prev_code = "0x%x:%s" % prev_insts[0]
                    msg("%s%s%s" % (" "*(prev_depth-1), " dep:%02d    " % (prev_depth-1), prev_code), teefd=logfd)

            text = "%s%s%s" % (" "*(prev_depth-1), " dep:%02d " % (prev_depth-1), code.strip())
            msg(text, teefd=logfd)

            if re.search("call", code.split(":\t")[-1].split()[0]):
                args = peda.get_function_args()
                if args:
                    for (i, a) in enumerate(args):
                        chain = peda.examine_mem_reference(a)
                        text = "%s        |-- arg[%d]: %s" % (" "*(prev_depth-1), i, format_reference_chain(chain))
                        msg(text, teefd=logfd)

            # get registers info if any
            (arch, bits) = peda.getarch()
            code = code.split("#")[0].strip("=>")
            if prev_code:
                m = p.search(prev_code)
            else:
                m = p.search(code)

            if m:
                for op in m.groups():
                    if op.startswith("0x"): continue
                    v = to_int(peda.parse_and_eval(op))
                    chain = peda.examine_mem_reference(v)
                    text = "%s        |-- %03s: %s" % (" "*(prev_depth-1), op, format_reference_chain(chain))
                    msg(text, teefd=logfd)

            count -= 1

        msg(code, "red")
        peda.restore_user_command("hook-stop")
        logfd.close()
        msg("Saved trace information in file %s, view with 'less -r file'" % logname)
        return

    def profile(self, *arg):
        """
        Simple profiling to count executed instructions in the program
        Usage:
            MYNAME count [keyword]
                default is to count instructions inside the program only
                count = 0: run until end of execution
                keyword: only display stats for instructions matched it
        """
        (count, keyword) = normalize_argv(arg, 2)

        if count is None:
            self._missing_argument()

        if not self._is_running():
            return

        if keyword is None or keyword == "all":
            keyword = ""

        keyword = keyword.replace(" ", "").split(",")

        peda.save_user_command("hook-stop") # disable hook-stop to speedup
        msg("Stepping %s instructions, Ctrl-C to stop..." % ("%d" % count if count else "all"))

        if count == 0:
            count = -1
        stats = {}
        total = 0
        binmap = peda.get_vmmap("binary")
        try:
            while count != 0:
                pc = peda.getreg("pc")
                if not peda.is_address(pc):
                    break
                code = peda.get_disasm(pc)
                if not code:
                    break
                if peda.is_address(pc, binmap):
                    for k in keyword:
                        if k in code.split(":\t")[-1]:
                            code = code.strip("=>").strip()
                            stats.setdefault(code, 0)
                            stats[code] += 1
                            break
                    peda.execute_redirect("stepi", silent=True)
                else:
                    peda.execute_redirect("stepi", silent=True)
                    peda.execute_redirect("finish", silent=True)
                count -= 1
                total += 1
        except:
            pass

        peda.restore_user_command("hook-stop")
        text = "Executed %d instructions\n" % total
        text += "%s %s\n" % (blue("Run-count", "bold"), blue("Instruction", "bold"))
        for (code, count) in sorted(stats.items(), key = lambda x: x[1], reverse=True):
            text += "%8d: %s\n" % (count, code)
        pager(text)

        return

    @msg.bufferize
    def context_register(self, *arg):
        """
        Display register information of current execution context
        Usage:
            MYNAME
        """
        if not self._is_running():
            return

        pc = peda.getreg("pc")
        # display register info
        msg("[%s]" % "registers".center(78, "-"), "blue")
        self.xinfo("register")

        return

    @msg.bufferize
    def context_code(self, *arg):
        """
        Display nearby disassembly at $PC of current execution context
        Usage:
            MYNAME [linecount]
        """
        (count,) = normalize_argv(arg, 1)

        if count is None:
            count = 8

        if not self._is_running():
            return

        pc = peda.getreg("pc")
        if peda.is_address(pc):
            inst = peda.get_disasm(pc)
        else:
            inst = None

        text = blue("[%s]" % "code".center(78, "-"))
        msg(text)
        if inst: # valid $PC
            text = ""
            opcode = inst.split(":\t")[-1].split()[0]
            # stopped at function call
            if "call" in opcode:
                text += peda.disassemble_around(pc, count)
                msg(format_disasm_code(text, pc))
                self.dumpargs()
            # stopped at jump
            elif "j" in opcode:
                jumpto = peda.testjump(inst)
                if jumpto: # JUMP is taken
                    code = peda.disassemble_around(pc, count)
                    code = code.splitlines()
                    pc_idx = 999
                    for (idx, line) in enumerate(code):
                        if ("0x%x" % pc) in line.split(":")[0]:
                            pc_idx = idx
                        if idx <= pc_idx:
                            text += line + "\n"
                        else:
                            text += " | %s\n" % line.strip()
                    text = format_disasm_code(text, pc) + "\n"
                    text += " |->"
                    code = peda.get_disasm(jumpto, count//2)
                    if not code:
                        code = "   Cannot evaluate jump destination\n"

                    code = code.splitlines()
                    text += red(code[0]) + "\n"
                    for line in code[1:]:
                        text += "       %s\n" % line.strip()
                    text += red("JUMP is taken".rjust(79))
                else: # JUMP is NOT taken
                    text += format_disasm_code(peda.disassemble_around(pc, count), pc)
                    text += "\n" + green("JUMP is NOT taken".rjust(79))

                msg(text.rstrip())
            # stopped at other instructions
            else:
                text += peda.disassemble_around(pc, count)
                msg(format_disasm_code(text, pc))
        else: # invalid $PC
            msg("Invalid $PC address: 0x%x" % pc, "red")

        return

    @msg.bufferize
    def context_stack(self, *arg):
        """
        Display stack of current execution context
        Usage:
            MYNAME [linecount]
        """
        (count,) = normalize_argv(arg, 1)

        if not self._is_running():
            return

        text = blue("[%s]" % "stack".center(78, "-"))
        msg(text)
        sp = peda.getreg("sp")
        if peda.is_address(sp):
            self.telescope(sp, count)
        else:
            msg("Invalid $SP address: 0x%x" % sp, "red")

        return

    def context(self, *arg):
        """
        Display various information of current execution context
        Usage:
            MYNAME [reg,code,stack,all] [code/stack length]
        """

        (opt, count) = normalize_argv(arg, 2)

        if to_int(count) is None:
            count = 8
        if opt is None:
            opt = config.Option.get("context")
        if opt == "all":
            opt = "register,code,stack"

        opt = opt.replace(" ", "").split(",")

        if not opt:
            return

        if not self._is_running():
            return

        clearscr = config.Option.get("clearscr")
        if clearscr == "on":
            clearscreen()

        status = peda.get_status()
        # display registers
        if "reg" in opt or "register" in opt:
            self.context_register()

        # display assembly code
        if "code" in opt:
            self.context_code(count)

        # display stack content, forced in case SIGSEGV
        if "stack" in opt or "SIGSEGV" in status:
            self.context_stack(count)
        msg("[%s]" % ("-"*78), "blue")
        msg("Legend: %s, %s, %s, value" % (red("code"), blue("data"), green("rodata")))

        # display stopped reason
        if "SIG" in status:
            msg("Stopped reason: %s" % red(status))

        return

    def breakrva(self, *arg):
        """
        Set breakpoint by Relative Virtual Address (RVA)
        Usage:
            MYNAME rva
            MYNAME rva module_name (e.g binary, shared module name)
        """
        (rva, module) = normalize_argv(arg, 2)
        if rva is None or not to_int(rva):
            self._missing_argument()
        if module is None:
            module = 'binary'

        binmap = peda.get_vmmap(module)
        if len(binmap) == 0:
            msg("No module matches '%s'" % module)
        else:
            base_address = binmap[0][0]
            peda.set_breakpoint(base_address+rva)
        return

    #################################
    #   Memory Operation Commands   #
    #################################
    # get_vmmap()
    def vmmap(self, *arg):
        """
        Get virtual mapping address ranges of section(s) in debugged process
        Usage:
            MYNAME [mapname] (e.g binary, all, libc, stack)
            MYNAME address (find mapname contains this address)
            MYNAME (equiv to cat /proc/pid/maps)
        """

        (mapname,) = normalize_argv(arg, 1)
        if not self._is_running():
            maps = peda.get_vmmap()
        elif to_int(mapname) is None:
            maps = peda.get_vmmap(mapname)
        else:
            addr = to_int(mapname)
            maps = []
            allmaps = peda.get_vmmap()
            if allmaps is not None:
                for (start, end, perm, name) in allmaps:
                    if addr >= start and addr < end:
                        maps += [(start, end, perm, name)]

        if maps is not None and len(maps) > 0:
            l = 10 if peda.intsize() == 4 else 18
            msg("%s %s %s\t%s" % ("Start".ljust(l, " "), "End".ljust(l, " "), "Perm", "Name"), "blue", "bold")
            for (start, end, perm, name) in maps:
                color = "red" if "rwx" in perm else None
                msg("%s %s %s\t%s" % (to_address(start).ljust(l, " "), to_address(end).ljust(l, " "), perm, name), color)
        else:
            warning_msg("not found or cannot access procfs")
        return

    # writemem()
    def patch(self, *arg):
        """
        Patch memory start at an address with string/hexstring/int
        Usage:
            MYNAME address (multiple lines input)
            MYNAME address "string"
            MYNAME from_address to_address "string"
            MYNAME (will patch at current $pc)
        """

        (address, data, byte) = normalize_argv(arg, 3)
        address = to_int(address)
        end_address = None
        if address is None:
            address = peda.getreg("pc")

        if byte is not None and to_int(data) is not None:
            end_address, data = to_int(data), byte
            if end_address < address:
                address, end_address = end_address, address

        if data is None:
            data = ""
            while True:
                line = input("patch> ")
                if line.strip() == "": continue
                if line == "end":
                    break
                user_input = line.strip()
                if user_input.startswith("0x"):
                    data += hex2str(user_input)
                else:
                    data += eval("%s" % user_input)

        if to_int(data) is not None:
            data = hex2str(to_int(data), peda.intsize())

        data = to_binary_string(data)
        data = data.replace(b"\\\\", b"\\")
        if end_address:
            data *= (end_address-address + 1) // len(data)
        bytes_ = peda.writemem(address, data)
        if bytes_ >= 0:
            msg("Written %d bytes to 0x%x" % (bytes_, address))
        else:
            warning_msg("Failed to patch memory, try 'set write on' first for offline patching")
        return

    # dumpmem()
    def dumpmem(self, *arg):
        """
        Dump content of a memory region to raw binary file
        Usage:
            MYNAME file start end
            MYNAME file mapname
        """
        (filename, start, end) = normalize_argv(arg, 3)
        if end is not None and to_int(end):
            if end < start:
                start, end = end, start
            ret = peda.execute("dump memory %s 0x%x 0x%x" % (filename, start, end))
            if not ret:
                warning_msg("failed to dump memory")
            else:
                msg("Dumped %d bytes to '%s'" % (end-start, filename))
        elif start is not None: # dump by mapname
            maps = peda.get_vmmap(start)
            if maps:
                fd = open(filename, "wb")
                count = 0
                for (start, end, _, _) in maps:
                    mem = peda.dumpmem(start, end)
                    if mem is None: # nullify unreadable memory
                        mem = "\x00"*(end-start)
                    fd.write(mem)
                    count += end - start
                fd.close()
                msg("Dumped %d bytes to '%s'" % (count, filename))
            else:
                warning_msg("invalid mapname")
        else:
            self._missing_argument()

        return

    # loadmem()
    def loadmem(self, *arg):
        """
        Load contents of a raw binary file to memory
        Usage:
            MYNAME file address [size]
        """
        mem = ""
        (filename, address, size) = normalize_argv(arg, 3)
        address = to_int(address)
        size = to_int(size)
        if filename is not None:
            try:
                mem = open(filename, "rb").read()
            except:
                pass
            if mem == "":
                error_msg("cannot read data or filename is empty")
                return
            if size is not None and size < len(mem):
                mem = mem[:size]
            bytes = peda.writemem(address, mem)
            if bytes > 0:
                msg("Written %d bytes to 0x%x" % (bytes, address))
            else:
                warning_msg("failed to load filename to memory")
        else:
            self._missing_argument()
        return

    # cmpmem()
    def cmpmem(self, *arg):
        """
        Compare content of a memory region with a file
        Usage:
            MYNAME start end file
        """
        (start, end, filename) = normalize_argv(arg, 3)
        if filename is None:
            self._missing_argument()

        try:
            buf = open(filename, "rb").read()
        except:
            error_msg("cannot read data from filename %s" % filename)
            return

        result = peda.cmpmem(start, end, buf)

        if result is None:
            warning_msg("failed to perform comparison")
        elif result == {}:
            msg("mem and filename are identical")
        else:
            msg("--- mem: %s -> %s" % (arg[0], arg[1]), "green", "bold")
            msg("+++ filename: %s" % arg[2], "blue", "bold")
            for (addr, bytes_) in result.items():
                msg("@@ 0x%x @@" % addr, "red")
                line_1 = "- "
                line_2 = "+ "
                for (mem_val, file_val) in bytes_:
                    m_byte = "%02X " % ord(mem_val)
                    f_byte = "%02X " % ord(file_val)
                    if mem_val == file_val:
                        line_1 += m_byte
                        line_2 += f_byte
                    else:
                        line_1 += green(m_byte)
                        line_2 += blue(f_byte)
                msg(line_1)
                msg(line_2)
        return

    # xormem()
    def xormem(self, *arg):
        """
        XOR a memory region with a key
        Usage:
            MYNAME start end key
        """
        (start, end, key) = normalize_argv(arg, 3)
        if key is None:
            self._missing_argument()

        result = peda.xormem(start, end, key)
        if result is not None:
            msg("XORed data (first 32 bytes):")
            msg('"' + to_hexstr(result[:32]) + '"')
        return

    # searchmem(), searchmem_by_range()
    def searchmem(self, *arg):
        """
        Search for a pattern in memory; support regex search
        Usage:
            MYNAME pattern start end
            MYNAME pattern mapname
        """
        (pattern, start, end) = normalize_argv(arg, 3)
        (pattern, mapname) = normalize_argv(arg, 2)
        if pattern is None:
            self._missing_argument()

        pattern = arg[0]
        result = []
        if end is None and to_int(mapname):
            vmrange = peda.get_vmrange(mapname)
            if vmrange:
                (start, end, _, _) = vmrange

        if end is None:
            msg("Searching for %s in: %s ranges" % (repr(pattern), mapname))
            result = peda.searchmem_by_range(mapname, pattern)
        else:
            msg("Searching for %s in range: 0x%x - 0x%x" % (repr(pattern), start, end))
            result = peda.searchmem(start, end, pattern)

        text = peda.format_search_result(result)
        pager(text)

        return

    # search_reference()
    def refsearch(self, *arg):
        """
        Search for all references to a value in memory ranges
        Usage:
            MYNAME value mapname
            MYNAME value (search in all memory ranges)
        """
        (search, mapname) = normalize_argv(arg, 2)
        if search is None:
            self._missing_argument()

        search = arg[0]
        if mapname is None:
            mapname = "all"
        msg("Searching for reference to: %s in: %s ranges" % (repr(search), mapname))
        result = peda.search_reference(search, mapname)

        text = peda.format_search_result(result)
        pager(text)

        return

    # search_address(), search_pointer()
    def lookup(self, *arg):
        """
        Search for all addresses/references to addresses which belong to a memory range
        Usage:
            MYNAME address searchfor belongto
            MYNAME pointer searchfor belongto
        """
        (option, searchfor, belongto) = normalize_argv(arg, 3)
        if option is None:
            self._missing_argument()

        result = []
        if searchfor is None:
            searchfor = "stack"
        if belongto is None:
            belongto = "binary"

        if option == "pointer":
            msg("Searching for pointers on: %s pointed to: %s, this may take minutes to complete..." % (searchfor, belongto))
            result = peda.search_pointer(searchfor, belongto)
        if option == "address":
            msg("Searching for addresses on: %s belong to: %s, this may take minutes to complete..." % (searchfor, belongto))
            result = peda.search_address(searchfor, belongto)

        text = peda.format_search_result(result, 0)
        pager(text)

        return
    lookup.options = ["address", "pointer"]

    # examine_mem_reference()
    def telescope(self, *arg):
        """
        Display memory content at an address with smart dereferences
        Usage:
            MYNAME [linecount] (analyze at current $SP)
            MYNAME address [linecount]
        """

        (address, count) = normalize_argv(arg, 2)

        if self._is_running():
            sp = peda.getreg("sp")
        else:
            sp = None

        if count is None:
            count = 8
            if address is None:
                address = sp
            elif address < 0x1000:
                count = address
                address = sp

        if not address:
            return

        step = peda.intsize()
        if not peda.is_address(address): # cannot determine address
            msg("Invalid $SP address: 0x%x" % address, "red")
            return
            for i in range(count):
                if not peda.execute("x/%sx 0x%x" % ("g" if step == 8 else "w", address + i*step)):
                    break
            return

        result = []
        for i in range(count):
            value = address + i*step
            if peda.is_address(value):
                result += [peda.examine_mem_reference(value)]
            else:
                result += [None]
        idx = 0
        text = ""
        for chain in result:
            text += "%04d| " % (idx)
            text += format_reference_chain(chain)
            text += "\n"
            idx += step

        pager(text)

        return

    def eflags(self, *arg):
        """
        Display/set/clear/toggle value of eflags register
        Usage:
            MYNAME
            MYNAME [set|clear|toggle] flagname
        """
        FLAGS = ["CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"]
        FLAGS_TEXT = ["Carry", "Parity", "Adjust", "Zero", "Sign", "Trap",
                        "Interrupt", "Direction", "Overflow"]

        (option, flagname) = normalize_argv(arg, 2)
        if not self._is_running():
            return

        elif option and not flagname:
            self._missing_argument()

        elif option is None: # display eflags
            flags = peda.get_eflags()
            text = ""
            for (i, f) in enumerate(FLAGS):
                if flags[f]:
                    text += "%s " % red(FLAGS_TEXT[i].upper(), "bold")
                else:
                    text += "%s " % green(FLAGS_TEXT[i].lower())

            eflags = peda.getreg("eflags")
            msg("%s: 0x%x (%s)" % (green("EFLAGS"), eflags, text.strip()))

        elif option == "set":
            peda.set_eflags(flagname, True)

        elif option == "clear":
            peda.set_eflags(flagname, False)

        elif option == "toggle":
            peda.set_eflags(flagname, None)

        return
    eflags.options = ["set", "clear", "toggle"]

    def xinfo(self, *arg):
        """
        Display detail information of address/registers
        Usage:
            MYNAME address
            MYNAME register [reg1 reg2]
        """

        (address, regname) = normalize_argv(arg, 2)
        if address is None:
            self._missing_argument()

        text = ""
        if not self._is_running():
            return

        def get_reg_text(r, v):
            text = green("%s" % r.upper().ljust(3)) + ": "
            chain = peda.examine_mem_reference(v)
            text += format_reference_chain(chain)
            text += "\n"
            return text

        (arch, bits) = peda.getarch()
        if str(address).startswith("r"):
            # Register
            regs = peda.getregs(" ".join(arg[1:]))
            if regname is None:
                for r in REGISTERS[bits]:
                    if r in regs:
                        text += get_reg_text(r, regs[r])
            else:
                for (r, v) in sorted(regs.items()):
                    text += get_reg_text(r, v)
            if text:
                msg(text.strip())
            if regname is None or "eflags" in regname:
                self.eflags()
            return

        elif to_int(address) is None:
            warning_msg("not a register nor an address")
        else:
            # Address
            chain = peda.examine_mem_reference(address, depth=0)
            text += format_reference_chain(chain) + "\n"
            vmrange = peda.get_vmrange(address)
            if vmrange:
                (start, end, perm, name) = vmrange
                text += "Virtual memory mapping:\n"
                text += green("Start : %s\n" % to_address(start))
                text += green("End   : %s\n" % to_address(end))
                text += yellow("Offset: 0x%x\n" % (address-start))
                text += red("Perm  : %s\n" % perm)
                text += blue("Name  : %s" % name)
        msg(text)

        return
    xinfo.options = ["register"]

    def strings(self, *arg):
        """
        Display printable strings in memory
        Usage:
            MYNAME start end [minlen]
            MYNAME mapname [minlen]
            MYNAME (display all printable strings in binary - slow)
        """
        (start, end, minlen) = normalize_argv(arg, 3)

        mapname = None
        if start is None:
            mapname = "binary"
        elif to_int(start) is None or (end < start):
            (mapname, minlen) = normalize_argv(arg, 2)

        if minlen is None:
            minlen = 1

        if mapname:
            maps = peda.get_vmmap(mapname)
        else:
            maps = [(start, end, None, None)]

        if not maps:
            warning_msg("failed to get memory map for %s" % mapname)
            return

        text = ""
        regex_pattern = "[%s]{%d,}" % (re.escape(string.printable), minlen)
        p = re.compile(regex_pattern.encode('utf-8'))
        for (start, end, _, _) in maps:
            mem = peda.dumpmem(start, end)
            if not mem: continue
            found = p.finditer(mem)
            if not found: continue

            for m in found:
                text += "0x%x: %s\n" % (start+m.start(), string_repr(mem[m.start():m.end()].strip(), show_quotes=False))

        pager(text)
        return

    def sgrep(self, *arg):
        """
        Search for full strings contain the given pattern
        Usage:
            MYNAME pattern start end
            MYNAME pattern mapname
            MYNAME pattern
        """
        (pattern,) = normalize_argv(arg, 1)

        if pattern is None:
            self._missing_argument()
        arg = list(arg[1:])
        if not arg:
            arg = ["binary"]

        pattern = "[^\x00]*%s[^\x00]*" % pattern
        self.searchmem(pattern, *arg)

        return


    ###############################
    #   Exploit Helper Commands   #
    ###############################
    # elfheader()
    def elfheader(self, *arg):
        """
        Get headers information from debugged ELF file
        Usage:
            MYNAME [header_name]
        """

        (name,) = normalize_argv(arg, 1)
        result = peda.elfheader(name)
        if len(result) == 0:
            warning_msg("%s not found, did you specify the FILE to debug?" % (name if name else "headers"))
        elif len(result) == 1:
            (k, (start, end, type)) = list(result.items())[0]
            msg("%s: 0x%x - 0x%x (%s)" % (k, start, end, type))
        else:
            for (k, (start, end, type)) in sorted(result.items(), key=lambda x: x[1]):
                msg("%s = 0x%x" % (k, start))
        return

    # readelf_header(), elfheader_solib()
    def readelf(self, *arg):
        """
        Get headers information from an ELF file
        Usage:
            MYNAME mapname [header_name]
            MYNAME filename [header_name]
        """

        (filename, hname) = normalize_argv(arg, 2)
        result = {}
        maps = peda.get_vmmap()
        if filename is None: # fallback to elfheader()
            result = peda.elfheader()
        else:
            result = peda.elfheader_solib(filename, hname)

        if not result:
            result = peda.readelf_header(filename, hname)
        if len(result) == 0:
            warning_msg("%s or %s not found" % (filename, hname))
        elif len(result) == 1:
            (k, (start, end, type)) = list(result.items())[0]
            msg("%s: 0x%x - 0x%x (%s)" % (k, start, end, type))
        else:
            for (k, (start, end, type)) in sorted(result.items(), key=lambda x: x[1]):
                msg("%s = 0x%x" % (k, start))
        return

    # elfsymbol()
    def elfsymbol(self, *arg):
        """
        Get non-debugging symbol information from an ELF file
        Usage:
            MYNAME symbol_name
        """
        (name,) = normalize_argv(arg, 1)
        if not peda.getfile():
            warning_msg("please specify a file to debug")
            return

        result = peda.elfsymbol(name)
        if len(result) == 0:
            msg("'%s': no match found" % (name if name else "plt symbols"))
        else:
            if ("%s@got" % name) not in result:
                msg("Found %d symbols" % len(result))
            else:
                msg("Detail symbol info")
            for (k, v) in sorted(result.items(), key=lambda x: x[1]):
                msg("%s = %s" % (k, "0x%x" % v if v else repr(v)))
        return

    # checksec()
    def checksec(self, *arg):
        """
        Check for various security options of binary
        For full features, use http://www.trapkit.de/tools/checksec.sh
        Usage:
            MYNAME [file]
        """
        (filename,) = normalize_argv(arg, 1)
        colorcodes = {
            0: red("disabled"),
            1: green("ENABLED"),
            2: yellow("Partial"),
            3: green("FULL"),
            4: yellow("Dynamic Shared Object"),
        }

        result = peda.checksec(filename)
        if result:
            for (k, v) in sorted(result.items()):
                msg("%s: %s" % (k.ljust(10), colorcodes[v]))
        return

    def nxtest(self, *arg):
        """
        Perform real NX test to see if it is enabled/supported by OS
        Usage:
            MYNAME [address]
        """
        (address,) = normalize_argv(arg, 1)

        exec_wrapper = peda.execute_redirect("show exec-wrapper").split('"')[1]
        if exec_wrapper != "":
            peda.execute("unset exec-wrapper")

        if not peda.getpid(): # start program if not running
            peda.execute("start")

        # set current PC => address, continue
        pc = peda.getreg("pc")
        sp = peda.getreg("sp")
        if not address:
            address = sp
        peda.execute("set $pc = 0x%x" % address)
        # set value at address => 0xcc
        peda.execute("set *0x%x = 0x%x" % (address, 0xcccccccc))
        peda.execute("set *0x%x = 0x%x" % (address+4, 0xcccccccc))
        out = peda.execute_redirect("continue")
        text = "NX test at %s: " % (to_address(address) if address != sp else "stack")

        if out:
            if "SIGSEGV" in out:
                text += red("Non-Executable")
            elif "SIGTRAP" in out:
                text += green("Executable")
        else:
            text += "Failed to test"

        msg(text)
        # restore exec-wrapper
        if exec_wrapper != "":
            peda.execute("set exec-wrapper %s" % exec_wrapper)

        return

    # search_asm()
    def asmsearch(self, *arg):
        """
        Search for ASM instructions in memory
        Usage:
            MYNAME "asmcode" start end
            MYNAME "asmcode" mapname
        """
        (asmcode, start, end) = normalize_argv(arg, 3)
        if asmcode is None:
            self._missing_argument()

        if not self._is_running():
            return

        asmcode = arg[0]
        result = []
        if end is None:
            mapname = start
            if mapname is None:
                mapname = "binary"
            maps = peda.get_vmmap(mapname)
            msg("Searching for ASM code: %s in: %s ranges" % (repr(asmcode), mapname))
            for (start, end, _, _) in maps:
                if not peda.is_executable(start, maps): continue # skip non-executable page
                result += peda.search_asm(start, end, asmcode)
        else:
            msg("Searching for ASM code: %s in range: 0x%x - 0x%x" % (repr(asmcode), start, end))
            result = peda.search_asm(start, end, asmcode)

        text = "Not found"
        if result:
            text = ""
            for (addr, (byte, code)) in result:
                text += "%s : (%s)\t%s\n" % (to_address(addr), byte.decode('utf-8'), code)
        pager(text)

        return

    # search_asm()
    def ropsearch(self, *arg):
        """
        Search for ROP gadgets in memory
            Note: only for simple gadgets, for full ROP search try: http://ropshell.com
        Usage:
            MYNAME "gadget" start end
            MYNAME "gadget" pagename
        """

        (asmcode, start, end) = normalize_argv(arg, 3)
        if asmcode is None:
            self._missing_argument()

        if not self._is_running():
            return

        asmcode = arg[0]
        result = []
        if end is None:
            if start is None:
                mapname = "binary"
            else:
                mapname = start
            maps = peda.get_vmmap(mapname)
            msg("Searching for ROP gadget: %s in: %s ranges" % (repr(asmcode), mapname))
            for (start, end, _, _) in maps:
                if not peda.is_executable(start, maps): continue # skip non-executable page
                result += peda.search_asm(start, end, asmcode, rop=1)
        else:
            msg("Searching for ROP gadget: %s in range: 0x%x - 0x%x" % (repr(asmcode), start, end))
            result = peda.search_asm(start, end, asmcode, rop=1)

        result = sorted(result, key=lambda x: len(x[1][0]))
        text = "Not found"
        if result:
            text = ""
            for (addr, (byte, code)) in result:
                text += "%s : (%s)\t%s\n" % (to_address(addr), byte, code)
        pager(text)

        return

    # dumprop()
    def dumprop(self, *arg):
        """
        Dump all ROP gadgets in specific memory range
            Note: only for simple gadgets, for full ROP search try: http://ropshell.com
            Warning: this can be very slow, do not run for big memory range
        Usage:
            MYNAME start end [keyword] [depth]
            MYNAME mapname [keyword]
                default gadget instruction depth is: 5
        """

        (start, end, keyword, depth) = normalize_argv(arg, 4)
        filename = peda.getfile()
        if filename is None:
            warning_msg("please specify a filename to debug")
            return

        filename = os.path.basename(filename)
        mapname = None
        if start is None:
            mapname = "binary"
        elif end is None:
            mapname = start
        elif to_int(end) is None:
            mapname = start
            keyword = end

        if depth is None:
            depth = 5

        result = {}
        warning_msg("this can be very slow, do not run for large memory range")
        if mapname:
            maps = peda.get_vmmap(mapname)
            for (start, end, _, _) in maps:
                if not peda.is_executable(start, maps): continue # skip non-executable page
                result.update(peda.dumprop(start, end, keyword))
        else:
            result.update(peda.dumprop(start, end, keyword))

        text = "Not found"
        if len(result) > 0:
            text = ""
            outfile = "%s-rop.txt" % filename
            fd = open(outfile, "w")
            msg("Writing ROP gadgets to file: %s ..." % outfile)
            for (code, addr) in sorted(result.items(), key = lambda x:len(x[0])):
                text += "0x%x: %s\n" % (addr, code)
                fd.write("0x%x: %s\n" % (addr, code))
            fd.close()

        pager(text)
        return

    # common_rop_gadget()
    def ropgadget(self, *arg):
        """
        Get common ROP gadgets of binary or library
        Usage:
            MYNAME [mapname]
        """

        (mapname,) = normalize_argv(arg, 1)
        result = peda.common_rop_gadget(mapname)
        if not result:
            msg("Not found")
        else:
            text = ""
            for (k, v) in sorted(result.items(), key=lambda x: len(x[0]) if not x[0].startswith("add") else int(x[0].split("_")[1])):
                text += "%s = 0x%x\n" % (k, v)
            pager(text)

        return

    # search_jmpcall()
    def jmpcall(self, *arg):
        """
        Search for JMP/CALL instructions in memory
        Usage:
            MYNAME (search all JMP/CALL in current binary)
            MYNAME reg [mapname]
            MYNAME reg start end
        """

        (reg, start, end) = normalize_argv(arg, 3)
        result = []
        if not self._is_running():
            return

        mapname = None
        if start is None:
            mapname = "binary"
        elif end is None:
            mapname = start

        if mapname:
            maps = peda.get_vmmap(mapname)
            for (start, end, _, _) in maps:
                if not peda.is_executable(start, maps): continue
                result += peda.search_jmpcall(start, end, reg)
        else:
            result = peda.search_jmpcall(start, end, reg)

        if not result:
            msg("Not found")
        else:
            text = ""
            for (a, v) in result:
                text += "0x%x : %s\n" % (a, v)
            pager(text)

        return

    # cyclic_pattern()
    def pattern_create(self, *arg):
        """
        Generate a cyclic pattern
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME size [file]
        """

        (size, filename) = normalize_argv(arg, 2)
        if size is None:
            self._missing_argument()

        pattern = cyclic_pattern(size)
        if filename is not None:
            open(filename, "wb").write(pattern)
            msg("Writing pattern of %d chars to filename \"%s\"" % (len(pattern), filename))
        else:
            msg("'" + pattern.decode('utf-8') + "'")

        return

    # cyclic_pattern()
    def pattern_offset(self, *arg):
        """
        Search for offset of a value in cyclic pattern
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME value
        """

        (value,) = normalize_argv(arg, 1)
        if value is None:
            self._missing_argument()

        pos = cyclic_pattern_offset(value)
        if pos is None:
            msg("%s not found in pattern buffer" % value)
        else:
            msg("%s found at offset: %d" % (value, pos))

        return

    # cyclic_pattern(), searchmem_*()
    def pattern_search(self, *arg):
        """
        Search a cyclic pattern in registers and memory
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME
        """
        def nearby_offset(v):
            for offset in range(-128, 128, 4):
                pos = cyclic_pattern_offset(v + offset)
                if pos is not None:
                    return (pos, offset)
            return None

        if not self._is_running():
            return

        reg_result = {}
        regs = peda.getregs()

        # search for registers with value in pattern buffer
        for (r, v) in regs.items():
            if len(to_hex(v)) < 8: continue
            res = nearby_offset(v)
            if res:
                reg_result[r] = res

        if reg_result:
            msg("Registers contain pattern buffer:", "red")
            for (r, (p, o)) in reg_result.items():
                msg("%s+%d found at offset: %d" % (r.upper(), o, p))
        else:
            msg("No register contains pattern buffer")

        # search for registers which point to pattern buffer
        reg_result = {}
        for (r, v) in regs.items():
            if not peda.is_address(v): continue
            chain = peda.examine_mem_reference(v)
            (v, t, vn) = chain[-1]
            if not vn: continue
            o = cyclic_pattern_offset(vn.strip("'").strip('"')[:4])
            if o is not None:
                reg_result[r] = (len(chain), len(vn)-2, o)

        if reg_result:
            msg("Registers point to pattern buffer:", "yellow")
            for (r, (d, l, o)) in reg_result.items():
                msg("[%s] %s offset %d - size ~%d" % (r.upper(), "-->"*d, o, l))
        else:
            msg("No register points to pattern buffer")

        # search for pattern buffer in memory
        maps = peda.get_vmmap()
        search_result = []
        for (start, end, perm, name) in maps:
            if "w" not in perm: continue # only search in writable memory
            res = cyclic_pattern_search(peda.dumpmem(start, end))
            for (a, l, o) in res:
                a += start
                search_result += [(a, l, o)]

        sp = peda.getreg("sp")
        if search_result:
            msg("Pattern buffer found at:", "green")
            for (a, l, o) in search_result:
                ranges = peda.get_vmrange(a)
                text = "%s : offset %4d - size %4d" % (to_address(a), o, l)
                if ranges[3] == "[stack]":
                    text += " ($sp + %s [%d dwords])" % (to_hex(a-sp), (a-sp)//4)
                else:
                    text += " (%s)" % ranges[3]
                msg(text)
        else:
            msg("Pattern buffer not found in memory")

        # search for references to pattern buffer in memory
        ref_result = []
        for (a, l, o) in search_result:
            res = peda.searchmem_by_range("all", "0x%x" % a)
            ref_result += [(x[0], a) for x in res]
        if len(ref_result) > 0:
            msg("References to pattern buffer found at:", "blue")
            for (a, v) in ref_result:
                ranges = peda.get_vmrange(a)
                text = "%s : %s" % (to_address(a), to_address(v))
                if ranges[3] == "[stack]":
                    text += " ($sp + %s [%d dwords])" % (to_hex(a-sp), (a-sp)//4)
                else:
                    text += " (%s)" % ranges[3]
                msg(text)
        else:
            msg("Reference to pattern buffer not found in memory")

        return

    # cyclic_pattern(), writemem()
    def pattern_patch(self, *arg):
        """
        Write a cyclic pattern to memory
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME address size
        """

        (address, size) = normalize_argv(arg, 2)
        if size is None:
            self._missing_argument()

        pattern = cyclic_pattern(size)
        num_bytes_written = peda.writemem(address, pattern)
        if num_bytes_written:
            msg("Written %d chars of cyclic pattern to 0x%x" % (size, address))
        else:
            msg("Failed to write to memory")

        return

    # cyclic_pattern()
    def pattern_arg(self, *arg):
        """
        Set argument list with cyclic pattern
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME size1 [size2,offset2] ...
        """

        if not arg:
            self._missing_argument()

        arglist = []
        for a in arg:
            (size, offset) = (a + ",").split(",")[:2]
            if offset:
                offset = to_int(offset)
            else:
                offset = 0
            size = to_int(size)
            if size is None or offset is None:
                self._missing_argument()

            # try to generate unique, non-overlapped patterns
            if arglist and offset == 0:
                offset = sum(arglist[-1])
            arglist += [(size, offset)]

        patterns = []
        for (s, o) in arglist:
            patterns += ["\'%s\'" % cyclic_pattern(s, o).decode('utf-8')]
        peda.execute("set arg %s" % " ".join(patterns))
        msg("Set %d arguments to program" % len(patterns))

        return

    # cyclic_pattern()
    def pattern_env(self, *arg):
        """
        Set environment variable with a cyclic pattern
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME ENVNAME size[,offset]
        """

        (env, size) = normalize_argv(arg, 2)
        if size is None:
            self._missing_argument()

        (size, offset) = (arg[1] + ",").split(",")[:2]
        size = to_int(size)
        if offset:
            offset = to_int(offset)
        else:
            offset = 0
        if size is None or offset is None:
            self._missing_argument()

        peda.execute("set env %s %s" % (env, cyclic_pattern(size, offset).decode('utf-8')))
        msg("Set environment %s = cyclic_pattern(%d, %d)" % (env, size, offset))

        return

    def pattern(self, *arg):
        """
        Generate, search, or write a cyclic pattern to memory
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME create size [file]
            MYNAME offset value
            MYNAME search
            MYNAME patch address size
            MYNAME arg size1 [size2,offset2]
            MYNAME env size[,offset]
        """

        options = ["create", "offset", "search", "patch", "arg", "env"]
        (opt,) = normalize_argv(arg, 1)
        if opt is None or opt not in options:
            self._missing_argument()

        func = getattr(self, "pattern_%s" % opt)
        func(*arg[1:])

        return
    pattern.options = ["create", "offset", "search", "patch", "arg", "env"]

    def substr(self, *arg):
        """
        Search for substrings of a given string/number in memory
        Commonly used for ret2strcpy ROP exploit
        Usage:
            MYNAME "string" start end
            MYNAME "string" [mapname] (default is search in current binary)
        """
        (search, start, end) = normalize_argv(arg, 3)
        if search is None:
            self._missing_argument()

        result = []
        search = arg[0]
        mapname = None
        if start is None:
            mapname = "binary"
        elif end is None:
            mapname = start

        if mapname:
            msg("Searching for sub strings of: %s in: %s ranges" % (repr(search), mapname))
            maps = peda.get_vmmap(mapname)
            for (start, end, perm, _) in maps:
                if perm == "---p":  # skip private range
                    continue
                result = peda.search_substr(start, end, search)
                if result: # return the first found result
                    break
        else:
            msg("Searching for sub strings of: %s in range: 0x%x - 0x%x" % (repr(search), start, end))
            result = peda.search_substr(start, end, search)

        if result:
            msg("# (address, target_offset), # value (address=0xffffffff means not found)")
            offset = 0
            for (k, v) in result:
                msg("(0x%x, %d), # %s" % ((0xffffffff if v == -1 else v), offset, string_repr(k)))
                offset += len(k)
        else:
            msg("Not found")

        return

    def assemble(self, *arg):
        """
        On the fly assemble and execute instructions using NASM
        Usage:
            MYNAME [mode] [address]
                mode: -b16 / -b32 / -b64
        """
        (mode, address) = normalize_argv(arg, 2)

        exec_mode = 0
        write_mode = 0
        if to_int(mode) is not None:
            address, mode = mode, None

        (arch, bits) = peda.getarch()
        if mode is None:
            mode = bits
        else:
            mode = to_int(mode[2:])
            if mode not in [16, 32, 64]:
                self._missing_argument()

        if self._is_running() and address == peda.getreg("pc"):
            write_mode = exec_mode = 1

        line = peda.execute_redirect("show write")
        if line and "on" in line.split()[-1]:
            write_mode = 1

        if address is None or mode != bits:
            write_mode = exec_mode = 0

        if write_mode:
            msg("Instruction will be written to 0x%x" % address)
        else:
            msg("Instructions will be written to stdout")

        msg("Type instructions (NASM syntax), one or more per line separated by \";\"")
        msg("End with a line saying just \"end\"")

        if not write_mode:
            address = 0xdeadbeef

        inst_list = []
        inst_code = b""
        # fetch instruction loop
        while True:
            inst = input("iasm|0x%x> " % address)
            if inst == "end":
                break
            if inst == "":
                continue
            bincode = peda.assemble(inst, mode)
            size = len(bincode)
            if size == 0:
                continue
            inst_list.append((size, bincode, inst))
            if write_mode:
                peda.writemem(address, bincode)
            # execute assembled code
            if exec_mode:
                peda.execute("stepi %d" % (inst.count(";")+1))

            address += size
            inst_code += bincode
            msg("hexify: \"%s\"" % to_hexstr(bincode))

        text = Nasm.format_shellcode(b"".join([x[1] for x in inst_list]), mode)
        if text:
            msg("Assembled%s instructions:" % ("/Executed" if exec_mode else ""))
            msg(text)
            msg("hexify: \"%s\"" % to_hexstr(inst_code))

        return


    ####################################
    #   Payload/Shellcode Generation   #
    ####################################
    def skeleton(self, *arg):
        """
        Generate python exploit code template
        Usage:
            MYNAME type [file]
                type = argv: local exploit via argument
                type = env: local exploit via crafted environment (including NULL byte)
                type = stdin: local exploit via stdin
                type = remote: remote exploit via TCP socket
        """
        options = ["argv", "stdin", "env", "remote"]
        (opt, outfile) = normalize_argv(arg, 2)
        if opt not in options:
            self._missing_argument()

        pattern = cyclic_pattern(20000).decode('utf-8')
        if opt == "argv":
            code = ExploitSkeleton().skeleton_local_argv
        if opt == "env":
            code = ExploitSkeleton().skeleton_local_env
        if opt == "stdin":
            code = ExploitSkeleton().skeleton_local_stdin
        if opt == "remote":
            code = ExploitSkeleton().skeleton_remote_tcp

        if outfile:
            msg("Writing skeleton code to file \"%s\"" % outfile)
            open(outfile, "w").write(code.strip("\n"))
            os.chmod(outfile, 0o755)
            open("pattern.txt", "w").write(pattern)
        else:
            msg(code)

        return
    skeleton.options = ["argv", "stdin", "env", "remote"]

    def shellcode(self, *arg):
        """
        Generate or download common shellcodes.
        Usage:
            MYNAME generate [arch/]platform type [port] [host]
            MYNAME search keyword (use % for any character wildcard)
            MYNAME display shellcodeId (shellcodeId as appears in search results)
	    MYNAME zsc [generate customize shellcode]

            For generate option:
                default port for bindport shellcode: 16706 (0x4142)
                default host/port for connect back shellcode: 127.127.127.127/16706
                supported arch: x86
        """
        def list_shellcode():
            """
            List available shellcodes
            """
            text = "Available shellcodes:\n"
            for arch in SHELLCODES:
                for platform in SHELLCODES[arch]:
                    for sctype in SHELLCODES[arch][platform]:
                        text += "    %s/%s %s\n" % (arch, platform, sctype)
            msg(text)

        """ Multiple variable name for different modes """
        (mode, platform, sctype, port, host) = normalize_argv(arg, 5)
        (mode, keyword) = normalize_argv(arg, 2)
        (mode, shellcodeId) = normalize_argv(arg, 2)

        if mode == "generate":
            arch = "x86"
            if platform and "/" in platform:
                (arch, platform) = platform.split("/")

            if platform not in SHELLCODES[arch] or not sctype:
                list_shellcode()
                return
            #dbg_print_vars(arch, platform, sctype, port, host)
            try:
                sc = Shellcode(arch, platform).shellcode(sctype, port, host)
            except Exception as e:
                self._missing_argument()

            if not sc:
                msg("Unknown shellcode")
                return

            hexstr = to_hexstr(sc)
            linelen = 16 # display 16-bytes per line
            i = 0
            text = "# %s/%s/%s: %d bytes\n" % (arch, platform, sctype, len(sc))
            if sctype in ["bindport", "connect"]:
                text += "# port=%s, host=%s\n" % (port if port else '16706', host if host else '127.127.127.127')
            text += "shellcode = (\n"
            while hexstr:
                text += '    "%s"\n' % (hexstr[:linelen*4])
                hexstr = hexstr[linelen*4:]
                i += 1
            text += ")"
            msg(text)

        # search shellcodes on shell-storm.org
        elif mode == "search":
            if keyword is None:
                self._missing_argument()

            res_dl = Shellcode().search(keyword)
            if not res_dl:
                msg("Shellcode not found or cannot retrieve the result")
                return

            msg("Found %d shellcodes" % len(res_dl))
            msg("%s\t%s" %(blue("ScId"), blue("Title")))
            text = ""
            for data_d in res_dl:
                text += "[%s]\t%s - %s\n" %(yellow(data_d['ScId']), data_d['ScArch'], data_d['ScTitle'])
            pager(text)

        # download shellcodes from shell-storm.org
        elif mode == "display":
            if to_int(shellcodeId) is None:
                self._missing_argument()

            res = Shellcode().display(shellcodeId)
            if not res:
                msg("Shellcode id not found or cannot retrieve the result")
                return

            msg(res)
	#OWASP ZSC API Z3r0D4y.Com
        elif mode == "zsc":
            'os lists'
            oslist = ['linux_x86','linux_x64','linux_arm','linux_mips','freebsd_x86',
                    'freebsd_x64','windows_x86','windows_x64','osx','solaris_x64','solaris_x86']
            'functions'
            joblist = ['exec(\'/path/file\')','chmod(\'/path/file\',\'permission number\')','write(\'/path/file\',\'text to write\')',
                    'file_create(\'/path/file\',\'text to write\')','dir_create(\'/path/folder\')','download(\'url\',\'filename\')',
                    'download_execute(\'url\',\'filename\',\'command to execute\')','system(\'command to execute\')']
            'encode types'
            encodelist = ['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random',
                    'sub_yourvalue','inc','inc_timeyouwant','dec','dec_timeyouwant','mix_all']
            try:
                while True:
                    for os in oslist:
                        msg('%s %s'%(yellow('[+]'),green(os)))
                    if pyversion == 2:
                        os = input('%s'%blue('os:'))
                    if pyversion == 3:
                        os = input('%s'%blue('os:'))
                    if os in oslist: #check if os exist
                        break
                    else:
                        warning_msg("Wrong input! Try Again.")
                while True:
                    for job in joblist:
                        msg('%s %s'%(yellow('[+]'),green(job)))
                    if pyversion == 2:
                        job = raw_input('%s'%blue('job:'))
                    if pyversion == 3:
                        job = input('%s'%blue('job:'))
                    if job != '':
                        break
                    else:
                        warning_msg("Please enter a function.")
                while True:
                    for encode in encodelist:
                        msg('%s %s'%(yellow('[+]'),green(encode)))
                    if pyversion == 2:
                        encode = raw_input('%s'%blue('encode:'))
                    if pyversion == 3:
                        encode = input('%s'%blue('encode:'))
                    if encode != '':
                        break
                    else:
                        warning_msg("Please enter a encode type.")
            except (KeyboardInterrupt, SystemExit):
                warning_msg("Aborted by user")
            result = Shellcode().zsc(os,job,encode)
            if result is not None:
                msg(result)
            else:
                pass
            return
        else:
            self._missing_argument()

        return
    shellcode.options = ["generate", "search", "display","zsc"]

    def gennop(self, *arg):
        """
        Generate abitrary length NOP sled using given characters
        Usage:
            MYNAME size [chars]
        """
        (size, chars) = normalize_argv(arg, 2)
        if size is None:
            self._missing_argument()

        nops = Shellcode.gennop(size, chars)
        msg(repr(nops))

        return

    def payload(self, *arg):
        """
        Generate various type of ROP payload using ret2plt
        Usage:
            MYNAME copybytes (generate function template for ret2strcpy style payload)
            MYNAME copybytes dest1 data1 dest2 data2 ...
        """
        (option,) = normalize_argv(arg, 1)
        if option is None:
            self._missing_argument()

        if option == "copybytes":
            result = peda.payload_copybytes(template=1) # function template
            arg = arg[1:]
            while len(arg) > 0:
                (target, data) = normalize_argv(arg, 2)
                if data is None:
                    break
                if to_int(data) is None:
                    if data[0] == "[" and data[-1] == "]":
                        data = eval(data)
                        data = list2hexstr(data, peda.intsize())
                else:
                    data = "0x%x" % data
                result += peda.payload_copybytes(target, data)
                arg = arg[2:]

        if not result:
            msg("Failed to construct payload")
        else:
            text = ""
            indent = to_int(config.Option.get("indent"))
            for line in result.splitlines():
                text += " "*indent + line + "\n"
            msg(text)
            filename = peda.get_config_filename("payload")
            open(filename, "w").write(text)

        return
    payload.options = ["copybytes"]

    def snapshot(self, *arg):
        """
        Save/restore process's snapshot to/from file
        Usage:
            MYNAME save file
            MYNAME restore file
        Warning: this is not thread safe, do not use with multithread program
        """
        options = ["save", "restore"]
        (opt, filename) = normalize_argv(arg, 2)
        if opt not in options:
            self._missing_argument()

        if not filename:
            filename = peda.get_config_filename("snapshot")

        if opt == "save":
            if peda.save_snapshot(filename):
                msg("Saved process's snapshot to filename '%s'" % filename)
            else:
                msg("Failed to save process's snapshot")

        if opt == "restore":
            if peda.restore_snapshot(filename):
                msg("Restored process's snapshot from filename '%s'" % filename)
                peda.execute("stop")
            else:
                msg("Failed to restore process's snapshot")

        return
    snapshot.options = ["save", "restore"]

    def crashdump(self, *arg):
        """
        Display crashdump info and save to file
        Usage:
            MYNAME [reason_text]
        """
        (reason,) = normalize_argv(arg, 1)
        if not reason:
            reason = "Interactive dump"

        logname = peda.get_config_filename("crashlog")
        logfd = open(logname, "a")
        config.Option.set("_teefd", logfd)
        msg("[%s]" % "START OF CRASH DUMP".center(78, "-"))
        msg("Timestamp: %s" % time.ctime())
        msg("Reason: %s" % red(reason))

        # exploitability
        pc = peda.getreg("pc")
        if not peda.is_address(pc):
            exp = red("EXPLOITABLE")
        else:
            exp = "Unknown"
        msg("Exploitability: %s" % exp)

        # registers, code, stack
        self.context_register()
        self.context_code(16)
        self.context_stack()

        # backtrace
        msg("[%s]" % "backtrace (innermost 10 frames)".center(78, "-"), "blue")
        msg(peda.execute_redirect("backtrace 10"))

        msg("[%s]\n" % "END OF CRASH DUMP".center(78, "-"))
        config.Option.set("_teefd", "")
        logfd.close()

        return

    def utils(self, *arg):
        """
        Miscelaneous utilities from utils module
        Usage:
            MYNAME command arg
        """
        (command, carg) = normalize_argv(arg, 2)
        cmds = ["int2hexstr", "list2hexstr", "str2intlist"]
        if not command or command not in cmds or not carg:
            self._missing_argument()

        func = globals()[command]
        if command == "int2hexstr":
            if to_int(carg) is None:
                msg("Not a number")
                return
            result = func(to_int(carg))
            result = to_hexstr(result)

        if command == "list2hexstr":
            if to_int(carg) is not None:
                msg("Not a list")
                return
            result = func(eval("%s" % carg))
            result = to_hexstr(result)

        if command == "str2intlist":
            res = func(carg)
            result = "["
            for v in res:
                result += "%s, " % to_hex(v)
            result = result.rstrip(", ") + "]"

        msg(result)
        return
    utils.options = ["int2hexstr", "list2hexstr", "str2intlist"]

###########################################################################
class pedaGDBCommand(gdb.Command):
    """
    Wrapper of gdb.Command for master "peda" command
    """
    def __init__(self, cmdname="peda"):
        self.cmdname = cmdname
        self.__doc__ = pedacmd._get_helptext()
        super(pedaGDBCommand, self).__init__(self.cmdname, gdb.COMMAND_DATA)

    def invoke(self, arg_string, from_tty):
        # do not repeat command
        self.dont_repeat()
        arg = peda.string_to_argv(arg_string)
        if len(arg) < 1:
            pedacmd.help()
        else:
            cmd = arg[0]
            if cmd in pedacmd.commands:
                func = getattr(pedacmd, cmd)
                try:
                    # reset memoized cache
                    reset_cache(sys.modules['__main__'])
                    func(*arg[1:])
                except Exception as e:
                    if config.Option.get("debug") == "on":
                        msg("Exception: %s" %e)
                        traceback.print_exc()
                    peda.restore_user_command("all")
                    pedacmd.help(cmd)
            else:
                msg("Undefined command: %s. Try \"peda help\"" % cmd)
        return

    def complete(self, text, word):
        completion = []
        if text != "":
            cmd = text.split()[0]
            if cmd in pedacmd.commands:
                func = getattr(pedacmd, cmd)
                for opt in func.options:
                    if word in opt:
                        completion += [opt]
            else:
                for cmd in pedacmd.commands:
                    if cmd.startswith(text.strip()):
                        completion += [cmd]
        else:
            for cmd in pedacmd.commands:
                if word in cmd and cmd not in completion:
                    completion += [cmd]
        return completion


###########################################################################
class Alias(gdb.Command):
    """
    Generic alias, create short command names
    This doc should be changed dynamically
    """
    def __init__(self, alias, command, shorttext=1):
        (cmd, opt) = (command + " ").split(" ", 1)
        if cmd == "peda" or cmd == "pead":
            cmd = opt.split(" ")[0]
        if not shorttext:
            self.__doc__ = pedacmd._get_helptext(cmd)
        else:
            self.__doc__ = green("Alias for '%s'" % command)
        self._command = command
        self._alias = alias
        super(Alias, self).__init__(alias, gdb.COMMAND_NONE)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("%s %s" %(self._command, args))

    def complete(self, text, word):
        completion = []
        cmd = self._command.split("peda ")[1]
        for opt in getattr(pedacmd, cmd).options: # list of command's options
            if text in opt and opt not in completion:
                completion += [opt]
        if completion != []:
            return completion
        if cmd in ["set", "show"] and text.split()[0] in ["option"]:
            opname = [x for x in config.OPTIONS.keys() if x.startswith(word.strip())]
            if opname != []:
                completion = opname
            else:
                completion = list(config.OPTIONS.keys())
        return completion


###########################################################################
## INITIALIZATION ##
# global instances of PEDA() and PEDACmd()
peda = PEDA()
pedacmd = PEDACmd()
pedacmd.help.__func__.options = pedacmd.commands # XXX HACK

# register "peda" command in gdb
pedaGDBCommand()
Alias("pead", "peda") # just for auto correction

# create aliases for subcommands
for cmd in pedacmd.commands:
    func = getattr(pedacmd, cmd)
    func.__func__.__doc__ = func.__doc__.replace("MYNAME", cmd)
    if cmd not in ["help", "show", "set"]:
        Alias(cmd, "peda %s" % cmd, 0)

# handle SIGINT / Ctrl-C
def sigint_handler(signal, frame):
    warning_msg("Got Ctrl+C / SIGINT!")
    gdb.execute("set logging off")
    peda.restore_user_command("all")
    raise KeyboardInterrupt
signal.signal(signal.SIGINT, sigint_handler)

# custom hooks
peda.define_user_command("hook-stop",
    "peda context\n"
    "session autosave"
    )

# common used shell commands aliases
shellcmds = ["man", "ls", "ps", "grep", "cat", "more", "less", "pkill", "clear", "vi", "nano"]
for cmd in shellcmds:
        Alias(cmd, "shell %s" % cmd)

# custom command aliases, add any alias you want
Alias("phelp", "peda help")
Alias("pset", "peda set")
Alias("pshow", "peda show")
Alias("pbreak", "peda pltbreak")
Alias("pattc", "peda pattern_create")
Alias("patto", "peda pattern_offset")
Alias("patta", "peda pattern_arg")
Alias("patte", "peda pattern_env")
Alias("patts", "peda pattern_search")
Alias("find", "peda searchmem") # override gdb find command
Alias("ftrace", "peda tracecall")
Alias("itrace", "peda traceinst")
Alias("jtrace", "peda traceinst j")
Alias("stack", "peda telescope $sp")
Alias("viewmem", "peda telescope")
Alias("reg", "peda xinfo register")
Alias("brva", "breakrva")

# misc gdb settings
peda.execute("set confirm off")
peda.execute("set verbose off")
peda.execute("set output-radix 0x10")
peda.execute("set prompt \001%s\002" % red("\002gdb-peda$ \001")) # custom prompt
peda.execute("set height 0") # disable paging
peda.execute("set history expansion on")
peda.execute("set history save on") # enable history saving
peda.execute("set disassembly-flavor intel")
peda.execute("set follow-fork-mode child")
peda.execute("set backtrace past-main on")
peda.execute("set step-mode on")
peda.execute("set print pretty on")
peda.execute("handle SIGALRM print nopass") # ignore SIGALRM
peda.execute("handle SIGSEGV stop print nopass") # catch SIGSEGV
