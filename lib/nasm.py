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
from utils import *
import config

class Nasm(object):
    """
    Wrapper class for assemble/disassemble using nasm/ndisassm
    """
    def __init__(self):
        pass

    @staticmethod
    def assemble(asmcode, mode=32):
        """
        Assemble ASM instructions using NASM
            - asmcode: input ASM instructions, multiple instructions are separated by ";" (String)
            - mode: 16/32/64 bits assembly

        Returns:
            - bin code (raw bytes)
        """
        if not os.path.exists(config.NASM):
            error_msg("%s binary not found, please install NASM for asm/rop functions" % config.NASM)
            raise UserWarning("missing requirement")

        asmcode = asmcode.strip('"').strip("'")
        asmcode = asmcode.replace(";", "\n")
        asmcode = ("BITS %d\n" % mode) + asmcode
        asmcode = decode_string_escape(asmcode)
        asmcode = re.sub("PTR|ptr|ds:|DS:", "", asmcode)
        infd = tmpfile()
        outfd = tmpfile(is_binary_file=True)
        infd.write(asmcode)
        infd.flush()
        execute_external_command("%s -f bin -o %s %s" % (config.NASM, outfd.name, infd.name))
        infd.close()

        if os.path.exists(outfd.name):
            bincode = outfd.read()
            outfd.close()
            return bincode
        # reopen it so tempfile will not complain
        open(outfd.name,'w').write('B00B')
        return None

    @staticmethod
    def disassemble(buf, mode=32):
        """
        Disassemble binary to ASM instructions using NASM
            - buf: input binary (raw bytes)
            - mode: 16/32/64 bits assembly

        Returns:
            - ASM code (String)
        """
        out = execute_external_command("%s -b %d -" % (config.NDISASM, mode), buf)
        return out

    @staticmethod
    def format_shellcode(buf, mode=32):
        """
        Format raw shellcode to ndisasm output display
            "\x6a\x01"  # 0x00000000:    push byte +0x1
            "\x5b"      # 0x00000002:    pop ebx

        TODO: understand syscall numbers, socket call
        """
        def nasm2shellcode(asmcode):
            if not asmcode:
                return ""

            shellcode = []
            pattern = re.compile("([0-9A-F]{8})\s*([^\s]*)\s*(.*)")

            matches = pattern.findall(asmcode)
            for line in asmcode.splitlines():
                m = pattern.match(line)
                if m:
                    (addr, bytes, code) = m.groups()
                    sc = '"%s"' % to_hexstr(codecs.decode(bytes, 'hex'))
                    shellcode += [(sc, "0x"+addr, code)]

            maxlen = max([len(x[0]) for x in shellcode])
            text = ""
            for (sc, addr, code) in shellcode:
                text += "%s # %s:    %s\n" % (sc.ljust(maxlen+1), addr, code)

            return text

        out = execute_external_command("%s -b %d -" % (config.NDISASM, mode), buf)
        return nasm2shellcode(out)
