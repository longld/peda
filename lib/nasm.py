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
    Wrapper class for disassemble using ndisassm
    """
    def __init__(self):
        pass

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
