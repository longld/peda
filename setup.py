#!/usr/bin/env python

from distutils.core import setup
from distutils.command.install_lib import install_lib as _install

class my_install(_install):
    def run(self):
        _install.run(self)
        from os.path import expanduser
        home = expanduser("~")
        print "Writing %s/.gdbinit" % home
        gdb = open(home + '/.gdbinit','a')
        gdb.write("source %speda/peda.py\n" % self.install_dir)
        gdb.close()

setup(name       = 'peda',
    cmdclass     = dict(install_lib=my_install),
    version      = '1.0',
    description  = 'Python Exploit Development Assistance for GDB',
    license      = 'Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License',
    author       = 'Long Le Dinh',
    author_email = 'longld@vnsecurity.net',
    url          = 'https://github.com/longld/peda',
    packages     = ['peda', 'peda.lib'],
   )
