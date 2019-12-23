peda
====

PEDA - Python Exploit Development Assistance for GDB

## Key Features:
* Enhance the display of gdb: colorize and display disassembly codes, registers, memory information during debugging.
* Add commands to support debugging and exploit development (for a full list of commands use `peda help`):
  * `aslr` -- Show/set ASLR setting of GDB
  * `checksec` -- Check for various security options of binary
  * `dumpargs` -- Display arguments passed to a function when stopped at a call instruction
  * `dumprop` -- Dump all ROP gadgets in specific memory range
  * `elfheader` -- Get headers information from debugged ELF file
  * `elfsymbol` -- Get non-debugging symbol information from an ELF file
  * `lookup` -- Search for all addresses/references to addresses which belong to a memory range
  * `patch` -- Patch memory start at an address with string/hexstring/int
  * `pattern` -- Generate, search, or write a cyclic pattern to memory
  * `procinfo` -- Display various info from /proc/pid/
  * `pshow` -- Show various PEDA options and other settings
  * `pset` -- Set various PEDA options and other settings
  * `readelf` -- Get headers information from an ELF file
  * `ropgadget` -- Get common ROP gadgets of binary or library
  * `ropsearch` -- Search for ROP gadgets in memory
  * `searchmem|find` -- Search for a pattern in memory; support regex search
  * `shellcode` -- Generate or download common shellcodes.
  * `skeleton` -- Generate python exploit code template
  * `vmmap` -- Get virtual mapping address ranges of section(s) in debugged process
  * `xormem` -- XOR a memory region with a key

## Installation

    git clone https://github.com/not-duckie/peda.git /opt/peda
    echo "source /opt/peda/peda.py" >> ~/.gdbinit
    echo "DONE! debug your program with gdb and enjoy"
Note:
This is exaclty the clone of peda repositry by [longld]https://github.com/longld/peda but this one doesnt throw warning to
use == instead of is when using with python3.
I changed it as it was anonying and peda is a great project by [longld]https://github.com/longld/peda and above those warnings. 

## Screenshot
![start](http://i.imgur.com/P1BF5mp.png)

![pattern arg](http://i.imgur.com/W97OWRC.png)

![patts](http://i.imgur.com/Br24IpC.png)
