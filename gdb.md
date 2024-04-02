# gdb & gef

I am long-time gef user, please checkout: https://github.com/hugsy/gef for more information.

First, please replace the `endbr64` of the `hijacked_cpuid` into `jmp .`:

```shell
perl -pe 's/\xF3\x0F\x1E\xFA\x55\x48\x89\xF5\x4C\x89\xCE/\xEB\xFE\x90\x90\x55\x48\x89\xF5\x4C\x89\xCE/g' -i liblzma.so.5.6.1
```

Thanks to @smx-smx.

Run gdb with the gdbinit file:

```
root@laptop ~/xz-backdoor# gdb
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.debian.net>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
LD_PRELOAD=liblzma5_5.6.1-1/usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1
LANG=C
Argument list to give program being debugged when it is started is "-p 2022".
Catchpoint 1 (fork)
Now Enter Ctrl-C and run setup
```

The program will hang at the patched `jmp .`. (to ensure the liblzma is loaded)

Then press Ctrl+C and run the customized command `setup`. 

It will restore the `jmp .` and patch the check_software_breakpoint by `xor eax, eax` before `ret`.

```
^C
Program received signal SIGINT, Interrupt.
0x00007ffff7f8a7f0 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007ffff7f88fc8  →  0x000000000003bda0
$rcx   : 0x00007fffffffe8b8  →  0x0000006800000007
$rdx   : 0x00007fffffffe8b4  →  0x0000000700000000
$rsp   : 0x00007fffffffe8a8  →  0x00007ffff7f8cc29  →  0xfffe9e058d48c289
$rbp   : 0x00007fffffffe8d0  →  0x00007fffffffe9e0  →  0x00007fffffffecb0  →  0x00007fffffffeda0  →  0x0000000000000000
$rsi   : 0x00007fffffffe8b0  →  0x0000000000000007
$rdi   : 0x1               
$rip   : 0x00007ffff7f8a7f0  →  0xf58948559090feeb
$r8    : 0x00007fffffffe8bc  →  0xf7fc318000000068 ("h"?)
$r9    : 0x00007fffffffe8c0  →  0x00007ffff7fc3180  →  0x00007ffff7f86000  →  0x03010102464c457f
$r10   : 0x00007ffff7b3e480  →  0x00007ffff7f8804d  →  0x5800302e355f5a58 ("XZ_5.0"?)
$r11   : 0x00007ffff7fc3180  →  0x00007ffff7f86000  →  0x03010102464c457f
$r12   : 0x00007ffff7f87018  →  0x000d001a0000050c
$r13   : 0x7               
$r14   : 0x6800000007      
$r15   : 0x00007ffff7fc3180  →  0x00007ffff7f86000  →  0x03010102464c457f
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffe8a8│+0x0000: 0x00007ffff7f8cc29  →  0xfffe9e058d48c289    ← $rsp
0x00007fffffffe8b0│+0x0008: 0x0000000000000007   ← $rsi
0x00007fffffffe8b8│+0x0010: 0x0000006800000007   ← $rcx
0x00007fffffffe8c0│+0x0018: 0x00007ffff7fc3180  →  0x00007ffff7f86000  →  0x03010102464c457f     ← $r9
0x00007fffffffe8c8│+0x0020: 0xe6e1520f5cb95600
0x00007fffffffe8d0│+0x0028: 0x00007fffffffe9e0  →  0x00007fffffffecb0  →  0x00007fffffffeda0  →  0x0000000000000000      ← $rbp
0x00007fffffffe8d8│+0x0030: 0x00007ffff7fd9fab  →  <_dl_relocate_object+100b> mov r10, QWORD PTR [rbp-0xf8]
0x00007fffffffe8e0│+0x0038: 0x00007ffff7b48750  →  "/usr/local/lib/libgpg-error.so.0"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7f8a7e9                  pop    r12
   0x7ffff7f8a7eb                  ret    
   0x7ffff7f8a7ec                  nop    DWORD PTR [rax+0x0]
 → 0x7ffff7f8a7f0                  jmp    0x7ffff7f8a7f0
   0x7ffff7f8a7f2                  nop    
   0x7ffff7f8a7f3                  nop    
   0x7ffff7f8a7f4                  push   rbp
   0x7ffff7f8a7f5                  mov    rbp, rsi
   0x7ffff7f8a7f8                  mov    rsi, r9
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sshd", stopped 0x7ffff7f8a7f0 in ?? (), reason: SIGINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7f8a7f0 → jmp 0x7ffff7f8a7f0
[#1] 0x7ffff7f8cc29 → mov edx, eax
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  setup
Breakpoint 2 at 0x7ffff7f8a7f4
Breakpoint 3 at 0x7ffff7f8a784
gef➤  
```

You may need to find the correct address for these two replacement.

```
define setup
# patch check_software_breakpoint
set *(unsigned short*)0x7ffff7f93498=0xc031

# restore jmp. to endbr64
set *(unsigned int*)0x7ffff7f8a7f0=0xfa1e0ff3

# breakpoint at the next `push rbp`
name-break "get_cpuid" *0x7ffff7f8a7f4
name-break "backdoor_init" *0x7ffff7f8a784
end
```

Then continue, you will get breakpoint at `get_cpuid` twice, and then `backdoor_init`.

```
[+] Hit breakpoint *0x7ffff7f8a7f4 (get_cpuid)
...
[+] Hit breakpoint *0x7ffff7f8a7f4 (get_cpuid)
...
[+] Hit breakpoint *0x7ffff7f8a784 (backdoor_init)
```