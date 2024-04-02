set confirm off
unset env

source path/to/your/gef.py
gef config context.clear_screen False
## comment this out if you don't want to debug the initialization code
## (or use LD_LIBRARY_PATH instead)
set env LD_PRELOAD=liblzma5_5.6.1-1/usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1
set env LANG=C
file /usr/sbin/sshd
## start sshd on port 2022
set args -p 2022
set disassembly-flavor intel
set confirm on
set startup-with-shell off

show env
show args
catch fork

echo
echo Now Enter Ctrl-C and run setup
echo
run

define setup
# patch check_software_breakpoint
set *(unsigned short*)0x7ffff7f93498=0xc031
# restore jmp. to endbr64
set *(unsigned int*)0x7ffff7f8a7f0=0xfa1e0ff3
# breakpoint at the next `push rbp`
name-break "get_cpuid" *0x7ffff7f8a7f4
name-break "backdoor_init" *0x7ffff7f8a784
end

# catch load liblzma
# r
# b *0x7ffff7f8a7f0
