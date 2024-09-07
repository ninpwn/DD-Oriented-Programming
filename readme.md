# Prologue
I don't have a good prologue so I'll just say that I got tired of Linux process injection PoCs relying on either ``ptrace()`` or ``LD_PRELOAD`` and wanted to create a ***somewhat*** generic way to inject arbitrary code via a malicious shared object library into processes that relies on the fact that ``procfs`` memory related entries with r/w permissions allow me to quite literally pwn and own the process.
This PoC was done on an Ubuntu 22.04 x64 system. 
## Motivation
- It's cool and I love pwn.
- Could allow bypassing some process specific anti-debugging concepts.
# Requirements & Components
This PoC relies on ``procfs`` entries that include data that indicates the process's current state and mappings:
```
/proc/<pid>/maps
/proc/<pid>/syscall
```
And the ability to r/w from/to memory via:
```
/proc/<pid>/mem
```
But what is the ``procfs`` and what are the prementioned process specific entries?
# The PoC's Caveats 
It's worth mentioning that since 2012 the Linux kernel added a configurable security module named 'yama' which could manage or prevent the access to relevant ``procfs`` entries and the debugging of processes via the ``ptrace`` syscall.
However, if you're running as the ``root`` user you can run the following command to disable this potential system-wide restriction:
```sh
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```
Other than that, there should be no more system-wide mitigations in standard Linux systems.
# The Glorious Linux procfs
Quoted from ``man proc``:
```
The proc filesystem is a pseudo-filesystem which provides an interface to kernel data structures. It is commonly mounted at /proc....
Most of the files in the proc filesystem are read-only, but some files are writable, allowing kernel variables to be changed.
```
We mostly care about the ``/proc/<pid>/`` subdirectories which are defined as:
```
... subdirectories exposing information about the process with the corresponding process ID.
```
So... Simply put, files under ``/proc/<pid>/`` are virtual files that allow us to determine a process's state in terms of its execution and the resources that it's currently utilizing (according to the process id that is specified at the ``procfs`` virtual file path). The ``procfs`` pseudo-filesystem is great for process debugging purposes at runtime, but it can be also abused to allow process exploitation and that will become very clear later on.
## The Juicy Entries
When browsing the specific entries that the ``procfs`` has to offer I had two main goals in mind:
1. Identifying a process's current state
2. Reading and writing to/from a process's memory

The latter goal is fairly easy to achieve and its relevant ``procfs`` entry is commonly known as  ``/proc/<pid>/mem``, which as its name suggests, it's an interface to a process's memory that depending on the system's configuration allows reading and or writing to the process's memory.
The first goal however is a bit more trickier to achieve, more specifically determining the process's current state because for determining the process's mapped virtual memory, we have an entry that is used often during process debugging which is ``/proc/<pid>/maps``.
```sh
# Example /proc/<pid>/maps contents of a /bin/sh process:
mapped range			  perms                                          symbol
6322c9120000-6322c9124000 r--p 00000000 103:02 36700809                  /usr/bin/dash
...
6322c9140000-6322c9142000 rw-p 00000000 00:00 0 
6322ca5ef000-6322ca610000 rw-p 00000000 00:00 0                          [heap]
7acf3b800000-7acf3b828000 r--p 00000000 103:02 36700281                  /usr/lib/x86_64-linux-gnu/libc.so.6
...
7acf3bb98000-7acf3bb9a000 r--p 00000000 103:02 36700260                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fff64725000-7fff64746000 rw-p 00000000 00:00 0                          [stack]
7fff647f0000-7fff647f4000 r--p 00000000 00:00 0                          [vvar]
7fff647f4000-7fff647f6000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```
As can be seen in the example ``/proc/pid/maps`` output, we can very comfortably define the process's memory mappings according to their size, memory permissions and associated executable/shared object path or purpose.

But how do we determine the process's current execution state? The process's register values, current instruction being executed, etc. are critical to actually be able to control the process's flow and to restore the process's execution later on.
During my research I discovered the virtual file: ``/proc/<pid>/syscall``, which was introduced in Linux 2.6.27 (2017) and as quoted in ``man proc`` it exposes the:
```
...system call number and argument registers for the system call currently being executed by the process, followed by the values of the stack pointer and program counter registers.
```
Which is **EXACTLY** what I was looking for.
```sh
# Example output from /proc/<pid>/syscall in an x64 system
0 0x3 0x749a81074000 0x20000 0x22 0x749a81073010 0x749a81073010 0x7fff6b43c3b8 0x749a80f147e2
```
# Exploitation Flow
Now that we know all of the essential ``procfs`` entries, we need to compile the abilities that we gain from them into a complete exploit.
I went for a memory corruption exploit that could be used on modern ELF binaries, meaning it's able to bypass common modern binary exploitation mitigations:
* NX enabled (no executable stack)
* Full RELRO (GOT & PLT protection)
* ASLR (Address Space Layout Randomization, prevents the usage of hardcoded addresses)

Eventually, I went for a ROP chain that's executed by corrupting the stack after enumerating gadgets in mapped executable virtual memory and finding the current value of the ``RSP`` register in the target process.
We're aiming to execute ``dlopen`` as an easy way to execute complex logic via the malicious so instead of a fragile ROP chain.
## Exploitation Overview
1. Parsing the ``/proc/<pid>/syscall`` maps into registers.
2. Finding a 'cave' in the mapped BSS segments (there's always a cave due to page aligned mappings of different segments) - we use that 'cave' to write our malicious so path for the later ``dlopen`` call, this phase is technically optional as the so path could be written directly onto the stack and then referred to via a stack pointer, but I thought that the BSS approach would be easier to implement.
3. Enumerating mapped segments with execution permissions for gadgets using ``/proc/<pid>/maps`` for mappings and their permissions and ``/proc/<pid>/mem`` to scan the relevant mappings for specific gadget signatures.
4. Finding ``dlopen``'s address by calculating its address using ``libc``'s base address and the offset specified in ``dlopen``'s ELF symbol.
5. Writing the ROP chain to the stack using the ``RSP`` obtained from ``/proc/<pid>/syscall``,  and ``/proc/<pid>/mem`` for the actual stack content manipulation.
6. Trigger the execution explicitly or wait for the syscall to finish its execution. 
## ROP Chain Gadgets (dlopen)

```python
rop_chain = (  
    p64(found_gadgets["nop"]) +              # aligning the stack
    p64(found_gadgets["pop_rax"]) +          # rax = dlopen address
    p64(dlopen_addr) +                       
    p64(found_gadgets["pop_rdi"]) +          # rdi = pointer to the so_path
    p64(address) +  
    p64(found_gadgets["pop_rsi"]) +          # rsi = RTLD_LAZY / 1
    p64(os.RTLD_LAZY) +  
    p64(found_gadgets["jmp_rax"]) +          # executing dlopen with our args
)
```
## Test Malicious SO Contents
```c
#include <stdio.h>  
#include <stdlib.h>  
  
__attribute__((constructor))  // executed when the library is loaded into memory
void init_library() {  
    printf("Library loaded: Hello from the constructor!\n"); // direct output
    system("date >> /tmp/win"); // blind verification
}
```

# The PoC's PoC
https://github.com/user-attachments/assets/b179f8a8-7e86-417e-a9db-0fa3bad2bbe0
# TODO
This is a conceptual TODO as I don't intend on maintaining this project:
- Restoring the BSS cave with null bytes.
- Restoring the process's execution state via the SO's logic.
- Adding support for multiple architectures.
- Add logic that checks if a stack alignment is necessary or not (currently aligning the stack using a NOP gadget).
- Explore thread based entry points for network processes like web servers.
- Receive the malicious SO over a socket (to avoid writing it to the disk).
- Use a more accurate stack pointer to override the stack return address more precisely.
# Epilogue 
I hope you enjoyed this read, let me know what could be improved, for the record, I'm NOT responsible for the usage of this technique in unauthorized manners.
Feel free to read the source code, I tried my best to make it as readable as I can write it.
