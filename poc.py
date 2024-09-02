#!/usr/bin/env python3
import argparse
from memutils import *

LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
PAGE_SIZE = 4096

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

def initialize_target(binary_path: str):
    target_process = process([binary_path])
    return target_process


def parse_args():
    parser = argparse.ArgumentParser(description="[*] process injection on a vulnerable binary.")
    parser.add_argument("binary", help="[*] path to the vulnerable binary.")
    parser.add_argument("so", help="[*] path to the shared object (.so) file.")
    return parser.parse_args()


def main():
    user_args = parse_args()
    target_process = initialize_target(user_args.binary)
    syscall_info = parse_proc_syscall(target_process.pid)
    log.info(f"current rsp: {hex(syscall_info.rsp)}")
    target_process.interactive()

if __name__ == "__main__":
    main()
