#!/usr/bin/env python3
import argparse
from memutils import *

LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
PAGE_SIZE = 4096

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

DL_OPEN_GADGET_LEN = 0x30


def initialize_target(binary_path: str):
    target_process = process([binary_path])
    target_binary = ELF(binary_path, checksec=False)
    return target_process, target_binary


def parse_args():
    parser = argparse.ArgumentParser(description="[*] process injection on a vulnerable binary.")
    parser.add_argument("binary", help="[*] path to the vulnerable binary.")
    parser.add_argument("so", help="[*] path to the shared object (.so) file.")
    return parser.parse_args()


def setup_base_addresses(target_process, target_binary):
    mapped_text_sections = parse_proc_maps(target_process.pid)
    target_binary.address = mapped_text_sections[0][0]
    log.info(f"target binary base address: {hex(target_binary.address)}")

    libc = ELF(LIBC_PATH, checksec=False)
    libc.address = mapped_text_sections[3][0]
    log.info(f"LIBC base address: {hex(libc.address)}")

    return libc


def main():
    args = parse_args()
    target_process, target_binary = initialize_target(args.binary)
    libc = setup_base_addresses(target_process, target_binary)
    syscall_info = parse_proc_syscall(target_process.pid)
    log.info(f"current rsp: {hex(syscall_info.rsp)}")
    target_process.interactive()


if __name__ == "__main__":
    main()
