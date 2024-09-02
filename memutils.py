from pwn import *

PAGE_SIZE = 4096

PROC_MAPS = "/proc/{}/maps"
PROC_MEM = "/proc/{}/mem"
PROC_SYSCALL = "/proc/{}/syscall"

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

def dl_open_rop(pid: int, address, so_path):
    """
    :param pid:
    :param address:
    :param so_path:
    :return:
    """



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
