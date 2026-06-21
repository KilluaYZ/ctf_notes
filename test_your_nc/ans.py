from pwn import *

context.log_level = "debug"

io = remote(
    "7ebfbb42ca775a333cb76797.tcp-ctf2.dasctf.com",
    9999,
    ssl=True
)

# 1. 接收提示
#io.recvuntil(b"> ")

# 2. 发送 payload
#io.sendline(payload)

# 3. payload 成功执行 system("/bin/sh")、
#    execve("/bin/sh", ...) 或 ret2libc 后，进入交互 shell
io.interactive()
