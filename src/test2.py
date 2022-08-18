from pwn import *
conn=process("./s3")
conn.sendline(b"2")
conn.sendline("ciaone")
conn.interactive()