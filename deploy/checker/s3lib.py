import string
import random
from pwn import *
def get_random_string(n):
    alph = string.ascii_letters + string.digits
    return "".join(random.choice(alph) for _ in range(n)).encode()

def register(conn, password):
    conn.recvuntil(b">")
    conn.sendline(b"2")
    conn.recvuntil(b"Please insert your password: ")
    conn.sendline(password)
    conn.recvuntil(b"Your user's ID is: ")
    return int(conn.recvline(False))

def login(conn, id, password):
    conn.recvuntil(b">")
    conn.sendline(b"1")
    conn.recvuntil(b"Please insert your ID: ")
    conn.sendline(str(id).encode())
    conn.recvuntil(b"Please insert your password: ")
    conn.sendline(password)
    tmp=conn.recvline()
    if(b"Wrong password!" in tmp):
        raise ValueError("Wrong password.")

def logout(conn):
    conn.recvuntil(b">")
    conn.sendline(b"6")

def list_shellcodes(conn):
    conn.recvuntil(b">")
    conn.sendline(b"1")
    data=conn.recvuntil(b"Welcome to your private area user")
    data=data.split(b"\n")
    res=[]
    for x in data:
        if(b" - " in x):
            res.append(x.split(b" - ", 1)[1])
    return res

def get_shellcode(conn, name):
    conn.recvuntil(b">")
    conn.sendline(b"2")
    conn.recvuntil(b"> ")
    conn.sendline(name)
    data=conn.recvuntil(b"Welcome")
    if(b"Shellcode not found." in data):
        raise ValueError("Shellcode not found")
    data=data.replace(b"\nWelcome", b"")
    return data

def save_shellcode(conn, name, shellcode):
    conn.recvuntil(b">")
    conn.sendline(b"3")
    conn.recvuntil(b"> ")
    conn.sendline(name)
    tmp=conn.recvline()
    if(b"Could not create a shellcode with that name." in tmp):
        raise ValueError("Cannot save shellcode")
    conn.send(shellcode)
    conn.sendline()

def run_shellcode(conn, name):
    conn.recvuntil(b">")
    conn.sendline(b"4")
    conn.recvuntil(b"> ")
    conn.sendline(name)
    tmp=conn.recvline()
    if(b"Could not load a shellcode with that name." in tmp):
        raise ValueError("Cannot load shellcode")
    data=conn.recvuntil(b"Your shellcode should have been run!", timeout=10)
    return data.replace(b"Your shellcode should have been run!", b"")

def run_shellcode_no_save(conn, shellcode):
    conn.recvuntil(b">")
    conn.sendline(b"5")
    conn.recvuntil(b"Send the bytes of your shellcode!\n")
    conn.send(shellcode)
    conn.sendline()
    data=conn.recvuntil(b"Your shellcode should have been run!", timeout=10)
    return data.replace(b"Your shellcode should have been run!", b"")

def get_normal_shellcode():
    return random.choice([echo_shellcode, calc_shellcode])

def echo_flag_shellcode(flag):
    parts=[flag[i:i+8] for i in range(0, len(flag), 8)]
    shellcode=""
    for part in parts[::-1]:
        fixed=part.ljust(8, b'\x00')
        shellcode+=f"mov rax, 0x{fixed[::-1].hex()}\n push rax\n"
    shellcode+=f"""mov rdx, {len(parts)*8}
            mov rdi, 1
            mov rsi, rsp
            mov rax, 1
            syscall
            mov rdi, 0
            mov rax, 60
            syscall"""
    return asm(shellcode, arch="amd64")

def echo_shellcode(): # checks write
    size=random.randint(1,4)
    rnd=[get_random_string(8) for _ in range(size)]
    push_cose=[f"mov rax, 0x{_[::-1].hex()}\n push rax" for _ in rnd]
    write=f"""mov rdx, {len(rnd)*8}
            mov rdi, 1
            mov rsi, rsp
            mov rax, 1
            syscall
            mov rdi, 0
            mov rax, 60
            syscall"""
    return asm("\n".join(push_cose)+"\n"+write, arch="amd64"), b"".join(rnd[::-1])

def calc_shellcode(): # checks math
    start=random.randint(10000, 1000000)
    res=start
    operations=["add", "sub", "xor"]
    tmp=random.randint(5, 20)
    code=f"mov rax, {start}"
    for x in range(tmp):
        op=random.choice(operations)
        val=random.randint(10, 1000)
        if(op=="add"):
            code+=f"\n add rax, {val}"
            res+=val
        elif(op=="sub"):
            code+=f"\n sub rax, {val}"
            res-=val
        elif(op=="xor"):
            code+=f"\n xor rax, {val}"
            res=res^val
    code+="""
             mov rbx, 0
             loop:
             cmp rbx, 64
             jge end
             mov rcx, rax
             and rcx, 1
             cmp rcx, 0
             jne one
             mov byte ptr [rsp], '0'
             jmp endif
             one:
             mov byte ptr [rsp], '1'
             endif:
             dec rsp
             inc rbx
             shr rax, 1
             jmp loop
             end:
             inc rsp
             mov rdx, 64
             mov rdi, 1
             mov rsi, rsp
             mov rax, 1
             syscall
            mov rdi, 0
            mov rax, 60
            syscall"""
    return asm(code, arch="amd64"), bin(res)[2:].rjust(64, '0').encode()

def open_shellcode(f): # checks open, read, close, write
    parts=[f[i:i+8] for i in range(0, len(f), 8)]
    shellcode="""mov rax, 0x2f
                push rax
                mov rdi, rsp
                mov rax, 80
                syscall
                mov rax, 0x0
                push rax
                """
    for part in parts[::-1]:
        fixed=part.rjust(8, b'\x00')
        shellcode+=f"mov rax, 0x{fixed[::-1].hex()}\n push rax\n"
    shellcode+="mov rdi, rsp"
    shellcode+="\n xor rdx, rdx"
    shellcode+="\n xor rsi, rsi"
    shellcode+="\n mov rax, 2"
    shellcode+="\n syscall"
    shellcode+="""
                mov rdi, rax
                mov r8, rax
                mov rax, 0
                mov rsi, rsp
                mov rdx, 256
                syscall
                mov rdi, r8
                mov rax, 3
                syscall
                mov rdx, 256
                mov rdi, 1
                mov rsi, rsp
                mov rax, 1
                syscall
                mov rdi, 0
                mov rax, 60
                syscall"""
    return asm(shellcode, arch="amd64")




#print(open_shellcode(b"/xato/gioca/a/generals"))