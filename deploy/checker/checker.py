#!/usr/bin/env python3

# Do not make modification to checklib.py (except for debug), it can be replaced at any time
import checklib
import random
import string
import sys
import os
import hashlib
import json
import base64
os.environ["PWNLIB_NOTERM"] = "1"

from pwn import *
from s3lib import *

context.timeout = 5
context.log_level = "debug"

data = checklib.get_data()
action = data['action']
auth_port = 8392
service_name = 's3'

team_id = data['teamId']
team_addr = '10.60.' + team_id + '.1'
team_addr = "127.0.0.1"




# Check SLA


def check_sla():
    conn=None
    password=get_random_string(32)
    try:
        conn=remote(team_addr, auth_port)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                      "Cannot connect", str(e))
    id=None
    try:
        id=register(conn, password)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                      "Cannot register", str(e))
    
    try:
        login(conn, id, password)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                      "Cannot login", str(e))
    choice=random.randint(0,2)
    if(choice==0): # check save and load
        shellcode, expected_output = get_normal_shellcode()()
        shellcode=base64.b64encode(shellcode)
        name=get_random_string(32)
        # Check save and load
        try:
            save_shellcode(conn, name, shellcode)
        except Exception as e:
            checklib.quit(checklib.Status.DOWN,
                      "Cannot save shellcode", str(e))
        shellcodes=[]
        try:
            shellcodes=list_shellcodes(conn)
        except Exception as e:
            checklib.quit(checklib.Status.DOWN,
                      "Cannot retrieve list of shellcodes", str(e))
        if(not name in shellcodes):
            checklib.quit(checklib.Status.DOWN,
                      "Shellcode not in list of saved shellcodes", f"Saved shellcodes are {shellcodes}, {name} not in list")
        try:
            saved_shellcode=get_shellcode(conn, name)
            if(base64.b64decode(shellcode) not in saved_shellcode):
                checklib.quit(checklib.Status.DOWN,
                      "Saved shellcode does not match", f"{shellcode}!={saved_shellcode}")
        except Exception as e:
            checklib.quit(checklib.Status.DOWN,
                      "Cannot get saved shellcode", str(e))
        output=b""
        try:
            output=run_shellcode(conn, name)
        except Exception as e:
            checklib.quit(checklib.Status.DOWN,
                      "Cannot run shellcode", str(e))
        if(output!=expected_output):
            checklib.quit(checklib.Status.DOWN,
                      "Output from shellcode is not correct", f"{output}!={expected_output}")
    elif(choice==1): # check run without save
        shellcode, expected_output = get_normal_shellcode()()
        shellcode=base64.b64encode(shellcode)
        name=get_random_string(32)
        output=b""
        try:
            output=run_shellcode_no_save(conn, shellcode)
        except Exception as e:
            checklib.quit(checklib.Status.DOWN,
                      "Cannot run shellcode", str(e))
        if(output!=expected_output):
            checklib.quit(checklib.Status.DOWN,
                      "Output from shellcode is not correct", f"{output}!={expected_output}")
    elif(choice==2): # check open
        check = get_random_string(random.randint(30, 40))
        name = get_random_string(32)
        try:
            save_shellcode(conn, name, base64.b64encode(check))
        except Exception as e:
            checklib.quit(checklib.Status.DOWN,
                      "Cannot save shellcode", str(e))
        shellcode=open_shellcode(name)
        shellcode=base64.b64encode(shellcode)
        output=b""
        try:
            output=run_shellcode_no_save(conn, shellcode)
        except Exception as e:
            checklib.quit(checklib.Status.DOWN,
                      "Cannot run shellcode", str(e))
        if(check not in output):
            checklib.quit(checklib.Status.DOWN,
                      "Output from shellcode is not correct", f"{output}!={check}")


    checklib.quit(checklib.Status.OK, 'OK')


# Put the flag using the flag as the seed for random stuff
def put_flag():
    flag=data["flag"]
    hasher = hashlib.sha256()
    hasher.update(flag.encode())
    filename=hasher.hexdigest()
    f=open("./data/"+filename, "w")
    conn=None
    password=get_random_string(32)
    try:
        conn=remote(team_addr, auth_port)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                      "Cannot connect", str(e))
    id=None
    try:
        id=register(conn, password)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                      "Cannot register", str(e))
    try:
        login(conn, id, password)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                      "Cannot login", str(e))

    name=get_random_string(32)
    shellcode = echo_flag_shellcode(flag.encode())
    try:
        save_shellcode(conn, name, shellcode)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                    "Cannot save shellcode", str(e))
    shellcodes=[]
    try:
        shellcodes=list_shellcodes(conn)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                    "Cannot retrieve list of shellcodes", str(e))
    if(not name in shellcodes):
        checklib.quit(checklib.Status.DOWN,
                    "Shellcode not in list of saved shellcodes", f"Saved shellcodes are {shellcodes}, {name} not in list")

    f.write(json.dumps({"id":id,"password":password.decode(), "name":name.decode()}))
    f.close()

    checklib.quit(checklib.Status.OK, 'OK')

# Check if the flag still exists, use the flag as the seed for random stuff as for put flag


def get_flag():
    flag = data['flag']
    hasher = hashlib.sha256()
    hasher.update(flag.encode())
    filename=hasher.hexdigest()
    try:
        f=open("./data/"+filename, "r")
    except Exception as e:
        checklib.quit(checklib.Status.DOWN, "Flag not found", e)
    coso=json.loads(f.read())
    id=coso["id"]
    password=coso["password"].encode()
    name=coso["name"].encode()
    conn=None
    try:
        conn=remote(team_addr, auth_port)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                      "Cannot connect", str(e))
    try:
        login(conn, id, password)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                      "Cannot login", str(e))
    
    shellcodes=[]
    try:
        shellcodes=list_shellcodes(conn)
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                    "Cannot retrieve list of shellcodes", str(e))
    if(not name in shellcodes):
        checklib.quit(checklib.Status.DOWN,
                    "Shellcode not in list of saved shellcodes", f"Saved shellcodes are {shellcodes}, {name} not in list")
    
    output=""
    try:
        output=run_shellcode(conn, name).strip(b"\00").decode()
    except Exception as e:
        checklib.quit(checklib.Status.DOWN,
                    "Cannot run shellcode", str(e))
    if(output!=flag):
        checklib.quit(checklib.Status.DOWN,
                    "Output from shellcode is not correct", f"{output}!={flag}")

    checklib.quit(checklib.Status.OK, 'OK')


if __name__ == "__main__":
    isExist = os.path.exists("./data")

    if not isExist:
        os.makedirs("./data")
    if action == checklib.Action.CHECK_SLA.name:
        check_sla()
    elif action == checklib.Action.PUT_FLAG.name:
        put_flag()
    elif action == checklib.Action.GET_FLAG.name:
        get_flag()