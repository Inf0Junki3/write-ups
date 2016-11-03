Samsclass.info: heap overflow
=============================

url: https://samsclass.info/127/proj/p8x-heap-remote.htm

This challenge does not come with much in the way of instructions, but that's what makes this one
fun. The only thing that we know about the challenge is that it has to do with heap overflows.

We download the file and run a quick analysis on it to make sure it doesn't have any nasty 
backdoors; then, we use r2pipe to run the disassembly of the main instruction. The first time,
analysis seemed to bork and one can't run pdf @ main. No matter - we run a search on strings, pick
one that looks like it's relevant, then run axt to see references to the string.

Looking at the main function, it becomes evident that this is running as a service, to which one 
connects over TCP. Also, it appears that the program performs several allocations in the heap.
The first allocation is 4 bytes, which could be an int or a 4-byte address. The second call is for
0x220 bytes. The third call is 4 bytes again and the fourth call is 0x400 bytes. We start playing 
with those values, connecting to the service and providing cyclic patterns of 0x230 bytes and 0x410
bytes. We find that we're able to make the service crash at the following line:

        mov dword [edx], eax

Furthermore, we note that edx and eax contain values found in the cyclic pattern. Beautiful, we have
a write-what-where! Looking back at the code, a printf statement shortly follows the call that 
crashes the service. So we can use the write-what-where to overwrite the reference to printf and
point the EIP to a payload of our design. The size of the buffer we control is 0x220 bytes, so we 
have a fair amount of space to play with.

We use pwntools to find the reference to the printf function in the got:

        p8x_elf = ELF("p8x")                                                                                
        printf_address = p8x_elf.got["printf"]

Then, we assemble a payload -- once again with pwntools:

        payload = asm(shellcraft.setreuid(0) + shellcraft.findpeersh())

However, we have a problem: we need the address for our payload. Wait, don't we have that?

        0x08048c51      50             push eax
        0x08048c52      68768e0408     push str.Here_is_the_message:__s_n ; "Here is the message: %s." @ 0x8048e76
        0x08048c57      e864f9ffff     call sym.imp.printf

Notice that the call to printf references. So this means that eax basically contains the pointer
to our payload when we are calling printf. In fact, eax contains the address we are overwriting and
then our payload. So we need a gadget that adds at least 4 to eax and then calls eax. Using ropper,
finding such a gadget is easy.

We stick in the addresses, pad, and send the payload over to the service and -- presto, we get shell.
