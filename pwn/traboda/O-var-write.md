# O-Var-Write:

* In this challenge we have been given a c-code. We can see that value = 0xdeadbeef initially and initial buffer size is 160 bytes. However fgets() takes in max 168 bytes. We can also see that the "value" is compared with 0xcafebabe and if equal it calls function win() where the flag can be printed out.

* And so we know that the buffer lies in fgets() wherein i gave give 168 bytes of input though the buffersize declared is 160. Hence we need to overflow the buffer in a way that 'value = 0xcafebabe'
* To do that we know that our buffer size is 160 bytes and so whatever input follows these 160 bytes, probably gets stored in ebp-0xc and then is finally compared with 0xcafebabe

# To do that we can run the following command:
```
python -c "from pwn import *; print('A'*160 + p32(0xcafebabe))" | ./av_015504a4-7a4f-4708-bfd8-781af111dca9.chall
```
