# OverFlow:

* In this challenge, a c-program is given and according to the c-code, we can see that an initial buffer of buffersize 40 and flag of flagsize 40 are declared. The main function calls the vuln() function, where auth=0. However if auth=1, then it calls the f;ag() function. 
* Thus now our job is to locate the buffer and overwrite it with a suitable value, so that the flag() function gets called.

# Python code : 
```
python -c "print('A'*41)" | ./overflow.chal
```
