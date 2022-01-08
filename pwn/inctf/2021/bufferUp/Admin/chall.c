#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<stdbool.h>
#include<math.h>
#include<time.h>


int win3(unsigned long int arg4){
	unsigned long int x, n;
	int sum=0, len=0;

	x = rand();
	n = x;
	while (n != 0){
		len++;
        	n /= 10;
	}
	
	for(int i=len-1; i>=0; i--){
		sum += (int)(x/(pow(10, i))) % 10;
	}
	if(!(arg4 - sum)){
		return 1;
	}else{
		return 0;
	}
}

int win2(unsigned long int arg2, unsigned long int arg3){
	unsigned long int u, v, c1, c2, d1, d2;
	u = arg2 + arg3;
	v = arg2 - arg3;
	c1 = u ^ 0x11112222;
	c2 = v ^ 0x33334444;
	
	d1 = c1 ^ 0x55556666;
	d2 = c2 ^ 0x77778888;
	
	if((d1 == 0x1ffdd898f) && (d2 == 0x7e40fcc3)){
		return 1;
	}else{
		return 0;
	}
}

int win1(unsigned long int arg1){
char st[16], st1[16];
char *ptr;
unsigned long int n, num;
int rem, len = 0, j = 0;
n = arg1;
while (n != 0){
	len++;
        n /= 10;
}
for (int i = 0; i < len; i++){
        rem = arg1 % 10;
        arg1 = arg1 / 10;
        st[len - (i + 1)] = rem + '0';
}
st[len] = '\x00';		//0xdeadbeef = 37359 28559

for (int i = 0; i<len; i++){
	if(i<len/2){
		st1[i] = st[len/2 - 1 - i];
	}
	else if((i>=len/2) && (i<len) && (j<len/2)){
	st1[i] = st[len - 1 - j];
	j++;
	}
	
}
st1[len] = '\x00';

num = 0, j = 0;
for (int i = len-1; i >= 0; i--){
        num+= (st1[i] - 48)*pow(10, j);
        j++;
}

if(!(num - 3405691582)){	//num = 0xcafebabe
	return 1;
}else{
	return 0;
}

}
void initialize()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(30);
}

int vuln(){
char buf[0x20];
bool w1 = false;
bool w2 = false;
bool w3 = false;

unsigned long int argument1 = 0xdeadbeef;
unsigned long int argument2 = 0xbeefcafe;
unsigned long int argument3 = 0xdeadcafe;
unsigned long int argument4 = 0xbabedead;

puts("Please enter your name: ");
fgets(buf, 0x80, stdin);

w1 = win1(argument1);
if(w1){
	w2 = win2(argument2, argument3);
	if(w2){
		w3 = win3(argument4);
		if(w3){
			return w3;
		}else{
			exit(0);
		}
	}	
}
exit(0);
}

int main(){
initialize();
srand(time(0) & 0xffffff00);
vuln();
return 0;
}
