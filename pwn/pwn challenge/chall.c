// gcc chall.c -fno-stack-protector -no-pie -o chall

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(){
int auth = 0;
char passphrase[20];
printf("Enter the passphrase: ");
gets(passphrase);
if(auth){
    printf("Access granted!\n");
}else{
    printf("Access denied!\n");
}
return 0;
}
