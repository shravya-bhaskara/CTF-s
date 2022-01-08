#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<time.h>

struct credentials{
	char name[20];
	char password[20];
	void (*call_password_view)(char* pass);
	int check_flag;
};

void backdoor();

void hidden_func(){
char buf[0x100];
printf("\nJump to:\n");
read(0, buf, 0x100-1);
asm("jmp *%0": :"m"(*buf));
return ;
}

void password_view(){
printf("\n\nOnly authorized personnels are allowed to view this data!\n1. Username: Harry\nPassword: s3cur17y_5uck5\n\n2. Username: Astrid\nPassword: d4ff0d1ll5_4r3_pr3t7y\n\n3. Username: Rose\nPassword: M4ry_h4s_4_l177l3_l4mb\n\n4. Username: Catherine\nPassword: 7r4v3ll3r_15_l0s7\n\n5. Username: Joe\nPassword: m4rtyr\n\n6. Username: Vincent\nPassword: s3v3n_sw0rd5\n\n");
puts("Whoa what have I found here?? Lemme search for a backdoor too !! :)\n");
}

int password_check(struct credentials cred){

char pass[20] = "s3cur3_p4ssw0rd";
for(int i=0; i<strlen(pass); i++){
if(!(*(cred.password+i) == *(pass+i))){
printf("Invalid Password\n");
exit(0);
}
}
printf("Correct Password!\n");
//password_view();
return rand();
}

void initialize()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(60);
}

void main(){

initialize();

struct credentials credentials;
credentials.check_flag = 0;
credentials.call_password_view = password_view;

srand(time(0) & 0xffffff00);
int res;
char buf[0x100];

printf("Please enter your credentials:\nName:\n");
read(0, credentials.name, 20);
fflush(stdin);

printf("Password:\n");
read(0, credentials.password, 0x50);
fflush(stdin);

res = password_check(credentials);
credentials.call_password_view(credentials.name);

if(credentials.check_flag == res){
hidden_func();
return ;
}
}

void backdoor(){
	char flag[50];
	FILE *fp;
	fp = fopen("flag.txt", "rb");
	if(fp != NULL){
		fgets(flag, 60, fp);
		fclose(fp);
	}
	printf("%s\n", flag);
	exit(0);

}


