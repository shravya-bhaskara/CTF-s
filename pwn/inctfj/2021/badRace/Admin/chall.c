#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

void initialize()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(60);
}

int begin_race(int access){
unsigned int token_key;
char word[0x20];
printf("Give us your access token key: \n");
scanf("%u", &token_key);
getchar();

if((access ^ token_key) == 0x1337c0de){
	printf("\nGive us your navigation commands to win the race!\n");
	fgets(word, 0x50, stdin);

}else{
	printf("Access denied!\n");
}
return 0;
}

void race_car(int car){

char choice;
int access_code = 0;
printf("\nWhat kind of race would you choose?\n");
printf("\n1. Open-wheel racing\n2. Touring car racing\nChoice: ");

scanf("%c", &choice);
getchar();
if(car == 0){
printf("Choose a car first\n");
exit(0);
}else{
switch (choice){
	case '1':
		if(car == 1){
		access_code = 0xdeadbeef;
		break;
		}else{
		access_code = 0xd0d0face;
		break;
		}
	case '2':
		if(car == 1){
		access_code = 0xc0cac0de;
		break;
		}else{
		access_code = 0xcafebabe;
		break;
		}
	default:
		printf("Invalid choice!\n");
		exit(0);
}
begin_race(access_code);
}
}

int buy_car(){

char choice;
char car1[0x20];
char car2[0x20];

puts("\nWhat car do you wish to buy?");
printf("1. Ace of Spades\n2. Nightshade\nChoice: ");

scanf("%c",&choice);
getchar();
switch(choice){
	case '1':
		printf("You may find your car at this location: %p\n", &car1);
		return 1;
		break;
	case '2':
		printf("You may find your car at this location: %p\n", &car2);
		return 2;
		break;
	default:
		printf("Invalid input!\n");
		exit(0);
}
}


int main(){

char choice;
int car = 0;

initialize();
puts("Wecome to my car race!");

while(1){
printf("\n1. Buy car\n2. Race car\nChoice: ");

scanf("%c", &choice);
getchar();
switch(choice){
	case '1':
		car = buy_car();
		break;
	case '2':
		race_car(car);
		break;
	default:
		printf("Invalid choice!\n");
		break;
}
}
}

