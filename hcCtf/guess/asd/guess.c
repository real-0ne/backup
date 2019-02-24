#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

int main(void)
{
        setvbuf(stdout,NULL,_IONBF,0);
        setvbuf(stdin,NULL,_IONBF,0);
	char buf[LENGTH];
    	
	memset(buf,0,LENGTH);
        puts("Input String!");
	read(0,buf,0x300);
	return 0;
}
