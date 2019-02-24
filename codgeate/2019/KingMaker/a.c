#include <stdio.h>
#include <string.h>

int main()
{
    char s1[20];
    FILE *stream;

    stream = fopen("key1","r");

    printf("%d\n",stream);
    fgets(s1,5,0);
}
