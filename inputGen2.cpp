#include <stdio.h>
#include <time.h>
#include <stdlib.h>


int main(int argc, char *argv[])
{
	if(argc < 2){
		printf("Need one argument(fileLen)\n");
		return -1;
	}

	FILE *f = fopen("input.txt", "w");
	if (f == NULL)
	{
	    printf("Error opening file!\n");
	    return -1;
	}

    char hexStr[33] = {'0','0','1','1','2','2','3','3','4','4','5','5','6','6','7','7','8','8','9','9','a','a','b','b','c','c','d','d','e','e','f','f','\0'};
	unsigned int fileLen = atoi(argv[1]);

	for(int i=0; i < fileLen/32 ; i++)
	{
	    fprintf(f, "%s", hexStr);
	}

	fclose(f);


	return 0;
}