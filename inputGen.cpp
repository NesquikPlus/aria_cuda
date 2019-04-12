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

    char hexStr[2];
	unsigned int num;
	unsigned int fileLen = atoi(argv[1]);

	srand(time(NULL)); 


	for(int i=0; i < fileLen; i++)
	{
	    num = rand() % 16;;
	    sprintf(hexStr, "%x", num);
	    fprintf(f, "%s", hexStr);
	}

	fclose(f);


	return 0;
}