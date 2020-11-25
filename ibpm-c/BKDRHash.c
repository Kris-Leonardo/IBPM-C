#include "BKDRHash.h"

unsigned int BKDRHash(const unsigned char* str, unsigned int len)
{
	unsigned int seed = 131;
	unsigned int hash = 0;
	unsigned int i    = 0;

	for(i = 0; i < len; str++, i++)
	{
		hash = (hash * seed) + (*str);
	}

	return hash;
}
