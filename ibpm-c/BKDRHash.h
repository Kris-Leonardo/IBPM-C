#ifndef INCLUDE_GENERALHASHFUNCTION_C_H
#define INCLUDE_GENERALHASHFUNCTION_C_H

#include <stdio.h>

typedef unsigned int (*hash_function)(unsigned char*, unsigned int len);

unsigned int BKDRHash(const unsigned char* str, unsigned int len);

#endif
