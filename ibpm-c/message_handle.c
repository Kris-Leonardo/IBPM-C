#include "message_handle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "stdlib.h"
void messageToValue(void *message, mpz_t message_mpz, char *m)
{
  char* c = NULL;
  unsigned int value = 0, size = 0;
  c = message;
  while(*c != '\0')
  {
  	value = (unsigned int) *c;
	mpz_mul_ui(message_mpz, message_mpz, 256);
  	mpz_add_ui(message_mpz, message_mpz, value);
	c += 1;
  }
  mpz_get_str(m, 10, message_mpz);
}

void valueToMessage(char *message, mpz_t message_mpz)
{
  char *c = NULL;
  c = (char*) message_mpz->_mp_d;
  unsigned int count = 0;

  while(*(c + count) != '\0'){
	count += 1;
  }
  message[count] = '\0';
  while(count > 0){
  	count -= 1;
  	message[count] = *c;
	c += 1;
  }
}

