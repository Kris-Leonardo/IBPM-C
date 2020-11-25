targets = bls3.o sm3.o sm4.o BKDRHash.o message_handle.o
cc = gcc

edit : $(targets)
	cc -o edit $(targets) -L. -lpbc -lgmp

bls3.o : bls3.c sm3.h
	cc -c -Wall bls3.c -L. -lpbc -lgmp
sm3.o : sm3.c sm3.h
	cc -c sm3.c
sm4.o : sm4.c sm4.h
	cc -c sm4.c
BKDRHash.o : BKDRHash.c BKDRHash.h
	cc -c BKDRHash.c
message_handle.o : message_handle.c message_handle.h
	cc -c message_handle.c
.PHONY :clean
clean :
	rm bls3.o sm3.o sm4.o BKDRHash.o message_handle.o 
