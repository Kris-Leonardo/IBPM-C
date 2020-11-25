/*Hash_1 = SM3
  Hash_2 = SM4
  Hash_3 = BKDRHash*/

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/time.h>
#include </home/chenshuyi/ibpm6/sm3.h>
#include </home/chenshuyi/ibpm6/sm4.h>
#include </home/chenshuyi/ibpm6/message_handle.h>
#include </home/chenshuyi/ibpm6/BKDRHash.h>


#define counts 32768 //隐私数据集合元素个数


pairing_t pairing;
element_t g;
element_t a,b,c,s;

unsigned char *getRandomStr(unsigned char str[],int length)
{
    int i,randnum;
    unsigned char str_array[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for(i = 0; i < length; i++)
    {
        randnum = rand() % 62;
        str[i] = str_array[randnum];
    }
    str[length] = '\0';
    return str;
}

void StrToHex(unsigned char *pbDest, unsigned char *pbSrc, int nLen)
{
    unsigned char h1,h2;
    unsigned char s1,s2;
    int i;

    for (i=0; i<nLen; i++)
    {
        h1 = pbSrc[2*i];
        h2 = pbSrc[2*i+1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9)
            s1 -= 7;

        s2 = toupper(h2) - 0x30;
        if (s2 > 9)
            s2 -= 7;

        pbDest[i] = s1*16 + s2;
    }
}


void setup()
{
    element_init_G1(g,pairing);
    element_init_Zr(a,pairing);
    element_init_Zr(b,pairing);
    element_init_Zr(c,pairing);
    element_init_Zr(s,pairing);
    element_random(g);
    element_random(a);
    element_random(b);
    element_random(c);
    element_random(s);

}

element_t * KeyGen1(unsigned char id[100],element_t t)
{
    element_t* sk1,*skt;
    element_t h1,ab1,g1;
    sk1 = (element_t*)malloc(sizeof(element_t));
    skt = (element_t*)malloc(sizeof(element_t));
    element_init_G1(h1,pairing);
    element_init_G1(sk1[0],pairing);
    element_init_G1(skt[0],pairing);
    element_init_Zr(ab1,pairing);
    element_init_G1(g1,pairing);

    unsigned char hash3_sk1[32];
    int ilen = strlen((char *)id);
    sm3(id,ilen,hash3_sk1);
    element_from_hash(h1,hash3_sk1,32);
    element_pow_zn(skt[0],h1,t);
    element_mul(ab1,a,b);
    element_pow_zn(g1,g,ab1);
    element_mul(sk1[0],g1,skt[0]);

    return sk1;
}
element_t *KeyGen2(element_t t)
{
    element_t* sk2;
    sk2 = (element_t*)malloc(sizeof(element_t));
    element_init_G1(sk2[0], pairing);
    element_pow_zn(sk2[0], g, t);
    return sk2;
}

element_t* KeyGen3(unsigned char id[100])
{
    element_t h3;
    element_t* sk3;
    sk3=(element_t *)malloc(sizeof(element_t));
    element_init_G1(h3,pairing);
    element_init_G2(sk3[0],pairing);

    unsigned char key_sk3[16];
    unsigned char input_sk3[16];
    unsigned char hash2_sk3[16];
    sm4_context ctx;
    StrToHex(key_sk3,id,16);
    sm4_setkey_enc(&ctx, key_sk3);
    StrToHex(input_sk3,id,16);
    sm4_crypt_ecb(&ctx, 1, 16,input_sk3,hash2_sk3);

    element_from_hash(h3,hash2_sk3,16);
    element_pow_zn(sk3[0],h3,c);

    element_clear(h3);
    return sk3;
}
element_t **Enc(unsigned char id[100],unsigned char D[][100])
{
    unsigned int i,j;
    element_t **data;
    data = (element_t**)malloc(sizeof(element_t*)*counts);
    for ( i = 0; i <counts ; i++)
    {
        data[i] = (element_t *)malloc(sizeof(element_t) * 5);
    }

    for(i=0; i<=(counts - 1); i++)
    {
        for(j=0; j<=4; j++)
        {
            if(j==4)
                element_init_GT(data[i][j],pairing);
            else
                element_init_G1(data[i][j],pairing);
        }
    }
    element_t r1,r2;
    element_t t1,t2,t3,t4,t5,t6;
    element_t temp4;
    element_t d;
    element_t C1,C2,C3,C4,C5;
    element_t h3,h4;
    element_t hash_c5;
    mpz_t message_mpz;
    for(i=0; i<=(counts - 1); i++)
    {
        element_init_G1(hash_c5,pairing);
        element_init_Zr(r1,pairing);
        element_init_Zr(r2,pairing);
        element_init_Zr(t1,pairing);
        element_init_Zr(t2,pairing);
        element_init_Zr(t3,pairing);
        element_init_G1(t4,pairing);
        element_init_GT(t5,pairing);
        element_init_GT(t6,pairing);
        element_init_G1(C1,pairing);
        element_init_G1(C2,pairing);
        element_init_G1(C3,pairing);
        element_init_G1(C4,pairing);
        element_init_GT(C5,pairing);

        element_init_G1(h3,pairing);
        element_init_G1(h4,pairing);
        element_init_G1(temp4,pairing);
        element_init_GT(d,pairing);

        mpz_init(message_mpz);
        element_random(r1);
        element_random(r2);
        /*C1*/
        element_pow_zn(C1, g, r2);
        element_set(data[i][0],C1);
        //element_printf(" C_%d_1 =  %B\n",i,C1);
        /*C2*/
        element_mul(t1,b,r1);
        element_pow_zn(C2,g,t1);
        element_set(data[i][1],C2);
        //element_printf(" C_%d_2 =  %B\n",i,C2);
        /*C3*/
        unsigned char hash3_c3[32];
        int ilen_c3 = strlen((char *)id);
        sm3(id,ilen_c3,hash3_c3);
        element_from_hash(h3,hash3_c3,32);
        element_pow_zn(C3,h3,r2);
        element_set(data[i][2],C3);
        //element_printf(" C_%d_3 =  %B\n",i,C3);
        /*C4*/
        unsigned  int hash4;
        hash4 = BKDRHash(D[i],sizeof(D[i]));
        char s4[10];
        sprintf(s4,"%u",hash4);
        element_from_hash(h4,s4,10);
        element_add(t2,r1,r2);
        element_mul(t3,a,t2);
        element_pow_zn(temp4,g,t3);
        element_mul(C4,temp4,h4);
        element_set(data[i][3],C4);
        //element_printf(" C_%d_4 =  %B\n",i,C4);
        /*C5*/
        unsigned char key_hashID[16];
        unsigned char input_hashID[16];
        unsigned char hash2_ID[16];
        sm4_context ctx_c5;
        StrToHex(key_hashID,id,16);
        sm4_setkey_enc(&ctx_c5,key_hashID);
        StrToHex(input_hashID,id,16);
        sm4_crypt_ecb(&ctx_c5, 1, 16,input_hashID,hash2_ID);
        char mes5[2048];
        char message_dec[2048];
        messageToValue(D[i],message_mpz,message_dec);// get the hex str of D[i]
        strcpy(mes5,"[");
        strcat(mes5,message_dec);
        strcat(mes5,",0]");
        element_set_str(d,mes5,10);
        element_to_mpz(message_mpz,d); // change the mes5 to string
        valueToMessage(mes5,message_mpz);
        element_from_hash(hash_c5,hash2_ID,16);
        element_pow_zn(t4,g,c);
        element_pairing(t5,hash_c5,t4);
        element_pow_zn(t6,t5,r2);
        element_mul(C5,t6,d);
        element_set(data[i][4],C5);
        //element_printf(" C_%d_5 =  %B\n\n",i,C5);

        element_clear(r1);
        element_clear(r2);
        element_clear(C1);
        element_clear(C2);
        element_clear(C3);
        element_clear(C4);
        element_clear(C5);
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);
        element_clear(t4);
        element_clear(t5);
        element_clear(t6);
        element_clear(d);
        element_clear(temp4);
        mpz_clear(message_mpz);
    }
    return data;
}

void Dec(element_t **cipArray,unsigned char id[100],unsigned char D[2][100])
{
    element_t **cip5 = cipArray;
    element_t tempdec,dec;
    element_init_GT(tempdec,pairing);
    element_init_GT(dec,pairing);
    element_t * sk3;
    mpz_t message_mpz; // used when convert the decrypt value to string message
    mpz_init(message_mpz);
    char message[2048],message_dec[2048];
 
	sk3=KeyGen3(id);

	int i;
    for(i=0; i<=(counts - 1); i++)
    {
        messageToValue(D[i],message_mpz,message_dec);
        strcpy(message,"[");
        strcat(message,message_dec);
        strcat(message,",0]");
        element_pairing(tempdec,sk3[0],cip5[i][0]);
        element_div(dec,cip5[i][4],tempdec);
        element_to_mpz(message_mpz,dec); // change the message_dec to string
        valueToMessage(message,message_mpz);
        //element_printf(" D_%d = %B\n",i,dec);
        //printf(" message D_%d=",i);
        //puts(message);
        //printf("\n");
    }
    free(sk3[0]);
    element_clear(tempdec);
    element_clear(dec);
    mpz_clear(message_mpz);
}
element_t *Aut(unsigned char id1[100],unsigned char id2[100],element_t t1,element_t t2)
{

    element_t * sk1,* sk2,* sk3,* sk4;
    element_t h1, h2, h3, h4, h5, h6;
    element_t n1, n2;
    int i;
    element_t *data;
    data = (element_t*)malloc(sizeof(element_t)*6);
    for (i = 0; i < 6; i++)
    {
        element_init_G1(data[i], pairing);
    }

    sk1 = KeyGen1(id1,t1);
	
	sk2 = KeyGen2(t1);
	
	sk3 = KeyGen1(id2,t2);
    sk4 = KeyGen2(t2);
    element_init_G1(h1, pairing);
    element_init_G1(h2, pairing);
    element_init_G1(h3, pairing);
    element_init_G1(h4, pairing);
    element_init_G1(h5, pairing);
    element_init_G1(h6, pairing);
    element_init_G1(n1, pairing);
    element_init_G1(n2, pairing);

    element_pow_zn(n1, g, a);
    element_pow_zn(n2, g, b);
    element_pow_zn(h1,sk1[0],s);
    element_set(data[0], h1);
    element_pow_zn(h2, sk2[0], s);
    element_set(data[1], h2);
    element_pow_zn(h3,sk3[0],s);
    element_set(data[2], h3);
    element_pow_zn(h4, sk4[0], s);
    element_set(data[3], h4);
    element_pow_zn(h5, n1, s);
    element_set(data[4], h5);
    element_pow_zn(h6, n2, s);
    element_set(data[5], h6);
    element_clear(n1);
    element_clear(n2);
    element_clear(h1);
    element_clear(h2);
    element_clear(h3);
    element_clear(h4);
    element_clear(h5);
    element_clear(h6);
    return data;

}

element_t *ETi_1(element_t **cipArray,element_t *Tok)
{
    element_t **C = cipArray;
    element_t *T=Tok;
    element_t *data1;
    data1 = (element_t*)malloc(sizeof(element_t)*counts);
    int i;
    for(i=0; i<=(counts - 1); i++)
    {
        element_init_GT(data1[i],pairing);
    }

    element_t ET1,ET2,temp1,temp2,temp3,temp4,ET;

    element_init_GT(ET1,pairing);
    element_init_GT(ET2,pairing);
    element_init_GT(ET,pairing);
    element_init_GT(temp1,pairing);
    element_init_GT(temp2,pairing);
    element_init_GT(temp3,pairing);
    element_init_GT(temp4,pairing);
    for(i=0; i<counts; i++)
    {
        element_pairing(ET1,C[i][1],T[4]);
        element_pairing(temp1,T[0],C[i][0]);
        element_pairing(temp2,T[1],C[i][2]);
        element_div(ET2,temp1,temp2);
        element_pairing(temp3,C[i][3],T[5]);
        element_mul(temp4,ET1,ET2);
        element_div(ET,temp3,temp4);

        element_set(data1[i],ET);
    }
    element_clear(temp4);
    element_clear(temp3);
    element_clear(temp2);
    element_clear(temp1);
    element_clear(ET1);
    element_clear(ET2);
    element_clear(ET);
    for(i=0 ; i<=(counts - 1); i++)
    {
        free(C[i]);
    }
    free(C);
    return data1;
}

element_t * ETi_2(element_t **cipArray,element_t *Tok)
{
    element_t **C = cipArray;
    element_t *T=Tok;
    element_t ET1,ET2,temp1,temp2,temp3,temp4,ET;
    element_t *data2;
    data2 = (element_t*)malloc(sizeof(element_t)*counts);
    int i;
    for(i=0; i<=(counts - 1); i++)
    {
        element_init_GT(data2[i],pairing);
    }

    element_init_GT(ET1,pairing);
    element_init_GT(ET2,pairing);
    element_init_GT(ET,pairing);
    element_init_GT(temp1,pairing);
    element_init_GT(temp2,pairing);
    element_init_GT(temp3,pairing);
    element_init_GT(temp4,pairing);
    for(i=0; i<=(counts - 1); i++)
    {
        element_pairing(ET1,C[i][1],T[4]);
        element_pairing(temp1,T[2],C[i][0]);
        element_pairing(temp2,T[3],C[i][2]);
        element_div(ET2,temp1,temp2);
        element_pairing(temp3,C[i][3],T[5]);
        element_mul(temp4,ET1,ET2);
        element_div(ET,temp3,temp4);
        element_set(data2[i], ET);
    }
    element_clear(temp4);
    element_clear(temp3);
    element_clear(temp2);
    element_clear(temp1);
    element_clear(ET1);
    element_clear(ET2);
    element_clear(ET);

    for(i=0 ; i<=(counts - 1); i++)
    {
        free(C[i]);
    }
    free(C);

    return data2;
}


int main(int argc, char **argv)
{
	printf("   ********************************************************************************************************************\n" );

    printf("   ********************************************************************************************************************\n" );

    printf("   *******************                                                                              *******************\n" );

    printf("   *******************                       Identity-Based-Private Matching                        *******************\n" );

    printf("   *******************                                                                              *******************\n" );

    printf("   ********************************************************************************************************************\n" );

    printf("   ********************************************************************************************************************\n" );
    pbc_demo_pairing_init(pairing,argc,argv);
    setup();
    printf("   ------------       (Trusted authority) gernerate Common Parameter(msk) & Master Private Key(pp)       --------------\n" );
    element_t t1,t2;
    element_init_Zr(t1,pairing);
    element_init_Zr(t2,pairing);

    element_random(t1);
    element_random(t2);

    int i,j;
    /*alice*/
    unsigned char *ma ="alice";
    unsigned char D1[counts][100];
    printf("   \n----------------------                            (Alice) message                               --------------------\n" );
    for(i=0; i<counts; i++)
        getRandomStr(D1[i],50);
	printf("   ----------------------                         After (Alice) Encode!                            --------------------\n" );
	element_t **cipArray1 = Enc(ma,D1);
	printf("   ----------------------                         After (Alice) Decode!                            --------------------\n" );
	Dec(cipArray1,ma,D1);
	
	
	unsigned char *mb="bob";
    unsigned char D2[counts][100];
    printf("   ----------------------                             (Bob) message                                --------------------\n" );
    for(i=0; i<counts; i++)
        getRandomStr(D2[i],50);
    printf("   ----------------------                          After (Bob) Encode!                             ------------------\n" );
	element_t **cipArray2 = Enc(mb,D2);
	printf(" ----------------------                          After (Bob) Decode!                             --------------------\n" );
	Dec(cipArray2,mb,D2);
	/*MATCH*/
    gettimeofday(&start_Aut,NULL);
	element_t *Tok = Aut(ma,mb,t1,t2);
    gettimeofday(&end_Aut,NULL);
	time_Aut=(end_Aut.tv_sec-start_Aut.tv_sec)*1000000+(end_Aut.tv_usec-start_Aut.tv_usec);
	time5 = time_Aut*0.000001;
	printf("################Aut Time #######   =  %f seconds\n",time5);
	
	printf("   \n----------------------                (Alice&Bob) gernerate Authorization token                 --------------------\n\n" );
    printf("   \n----------------------                       (Trusted authority)  Matching                      --------------------\n\n" );
    element_t *ET1,*ET2;
    
	gettimeofday(&start_Mat,NULL);
	ET1= ETi_1(cipArray1,Tok);
    ET2 = ETi_2(cipArray2,Tok);
    /*for(i=0; i<=(counts - 1); i++)
        element_printf(" (Alice) ET_%d=%B\n",i,ET1[i]);
    for(i=0; i<=(counts - 1); i++)
        element_printf(" (Bob) ET_%d=%B\n",i,ET2[i]);
    */
	for(i=0; i<=(counts - 1); i++)
    {
        for(j=0; j<=(counts - 1); j++)
        {

            if(element_cmp(ET1[i],ET2[j])==0)
                printf("\n       !!!!!!!!!!!!!!!!!!!!            (Alice) C_%d match (Bob) C_%d successfully            !!!!!!!!!!!!!!!!!!!!!\n\n",i,j);
            
        }
    }
	gettimeofday(&end_Mat,NULL);
	time_Mat=(end_Mat.tv_sec-start_Mat.tv_sec)*1000000+(end_Mat.tv_usec-start_Mat.tv_usec);
	time6 = time_Mat*0.000001;
	printf("################Mat Time #######   =  %f seconds\n",time6);
    element_clear(c);
    element_clear(b);
    element_clear(a);
    element_clear(g);
    pairing_clear(pairing);
    return 0;
}

