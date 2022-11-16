/*
   Generate encryption key / IV and save to binary files
*/

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void main( int argc , char * argv[] )
{
    uint8_t key[EVP_MAX_KEY_LENGTH] ,
             iv[EVP_MAX_IV_LENGTH] ; 
    
    unsigned key_len = EVP_MAX_KEY_LENGTH ;
    unsigned iv_len  = EVP_MAX_IV_LENGTH  ;
    int fd_key, fd_iv ;
    if( argc < 2 )
    {
        printf("\nMissing person name: use %s [amal | basim] \n\n" , argv[0]) ;
        exit(-1) ;
    }

    char keyFile[100] , ivFile[100] ;
    snprintf( keyFile , 100 , "%s/%sKey.bin" , argv[1] , argv[1] );
    snprintf( ivFile , 100 , "%s/%sIV.bin" , argv[1] , argv[1] );

    printf("\n*** Generating key file '%s' and IV file '%s'\n\n" , keyFile , ivFile );
    fd_key = open( keyFile , O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR)  ;
    if( fd_key == -1 )
    {
        fprintf(stderr, "Unable to create file '%s' for key\n" , keyFile );
        exit(-1) ;
    }

    fd_iv = open( ivFile , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)  ;
    if( fd_iv == -1 )
    {
        fprintf(stderr, "Unable to create file '%s' for IV\n" , ivFile );
        exit(-1) ;
    }

    // Genrate the random key & IV
    RAND_bytes( key , key_len );
    RAND_bytes( iv  , iv_len  );
    
    write( fd_key , key , key_len );
    write( fd_iv  , iv  , iv_len );
    
    close( fd_key ) ;
    close( fd_iv ) ;

}


