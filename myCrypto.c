/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c         SKELETON  

Written By: 
     1- Mia Pham
     2- Emily Graff
Submitted on: 12-01-2022
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
    int status ;
    unsigned len=0 , encryptedLen=0 ;
   
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
    if( ! ctx )
        handleErrors("encrypt: failed to create CTX");
    
    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ; 
    if( status != 1 )
        handleErrors("encrypt: failed to EncryptInit_ex");
   
    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, & len, pPlainText, plainText_len) ; 
    if( status != 1 )
        handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;
   
    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len ;

    // Finalize the encryption. 
    status = EVP_EncryptFinal_ex( ctx, pCipherText , & len ) ; 
    if( status != 1 )
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len; // len could be 0 if no additional cipher text was generated
   
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
   
    return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
    int status ;
    unsigned len=0 , decryptedLen=0 ;
   
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
    if( ! ctx )
        handleErrors("decrypt: failed to creat CTX");
   
    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ; 
    if( status != 1 )
        handleErrors("decrypt: failed to DecryptInit_ex");
    
    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    status = EVP_DecryptUpdate( ctx, pDecryptedText, & len, pCipherText, cipherText_len) ; 
    if( status != 1 )
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;
   
    // If additionl decrypted text may still be generated,
    // the pDecryptedText pointer must be first advanced forward
    pDecryptedText += len ;
   
    // Finalize the decryption. 
    status = EVP_DecryptFinal_ex( ctx, pDecryptedText , & len ) ; 
    if( status != 1 )
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;
   
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
   
    return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************

static unsigned char   plaintext  [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext [ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       ciphertext2[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext [ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application
//-----------------------------------------------------------------------------

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int status ;
    unsigned len=0 , encryptedLen=0 ;
   
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
    if( ! ctx )
        handleErrors("encrypt: failed to create CTX");
    
    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ; 
    if( status != 1 )
        handleErrors("encrypt: failed to EncryptInit_ex");
    
    /* Reads chunks of plaintext -up to PLAINTEXT_LEN_MAX bytes each and 
    then encrypts this chunk, sending the ciphertext to fd_out */
    unsigned plaintext_len ;
    while ( (plaintext_len = read (fd_in, plaintext, CIPHER_LEN_MAX - 32 )) > 0 )
    {
        status = EVP_EncryptUpdate(ctx, ciphertext, & len, plaintext, plaintext_len) ; 
        if( status != 1 )
            handleErrors("encrypt: failed to EncryptUpdate");
        encryptedLen += len;

        write ( fd_out, ciphertext, len ) ;
    }

    // Finalize the encryption. 
    status = EVP_EncryptFinal_ex( ctx, ciphertext , & len ) ; 
    if( status != 1 )
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len;
    write ( fd_out, ciphertext, len ) ;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
   
    return encryptedLen;
}

//-----------------------------------------------------------------------------

int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

}

//***********************************************************************
// pLAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    RSA *rsa = RSA_new() ;
    if ( public )
        rsa = PEM_read_RSA_PUBKEY( fp, &rsa , NULL , NULL );
    else
        rsa = PEM_read_RSAPrivateKey( fp , &rsa , NULL , NULL );
 
    fclose( fp );

    return rsa;
}

//***********************************************************************
// PA-02
//***********************************************************************
#define INPUT_CHUNK   (1 << 12)

size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, write a copy of the incoming data stream
// file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    int status ;
    unsigned digest_len = 0;
    static unsigned char data_buffer [ INPUT_CHUNK ];

    // Use EVP_MD_CTX_create() to create new hashing context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
    if( ! ctx )
        handleErrors("failed to create CTX");

    // Initialize the context using EVP_DigestInit() so that it deploys 
    // the EVP_sha256() hashing function 
    status = EVP_DigestInit(ctx, EVP_sha256());
    if( status != 1 )
        handleErrors("failed to DigestInit");

    /* Loop until end-of input file */
    size_t bytes_read ;
    
    bytes_read = read(fd_in, data_buffer, INPUT_CHUNK);
    while ( bytes_read > 0 )
    {
        // read( fd_in, ...  , INPUT_CHUNK );
        // reads incoming data stream from file fd_in into data_buffer

        // Use EVP_DigestUpdate() to hash the data you read
        status = EVP_DigestUpdate(ctx, data_buffer, bytes_read);
        if (status != 1)
            handleErrors("failed to DigestUpdate");

        // writes a copy of incoming data stream to file fd_out
        if ( fd_out > 0 )
            write (fd_out, data_buffer, bytes_read);
        
        bytes_read = read(fd_in, data_buffer, INPUT_CHUNK);
    }

    // Finialize the hash calculation using EVP_DigestFinal() directly
    // into the 'digest' array
    EVP_DigestFinal(ctx, digest, &digest_len);

    // Use EVP_MD_CTX_destroy( ) to clean up the context
    EVP_MD_CTX_destroy(ctx);

    // return the length of the computed digest in bytes ;
    return digest_len;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are unsigned integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

unsigned MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG2 New\n");
    fprintf( log , "**************************\n\n");
    //
    // Your code from PA-04 Part ONE
    //
        /*  Check all pointers not being NULL */ 
    if (log == NULL || msg2 == NULL || Ka == NULL || Kb == NULL || Ks == NULL || IDa == NULL
                    || IDb == NULL || Na == NULL)  
    {
        fprintf( log , "NULL pointer(s) passed to MSG2_new() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG2_new()" );
    }

    unsigned LenA   = strlen( IDa ) + 1 ;
    unsigned LenB   = strlen( IDb ) + 1 ;

    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in a dynamically-allocated buffer
    unsigned tktPlainLen =  KEYSIZE + LENSIZE +  LenA ;

    if ( tktPlainLen > PLAINTEXT_LEN_MAX  )  
    {
        fprintf( log , "Plaintext of Ticket in MSG2_new is too big %u bytes( max is %u ) "
                       " ... EXITING\n" , tktPlainLen , PLAINTEXT_LEN_MAX );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext of Ticket in MSG2_new is too big\n" );
    }

    uint8_t *TktPlain = malloc( tktPlainLen ) ;
    if ( !TktPlain )  
    {
        // similar to above, but with  "Out of Memory allocating for TktPlain in MSG2_new" 
        fprintf (log, "Out of Memory allocating for TktPlain in MSG2_new\n");
        fflush (log);   fclose (log);
        exitError ("\nOut of Memory allocating for TktPlain in MSG2_new\n");
    }

    // 'p' is a temp pointer used to access segments of the TktPlain buffer
    uint8_t  *p = TktPlain ;      
    memcpy( p , Ks , KEYSIZE ) ;                        
    p += KEYSIZE ;

    unsigned *lenPtr ;    
    lenPtr = (unsigned *) p  ;   *lenPtr = LenA ;       
    p += LENSIZE ;
    memcpy( p , IDa , LenA );
    
    fprintf( log ,"    Plaintext Ticket (%u Bytes) is\n" , tktPlainLen);
    BIO_dump_indent_fp ( log , TktPlain , tktPlainLen , 4 ) ;  fprintf( log , "\n") ; 

    // Now, set TktCipher = encrypt( Kb , TktPlain );
    uint8_t *TktCipher = malloc (CIPHER_LEN_MAX);
    unsigned lenTktCipher = encrypt( TktPlain, tktPlainLen, Kb->key, Kb->iv , TktCipher) ;
    free( TktPlain ) ; // no longer needed

    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher }
    
    // compute the length of plaintext of MSG2 ;
    unsigned lenMsg2Plain =  KEYSIZE + LENSIZE + LenB + NONCELEN + LENSIZE + lenTktCipher ;

    if ( lenMsg2Plain > PLAINTEXT_LEN_MAX  )  
    {
        fprintf( log , "Plaintext of MSG2 too big %u bytes( max is %u ) to encrypt in MSG2_new "
                       " ... EXITING\n" , lenMsg2Plain , PLAINTEXT_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext of MSG2 is too big in MSG2_new\n" );
    }

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || Na || lenTktCipher || TktCipher

    // Reuse the moving pointer 'p' , but now to contsruct plaintext of MSG2
    p = plaintext ;    

    //  ... some code ..... Copying Ks into plaintext buffer
    memcpy( p , Ks , KEYSIZE ) ;                        

    //  ... some code ..... Copying L(IDb) and IDb into plaintext buffer
    p += KEYSIZE ; 
    lenPtr = (unsigned *) p  ;   *lenPtr = LenB ;       
    p += LENSIZE ;
    memcpy( p , IDb , LenB );

    //  ... some code ..... Copying Na into the plaintext buffer
    p += LenB ;
    memcpy( p , Na , NONCELEN ) ;                         

    //  ... some code .....  Copying lenTktCipher and TktCipher into the plaintext buffer
    p += NONCELEN;
    lenPtr = (unsigned *) p  ;   *lenPtr = lenTktCipher ;       
    p += LENSIZE ;
    memcpy( p , TktCipher , lenTktCipher );
   
    // Now, encrypt Message 2 using Ka
    unsigned LenMsg2 = encrypt( plaintext , lenMsg2Plain, Ka->key, Ka->iv, ciphertext ) ;

    *msg2 = malloc( LenMsg2 ) ;
    if( *msg2 == NULL ) 
    {
        fprintf( log , "Out of Memory allocating %u bytes for MSG2 Ciphertext"
                       " in MSG2_new ... EXITING\n" , LenMsg2 );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for Ciphertext of MSG2 in MSG2_new\n" );
    }

    // Copy the encrypted ciphertext to Caller's msg2 buffer.
    memcpy( *msg2 , ciphertext , LenMsg2 ) ;

    fprintf( log , "The following new Encrypted MSG2 ( %u bytes ) has been"
                   " created by MSG2_new():  \n" , LenMsg2 ) ;
    BIO_dump_indent_fp( log , *msg2 , LenMsg2 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    fprintf( log ,"This is the new MSG2 ( %u Bytes ) before Encryption:\n" , lenMsg2Plain);

    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , KEYSIZE );
    BIO_dump_indent_fp ( log , (const char *) Ks, sizeof( myKey_t ) , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    IDb (%u Bytes) is:\n" , LenB );
    BIO_dump_indent_fp ( log , IDb , LenB , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN );
    BIO_dump_indent_fp ( log , (const char *) Na , NONCELEN , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Encrypted Ticket (%u Bytes) is\n" , lenTktCipher );
    BIO_dump_indent_fp ( log , TktCipher, lenTktCipher , 4 ) ;  fprintf( log , "\n") ; 


    return LenMsg2 ;    

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , unsigned *lenTktCipher , uint8_t **tktCipher )
{
    // CODE FROM pa-04 PART ONE

    return ;  
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from files
// Return:  1 on success, or 0 on failure

int getMasterKeyFromFiles( char *keyF , char *ivF , myKey_t *x )
{
    int   fd_key , fd_iv ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }
    read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ;
    close( fd_key ) ;

    fd_iv = open(ivF , O_RDONLY )  ;
    if( fd_iv == -1 ) 
    { 
        fprintf( stderr , "\nCould not open IV file '%s'\n" , ivF ); 
        return 0 ; 
    }
    read ( fd_iv , x->iv , INITVECTOR_LEN ) ;
    close( fd_iv ) ;
    
    return 1;  //  success
}


//***********************************************************************
// PA-04  Part  Two
//***********************************************************************

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are unsigned integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

unsigned MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t *Na )
{
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG1 New\n");
    fprintf( log , "**************************\n\n");

    // MUST always check none of the incoming pointers is NULL
    if (log == NULL || msg1 == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
        fprintf( log , "NULL pointer(s) passed to MSG1_new() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG1_new()" );
    }

    unsigned  LenA    = strlen( IDa ) + 1 ;
    unsigned  LenB    = strlen( IDb ) + 1 ;
    unsigned  LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + NONCELEN;
    unsigned *lenPtr ; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg1 = malloc (LenMsg1);
    if( *msg1 == NULL ) 
    {
        fprintf( log , "Out of Memory allocating %u bytes for MSG1"
                       " in MSG1_new ... EXITING\n" , LenMsg1 );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for IDa of MSG1 in MSG1_new\n" );
    }

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;

    // Copying Len(IDa) and IDa into msg1
    lenPtr = (unsigned *) p;
    *lenPtr = LenA;
    p += LENSIZE;
    memcpy(p, IDa, LenA);
    p += LenA;

    // Copying Len(IDb) and IDb into msg1
    lenPtr = (unsigned *) p;
    *lenPtr = LenB;
    p += LENSIZE;
    memcpy(p, IDb, LenB);
    p += LenB;

    // Copying Na into msg1
    memcpy(p, Na, NONCELEN);

    fprintf( log , "The following new MSG1 ( %u bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    BIO_dump_indent_fp(log, *msg1, LenMsg1, 4);    fprintf( log , "\n" ) ;  

    fflush( log ) ;
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t *Na )
{
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG1 Receive\n");
    fprintf( log , "**************************\n\n");

    if (log == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
        fprintf( log , "NULL pointer(s) passed to  MSG1_receive() ... EXITING\n"  );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG1_receive()" );
    }

    unsigned LenMsg1 , LenA , LenB ;
   
    // Read in the components of Msg1:  L(A)  ||  A   ||  L(B)  ||  B   ||  Na
    // 1) Read Len(IDa)  
    if ( read( fd , &LenA , LENSIZE  ) !=  LENSIZE  )
    {
        fprintf( log , "Unable to read all %lu bytes of Len(IDa) from FD %d in "
                       "MSG1_receive() ... EXITING\n" , LENSIZE , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    // 2) Allocate memory for, and Read IDa
    *IDa = malloc (LenA);
    if( *IDa == NULL ) 
    {
        fprintf( log , "Out of Memory allocating %u bytes for MSG1 IDa"
                       " in MSG1_receive ... EXITING\n" , LenA );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for IDa of MSG1 in MSG1_receive\n" );
    }

    if ( read( fd , *IDa , LenA  ) !=  LenA  )
    {
        fprintf( log , "Unable to read all %u bytes of IDa from FD %d in "
                       "MSG1_receive() ... EXITING\n" , LenA , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    // 3) Read Len(IDb)
    if ( read( fd , &LenB , LENSIZE  ) !=  LENSIZE  )
    {
        fprintf( log , "Unable to read all %lu bytes of Len(IDb) from FD %d in "
                       "MSG1_receive() ... EXITING\n" , LENSIZE , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    // 4) Allocate memory for, and Read IDb
    *IDb = malloc (LenB);
    if( *IDb == NULL ) 
    {
        fprintf( log , "Out of Memory allocating %u bytes for MSG1 IDb"
                       " in MSG1_receive ... EXITING\n" , LenA );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for IDa of MSG1 in MSG1_receive\n" );
    }

    if ( read( fd , *IDb , LenB  ) !=  LenB  )
    {
        fprintf( log , "Unable to read all %u bytes of IDb from FD %d in "
                       "MSG1_receive() ... EXITING\n" , LenB , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    // 5) Read Na
    if ( read( fd , Na , NONCELEN  ) !=  NONCELEN  )
    {
        fprintf( log , "Unable to read all %lu bytes of Na from FD %d in "
                       "MSG1_receive() ... EXITING\n" , NONCELEN , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    // Computed LenMsg1 instead of reading from fd bc Aboutabl code never sends the LenMsg1
    LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + NONCELEN;

    fprintf( log , "MSG1 ( %u bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

unsigned MSG3_new( FILE *log , uint8_t **msg3 , const unsigned lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{
    unsigned LenMsg3 ;
    uint8_t  *p ;    
    unsigned *lenPtr ;    

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG3 New\n");
    fprintf( log , "**************************\n\n");
    if (log == NULL || msg3 == NULL || tktCipher == NULL || Na2 == NULL)
    {
        fprintf( log , "NULL pointer(s) passed to MSG3_new() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG3_new()" );
    }

    LenMsg3 = LENSIZE + lenTktCipher + NONCELEN;
    // Allocate memory for msg3. MUST always check malloc() did not fail
    *msg3 = malloc(LenMsg3);
    if (*msg3 == NULL)
    {
        fprintf( log , "Out of Memory allocating %u bytes for MSG3"
                       " in MSG3_new ... EXITING\n" , LenMsg3 );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for MSG3 in MSG3_new\n" );
    }

    // Fill in Msg3:  Len( TktCipher )  ||  TktCipher   ||  Na2
    p = *msg3 ;

    // Set lenTktCipher  and  tktCipher  components of Msg3
    lenPtr = (unsigned *) p;
    *lenPtr = lenTktCipher;
    p += LENSIZE;
    memcpy(p, tktCipher, lenTktCipher);
    p += lenTktCipher;

    // Set the Na component of MSG3
    memcpy(p, Na2, NONCELEN);

    fprintf( log , "The following new MSG3 ( %u bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    BIO_dump_indent_fp(log, *msg3, LenMsg3, 4);    fprintf( log , "\n" ) ;  

    fflush( log ) ;    

    return( LenMsg3 ) ;
}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{
    uint8_t  *tktCipher ;     
    unsigned  lenTktCipher , lenTktPlain ;
    unsigned *lenPtr , LenA , LenMsg3;    

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG3 Receive\n");
    fprintf( log , "**************************\n\n");
    if (log == NULL || Kb == NULL || Ks == NULL || IDa == NULL || Na2 == NULL)
    {
        fprintf( log , "NULL pointer(s) passed to MSG3_recieve() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG3_recieve()" );
    }
    fflush(log);

    // I) Read 1st part of MSG#3: The TicketCiphertext len and TicketCiphertext
    // into the global scratch buffer ciphertext[]. Make sure it fits
    if ( read( fd , &lenTktCipher , LENSIZE  ) !=  LENSIZE  )
    {
        fprintf( log , "Unable to read all %lu bytes of Len(TktCiphertext) from FD %d in "
                       "MSG3_receive() ... EXITING\n" , LENSIZE , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    if ( lenTktCipher > CIPHER_LEN_MAX )  
    {
        fprintf( log , "TicketCiphertext of MSG3 too big %u bytes( max is %u ) to fit into ciphertext[] in MSG3_receive "
                       " ... EXITING\n" , lenTktCipher , CIPHER_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext of MSG3 is too big in MSG3_receive\n" );
    }

    if ( read( fd , ciphertext , lenTktCipher  ) !=  lenTktCipher )
    {
        fprintf( log , "Unable to read all %u bytes of TicketCiphertext from FD %d in "
                       "MSG3_receive() ... EXITING\n" , lenTktCipher , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }
    fprintf( log ,"The following Encrypted TktCipher ( %d bytes ) was received "
                  "via FD %d by MSG3_receive()\n" , lenTktCipher , fd );
    BIO_dump_indent_fp(log, ciphertext, lenTktCipher, 4);    fprintf( log , "\n" ) ;  
    fflush(log);

    // I.1) Decrypt the ticket into the global scratch buffer decryptext[]. Make sure it fits
    if ( lenTktPlain > PLAINTEXT_LEN_MAX )  
    {
        fprintf( log , "TicketPlaintext of MSG3 too big %u bytes( max is %u ) to decrypt in MSG3_receive "
                       " ... EXITING\n" , lenTktPlain , DECRYPTED_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nTicketPlaintext of MSG3 is too big in MSG3_receive\n" );
    }
    lenTktPlain =  decrypt(ciphertext, lenTktCipher, Kb->key, Kb->iv, decryptext);

    fprintf( log ,"Here is the Decrypted Ticket ( %d bytes ) in MSG3_receive():\n" , lenTktPlain ) ;
    BIO_dump_indent_fp(log, decryptext, lenTktPlain, 4);    fprintf( log , "\n" ) ;
    fflush(log);  

    // Start parsing the Ticket into the Caller-provided arguments
    uint8_t  *p = decryptext ;

    // I.2) Parse the session key Ks and copy it to caller's buffer
    memcpy(Ks, p, KEYSIZE);
    p += KEYSIZE;

    // I.3) Parse IDA    
    //     I.3.1) Allocate buffer for the caller to hold IDA
    //     I.3.2)  Copy IDA to caller's buffer
    lenPtr = (unsigned *) p    ;   LenA  = *lenPtr    ;          p += LENSIZE ;
    *IDa = malloc (LenA);
    if (*IDa == NULL)
    {
        fprintf( log , "Out of Memory allocating %u bytes for IDa"
                       " in MSG3_recieve ... EXITING\n" , LenA );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for IDa of MSG3 in MSG3_recieve\n" );   
    }
    memcpy( *IDa, p, LenA )  ; 
    p += LenA;

    // II) Finally, read the last part of MSG3: Na2
    if ( read( fd , Na2 , NONCELEN  ) !=  NONCELEN)
    {
        fprintf( log , "Unable to read all %lu bytes of Na2 from FD %d in "
                       "MSG3_receive() ... EXITING\n" , NONCELEN , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    } 

    return ;
}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

unsigned MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{
    uint8_t  *p ;    
    unsigned *lenPtr , LenMsg4 , lenPlaintext;

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG4 New\n");
    fprintf( log , "**************************\n\n");
    if (log == NULL, msg4 == NULL || Ks == NULL || fNa2 == NULL || Nb == NULL) 
    {
        fprintf( log , "NULL pointer(s) passed to MSG4_new() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG4_new()" );
    }
    fflush(log);

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values
    lenPlaintext = NONCELEN + NONCELEN;
    p = plaintext;

    // Copy f(Na2) into plaintext buffer
    memcpy( p , fNa2 , NONCELEN ) ;                        
    p += NONCELEN ;

    // Copy Nb into plaintext buffer
    memcpy( p , Nb , NONCELEN ) ;                        
    p += NONCELEN ;
    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result.  Make sure it fits.
    if ( lenPlaintext > PLAINTEXT_LEN_MAX )  
    {
        fprintf( log , "Plaintext of MSG4 too big %u bytes( max is %u ) to encrypt in MSG4_new "
                       " ... EXITING\n" , lenTktPlain , DECRYPTED_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext of MSG4 is too big in MSG4_new\n" );
    }
    LenMsg4 = encrypt( plaintext, lenPlaintext, Ks->key, Ks->iv , ciphertext );

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    *msg4 = malloc( LenMsg4 ) ;
    if( *msg4 == NULL ) 
    {
        fprintf( log , "Out of Memory allocating %u bytes for MSG4 Ciphertext"
                       " in MSG4_new ... EXITING\n" , LenMsg4 );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for Ciphertext of MSG4 in MSG4_new\n" );
    }

    memcpy( *msg4 , ciphertext , LenMsg4 ) ;                           

    fprintf( log , "The following new Encrypted MSG4 ( %u bytes ) has been"
                   " created by MSG4_new ():  \n" , LenMsg4 ) ;
    BIO_dump_indent_fp(log, *msg4, LenMsg4, 4);    fprintf( log , "\n" ) ;  

    fflush( log ) ;    

    return LenMsg4 ;
}

// //-----------------------------------------------------------------------------
// // Receive Message #4 by Amal from Basim
// // Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{
    // MSG4 = Encr( Ks ,  { f(Na2) || Nb }  ) by Basim

    uint8_t  *p ;    
    unsigned  LenMsg4 , LenMSG4cipher  ;

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG4 Receive\n");
    fprintf( log , "**************************\n\n");
    if (log == NULL || Ks == NULL || rcvd_fNa2 == NULL || Nb == NULL)
    {
        fprintf( log , "NULL pointer(s) passed to MSG4_recieve() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG4_recieve()" );
    }

    // Read Len( Msg4 ) followed by reading Msg4 itself
    // Always make sure read() and write() succeed    
    // Use the global scratch buffer ciphertext[] to receive MSG4. Make sure it fits. 
    if ( read( fd , &LenMSG4cipher , LENSIZE  ) !=  LENSIZE  )
    {
        fprintf( log , "Unable to read all %lu bytes of Len(MSG4) from FD %d in "
                       "MSG4_receive() ... EXITING\n" , LENSIZE , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }
    if ( LenMSG4cipher > CIPHER_LEN_MAX )  
    {
        fprintf( log , "Ciphertext of MSG4 too big %u bytes( max is %u ) to fit into ciphertext[] in MSG4_receive "
                       " ... EXITING\n" , LenMSG4cipher , CIPHER_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nCiphertext of MSG4 is too big in MSG4_receive\n" );
    }

    if ( read( fd , ciphertext , LenMSG4cipher  ) !=  LenMSG4cipher )
    {
        fprintf( log , "Unable to read all %u bytes of Msg4 from FD %d in "
                       "MSG3_receive() ... EXITING\n" , LenMSG4cipher , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    fprintf( log ,"\nThe following Encrypted MSG4 ( %u bytes ) was received"
                  " from FD %d :\n" , LenMSG4cipher , fd );
    BIO_dump_indent_fp(log, ciphertext, LenMSG4cipher, 4);    fprintf( log , "\n" ) ;  

    // Now, Decrypt MSG4 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption.
    // Make sure it fits.
    if ( LenMSG4cipher > CIPHER_LEN_MAX )  
    {
        fprintf( log , "Ciphertext of MSG4 too big %u bytes( max is %u ) to decrypt in MSG4_receive "
                       " ... EXITING\n" , LenMSG4cipher , CIPHER_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nCiphertext of MSG4 is too big in MSG4_receive\n" );
    }
    LenMsg4 = decrypt(ciphertext, LenMSG4cipher, Ks->key, Ks->iv, decryptext);

    // Parse MSG4 into its components f( Na2 ) and Nb
    p = decryptext;

    // Parse f(Na2) and copy it into buffer
    memcpy(rcvd_fNa2, p, NONCELEN);
    p += NONCELEN;

    // Parse Nb and copy it into buffer
    memcpy(Nb, p, NONCELEN);

    return ;
}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

unsigned MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    uint8_t  *p ;
    unsigned msg5PlainLen ;
    
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG5 New\n");
    fprintf( log , "**************************\n\n");
    if (log == NULL || msg5 == NULL || Ks == NULL || fNb == NULL)
    {
        fprintf( log , "NULL pointer(s) passed to MSG5_new() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG5_new()" );
    }

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 
    msg5PlainLen = NONCELEN;
    if ( msg5PlainLen > PLAINTEXT_LEN_MAX )  
    {
        fprintf( log , "Plaintext of MSG5 too big %u bytes( max is %u ) to fit into plaintext[] in MSG5_new "
                       " ... EXITING\n" , msg5PlainLen , PLAINTEXT_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext of MSG5 is too big in MSG5_new\n" );
    }

    p = plaintext;
    memcpy (p, fNb, NONCELEN);

    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.
    if ( msg5PlainLen > PLAINTEXT_LEN_MAX )  
    {
        fprintf( log , "Plaintext of MSG5 too big %u bytes( max is %u ) to encrypt in MSG5_new "
                       " ... EXITING\n" , msg5PlainLen , PLAINTEXT_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext of MSG5 is too big in MSG5_new\n" );
    }
    unsigned LenMSG5cipher = encrypt (plaintext, msg5PlainLen, Ks->key, Ks->iv, ciphertext);

    // Now allocate a LenMSG5cipher for the caller, and copy the encrypted MSG5 to it
    *msg5 = malloc(LenMSG5cipher);
    if (*msg5 == NULL)
    {
        fprintf( log , "Out of Memory allocating %u bytes for MSG5"
                       " in MSG5_new ... EXITING\n" , LenMSG5cipher );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for MSG5 in MSG5_new\n" );
    }
    memcpy(*msg5, ciphertext, LenMSG5cipher);
 
    fprintf( log , "The following new Encrypted MSG5 ( %u bytes ) has been"
                   " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    

    fflush( log ) ;    

    return LenMSG5cipher ;
    
}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{
    uint8_t  *p ;    
    unsigned  LenMsg5 , LenMSG5cipher , *lenPtr , LenNonce ;

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG5 Receive\n");
    fprintf( log , "**************************\n\n");
    if (log == NULL || Ks == NULL || fNb == NULL)
    {
        fprintf( log , "NULL pointer(s) passed to MSG5_recieve() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG5_recieve()" );
    }

    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    if ( read( fd , &LenMSG5cipher , LENSIZE  ) !=  LENSIZE  )
    {
        fprintf( log , "Unable to read all %lu bytes of Len(MSG5) from FD %d in "
                       "MSG5_receive() ... EXITING\n" , LENSIZE , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.
    if ( LenMSG5cipher > CIPHER_LEN_MAX )  
    {
        fprintf( log , "Ciphertext of MSG5 too big %u bytes( max is %u ) to fit into ciphertext[] in MSG5_receive "
                       " ... EXITING\n" , LenMSG5cipher , CIPHER_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nCiphertext of MSG5 is too big in MSG5_receive\n" );
    }
    if ( read( fd , ciphertext , LenMSG5cipher  ) !=  LenMSG5cipher  )
    {
        fprintf( log , "Unable to read all %u bytes of MSG5 from FD %d in "
                       "MSG5_receive() ... EXITING\n" , LenMSG5cipher , fd );
        
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    fprintf( log ,"The following Encrypted MSG5 ( %u bytes ) has been received"
                  " from FD %d :\n" , LenMSG5cipher , fd );

    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits
    if ( LenMSG5cipher > CIPHER_LEN_MAX )  
    {
        fprintf( log , "Ciphertext of MSG5 too big %u bytes( max is %u ) to decrypt in MSG5_receive "
                       " ... EXITING\n" , LenMSG5cipher , CIPHER_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nCiphertext of MSG5 is too big in MSG5_receive\n" );
    }
    LenMsg5 = decrypt(ciphertext, LenMSG5cipher, Ks->key, Ks->iv, decryptext);

    // Parse MSG5 into its components f( Nb )
    p = decryptext;
    memcpy(fNb, decryptext, NONCELEN);

    return ;
}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    r[0] = htonl( 1 + ntohl( n[0] ) ) ;
}

