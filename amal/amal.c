/*----------------------------------------------------------------------------
PA-04:  Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c           

Written By: 
     1- Emily Graff
     2 - Mia Pham
Submitted on: 12.01.22
----------------------------------------------------------------------------*/
#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    int      fd_A2K , fd_K2A , fd_A2B , fd_B2A  ;
    FILE    *log ;

    
    char *developerName = "Code By:  <<EMILY GRAFF>>" ;
    
    printf( "\nThis is Amal's    %s\n" , developerName ) ;
    
    if( argc < 5 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. KDC> <sendTo KDC> "
               "<getFr. Basim> <sendTo Basim>\n\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_K2A    = atoi( argv[1] ) ;  // Read from KDC    File Descriptor
    fd_A2K    = atoi( argv[2] ) ;  // Send to   KDC    File Descriptor
    fd_B2A    = atoi( argv[3] ) ;  // Read from Basim  File Descriptor
    fd_A2B    = atoi( argv[4] ) ;  // Send to   Basim  File Descriptor

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nThis is Amal's %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }
    fprintf( log , "\nThis is Amal's %s.\n" , developerName  ) ;

    fprintf( log , "\n<readFr. KDC> FD=%d , <sendTo KDC> FD=%d , "
                   "<readFr. Basim> FD=%d , <sendTo Basim> FD=%d\n" , 
                   fd_K2A , fd_A2K , fd_B2A , fd_A2B );

    // Get Amal's master key with the KDC
    myKey_t  Ka ;  // Amal's master key with the KDC

    if( ! getMasterKeyFromFiles( "amal/amalKey.bin" , "amal/amalIV.bin" , &Ka ) )
    { 
        fprintf( stderr , "\nCould not open Amal's Masker key files\n"); 
        fprintf( log , "\nCould not open Amal's Masker key files\n"); 
        fclose( log ) ; exit(-1) ; 
    }
    fprintf( log , "\nAmal has this Master Ka { key , IV }\n"  ) ;
    BIO_dump_indent_fp ( log , (uCharPtr) Ka.key, SYMMETRIC_KEY_LEN , 4 );
    fprintf( log , "\n" );
    BIO_dump_indent_fp ( log , (uCharPtr) Ka.iv , INITVECTOR_LEN , 4 );
    fprintf( log , "\n") ; 
        

    fflush( log ) ;

    //*************************************
    // Construct & Send    Message 1
    //*************************************
    char     *IDa = "Quidquid latine dictum sit, altum videtur." ,  *IDb = "Anything said in Latin sounds profound." ;
    Nonce_t   Na;  

    // Create a random nonce Na
    RAND_bytes( (unsigned char *) Na , NONCELEN  );  // First Nonce by A  
 
    unsigned  LenMsg1 ;
    uint8_t  *msg1 ;
    LenMsg1 = MSG1_new( log , &msg1 , IDa , IDb , &Na ) ;
    
    // Send MSG1 to KDC
    write( fd_A2K, msg1, LenMsg1 ) ;

    fprintf(log, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf( log , "Amal sent message 1 ( %d bytes ) to the KDC on FD %d with\n"
                   "    IDa ='%s' , IDb = '%s'\n" , LenMsg1 , fd_A2K , IDa , IDb ) ;
    fprintf( log , "    Na ( %lu Bytes ) is\n" , NONCELEN ) ;
    BIO_dump_indent_fp ( log , (const char *) Na, NONCELEN, 4 );
    fflush(log);

    free(msg1);

    //*************************************
    // Receive   &   Process Message 2
    //*************************************
    unsigned lenIDb = strlen(IDb) + 1;

    myKey_t   Ks ;       // Amal's session key with Basim. Created by the KDC   
    char     *IDb2 ;     // IDb as received from KDC .. must match what was sent in MSG1
    Nonce_t   NaCpy ;
    uint8_t  *tktCipher ;
    unsigned  lenTktCipher , LenKs= sizeof( myKey_t ) ;

    MSG2_receive( log , fd_K2A, &Ka, &Ks, &IDb2, &NaCpy, &lenTktCipher, &tktCipher );

    fprintf(log, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf( log , "Amal received the following in MSG2 from the KDC\n");
    fflush(log);

    fprintf( log , "    Ks { Key , IV } (%u Bytes ) is:\n" , LenKs );
    BIO_dump_indent_fp ( log , (const char *) &Ks, sizeof( myKey_t ) , 4 );    fprintf( log , "\n" );   

    fprintf( log , "    IDb (%u Bytes):" , lenIDb ) ;

    // Verify the strings IDb = IDb2 both in length and content
    if( strlen(IDb) != strlen(IDb2) && strcmp(IDb, IDb2) != 0 )
        fprintf( log , "   ..... MISMATCH .. but NOT Exiting\n" );
    else
        fprintf( log , "   ..... MATCH\n" );

    BIO_dump_indent_fp ( log , IDb2 , lenIDb , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log , "    Received Copy of Na (%lu bytes):" , NONCELEN ) ;
    // Verify Na == NaCpy    
    if( memcmp(&Na, &NaCpy, NONCELEN) == 0 )
        fprintf( log , "    ..... VALID\n" ) ;
    else
        fprintf( log , "    ..... INVALID ... but NOT Exiting\n" ) ;

    BIO_dump_indent_fp ( log , (const char *) &NaCpy , NONCELEN , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log , "    Encrypted Ticket (%d bytes):\n" , lenTktCipher ) ;
    BIO_dump_indent_fp ( log , (const char *) tktCipher, lenTktCipher, 4 );       fprintf( log , "\n") ;

    free( IDb2 ) ;  // It was allocated memory by MSG2_receive()
    fflush( log ) ;


    //*************************************
    // Construct & Send    Message 3
    //*************************************
    Nonce_t   Na2 ;
    unsigned  LenNa2 = NONCELEN , LenMsg3 ;
    uint8_t  *msg3 ;

    // Create Second Nonce Na2 by A to challenge B
    RAND_bytes( (unsigned char *) Na2 , NONCELEN  ); 
    fprintf( log , "Amal Created this nonce Na2 for MSG3:\n") ;
    BIO_dump_indent_fp ( log , (const char *) Na2, NONCELEN, 4 );
    fflush(log);

    LenMsg3 = MSG3_new( log, &msg3, lenTktCipher, tktCipher, &Na2 ) ;
    
    // Send MSG3 to Basim
    if(write( fd_A2B, msg3, LenMsg3 ) != LenMsg3 )
    {
        fprintf( log , "Unable to send all %u bytes of of L(M3) || M3from A to B"
                       "... EXITING\n" ,LenMsg3 ) ;
        
        fflush( log ) ;  fclose( log ) ;      free( msg3 )   ;
        exitError( "\nUnable to send MSG4 in KDC\n" );
    }

    fprintf(log, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf( log , "Amal Sent MSG3 ( %u bytes ) to Basim on FD %d:\n" , LenMsg3 , fd_A2B ) ;
 
    fflush( log ) ;
    // free(msg1);

    //*************************************
    // Receive   & Process Message 4
    //*************************************
    Nonce_t   rcvd_fNa2 , my_fNa2 , Nb ;

    fNonce(my_fNa2, Na2);
 
    // Get MSG4 from Basim
    MSG4_receive( log, fd_B2A, &Ks, &rcvd_fNa2, &Nb) ;    
    fprintf(log, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf( log , "\nAmal is expecting back this f( Na2 ) in MSG4:\n") ;
    BIO_dump_indent_fp ( log , (const char *) my_fNa2, NONCELEN, 4 );
    fflush(log);

    fprintf( log , "Basim returned the following f( Na2 )   >>>> " ) ;
    if ( memcmp(&my_fNa2, &rcvd_fNa2, NONCELEN) == 0 )
        fprintf( log , "VALID\n" ) ;
    else
        fprintf( log , "INVALID >>>> NOT Exiting)\n" ) ;
    
    BIO_dump_indent_fp ( log , (const char *) rcvd_fNa2, NONCELEN, 4 );
    fflush(log);

       
    fprintf( log , "Amal also received this Nb :\n"  ) ;
    BIO_dump_indent_fp ( log , (const char *)  Nb, NONCELEN, 4 );
    fprintf(log, "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");

    //*************************************
    // Construct & Send    Message 5
    //*************************************
    Nonce_t   fNb ;
    unsigned  LenMsg5 ;
    uint8_t  *msg5 ;

    // Compute fNb = f(Nb)
    fNonce(fNb, Nb);

    fprintf( log , "Amal computed this F(Nb) for MSG5:\n") ;
    BIO_dump_indent_fp ( log , (const char *) fNb, NONCELEN, 4 );


    LenMsg5 = MSG5_new( log, &msg5,  &Ks, &fNb  ) ;
    
    // Send MSG5 to Basim
     if(( write( fd_A2B, &LenMsg5, LENSIZE) != LENSIZE ) 
        || ( write( fd_A2B, msg5, LenMsg5 ) != LenMsg5 ))
    {
        fprintf( log , "Unable to send all %lu bytes of of L(M5) || M5 from A to B"
                       "... EXITING\n" , LENSIZE+LenMsg5 ) ;
        
        fflush( log ) ;  fclose( log ) ;      free( msg5 )   ;
        exitError( "\nUnable to send MSG5 in KDC\n" );
    }

     fprintf(log, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
     fprintf( log , "Amal Sending the above Message 5 ( %u bytes ) to Basim on FD %d\n"
                   , LenMsg5 , fd_A2B );
    fprintf(log, "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fflush(log);


    //*************************************   
    // Final Clean-Up
    //*************************************
   
    fprintf( log , "\nAmal has terminated normally. Goodbye\n" ) ;  
    fclose( log ) ;
    return 0 ;
}
