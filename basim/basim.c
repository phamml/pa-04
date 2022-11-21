/*----------------------------------------------------------------------------
PA-04:  Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c         SKELETON  

Written By: 
     1- Mia Pham
     2- Emily Graff
Submitted on: 12-01-2022
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
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;
    myKey_t   Kb ;    // Basim's master key with the KDC    

    char *developerName = "Code by <<MIA PHAM>>" ;
    printf( "\nThis is Basim's   %s\n" ,  developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }
    fd_A2B    = atoi(argv[1]) ;  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]) ;  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    fprintf( log , "\nThis is Basim's %s\n" , developerName ) ;
    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    if( ! getMasterKeyFromFiles("./basim/basimKey.bin", "./basim/basimIV.bin", &Kb))
    { 
        fprintf( stderr , "\nCould not open Basim's Masker key files\n"); 
        fprintf( log , "\nCould not open Basim's Masker key files\n"); 
        fclose( log ) ; exit(-1) ; 
    }
    fprintf( log , "\nBasim has this Master Kb { key , IV }\n"  ) ;
    BIO_dump_indent_fp ( log , (const char *) Kb.key, SYMMETRIC_KEY_LEN, 4 );
    fprintf( log , "\n" );
    BIO_dump_indent_fp ( log , (const char *) Kb.iv, INITVECTOR_LEN, 4 );
    fprintf( log , "\n") ; 
    fflush(log);

    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    myKey_t   Ks ;    // Basim's session key with Amal
    char     *IDa;    // Amal's Identity
    Nonce_t   Na2;    // Amal's nonce to Basim.

    // Get MSG3 from Amal
    MSG3_receive( log, fd_A2B, &Kb, &Ks, &IDa, &Na2 ) ; 
    fprintf(log, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fflush(log);
    fprintf( log , "Basim received Message 3 from Amal on FD %d "
                   "with the following\n    Session Ks { Key , IV }\n" , fd_A2B  );
    BIO_dump_indent_fp ( log , (const char *) &Ks, sizeof( myKey_t ) , 4 );    fprintf( log , "\n" );   
    fflush(log);

    fprintf( log , "\nBasim also learned the following\n    IDa= '%s'\n" , IDa );
    
    fprintf( log , "    Na2 ( %lu Bytes ) is:\n" , NONCELEN );
    BIO_dump_indent_fp ( log , (const char *) Na2, NONCELEN, 4 );
    fflush(log);


    //*************************************
    // Construct & Send    Message 4
    //*************************************
    Nonce_t   fNa2 , Nb ;
    uint8_t  *msg4 ;
    unsigned  LenMsg4 ;

    // Compute fNa2 = f(Na2)
    fNonce(fNa2, Na2);
    fprintf(log, "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    fprintf( log , "\nBasim computed this f(Na2) for MSG4:\n") ;
    BIO_dump_indent_fp ( log , (const char *) fNa2, NONCELEN, 4 );
    fflush(log);

    // Create a random Nonce by B to challenge A
    RAND_bytes( (unsigned char *) Nb , NONCELEN  ); 
    fprintf( log , "Basim Created this nonce Nb for MSG4:\n") ;
    BIO_dump_indent_fp ( log , (const char *) Nb, NONCELEN, 4 );
    fflush(log);

    LenMsg4 = MSG4_new( log, &msg4, &Ks, &fNa2, &Nb) ;
    
    // Send MSG4  to  Amal
    if(( write( fd_B2A, &LenMsg4, LENSIZE) != LENSIZE ) 
        || ( write( fd_B2A, msg4, LenMsg4 ) != LenMsg4 ))
    {
        fprintf( log , "Unable to send all %lu bytes of of L(M4) || M4 from B to A"
                       "... EXITING\n" , LENSIZE+LenMsg4 ) ;
        
        fflush( log ) ;  fclose( log ) ;      free( msg4 )   ;
        exitError( "\nUnable to send MSG2 in KDC\n" );
    }
 
    fprintf( log , "Basim Sent the above MSG4 to Amal on FD %d\n" , fd_B2A );
    fflush( log ) ;
    
    free (msg4);
                  
    //*************************************
    // Receive   & Process Message 5
    //*************************************
    Nonce_t   fNb , fNbCpy;

    // Get MSG5 from Amal
    MSG5_receive( log, fd_A2B, &Ks, &fNbCpy ) ;
    
    fprintf(log, "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf( log , "\nBasim expecting back this fNb in MSG5:\n") ;
    fNonce(fNb, Nb);
    BIO_dump_indent_fp ( log , (const char *) fNb, NONCELEN, 4 );

                  
    fprintf( log , "Basim received Message 5 from Amal on FD %d with this f( Nb ) >>>> " , fd_A2B ) ;
    // Validate f( Nb ) 
    if ( memcmp(&fNb, &fNbCpy, NONCELEN) == 0 )
    {
        fprintf( log , "VALID\n" ) ;
    }
    else
    {
        fprintf( log , "INVALID >>>> NOT Exiting\n" ) ;
    }
    BIO_dump_indent_fp ( log , (const char *) fNbCpy, NONCELEN, 4 );
    fflush( log ) ;


    //*************************************   
    // Final Clean-Up
    //*************************************

    fprintf(log, "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
