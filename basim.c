/*----------------------------------------------------------------------------
PA-04:  Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c         SKELETON  

Written By: 
     1-  M U S T      T Y P E     Y O U R     N A M E(s) 
Submitted on: 
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

    char *developerName = "Code by <<YOUR FULL NAME(s) IN UPPERCASE>>" ;
    printf( "\nThis is Basim's   %s\n" ,  developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }
    fd_A2B    = ...... ;  // Read from Amal   File Descriptor
    fd_B2A    = ...... ;  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    fprintf( log , "\nThis is Basim's %s\n" , developerName ) ;
    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    if( ! getMasterKeyFromFiles( /* .... */ ) )
    { 
        fprintf( stderr , "\nCould not open Basim's Masker key files\n"); 
        fprintf( log , "\nCould not open Basim's Masker key files\n"); 
        fclose( log ) ; exit(-1) ; 
    }
    fprintf( log , "\nBasim has this Master Kb { key , IV }\n"  ) ;
    BIO_dump_indent_fp ( log , /* key part */ );
    fprintf( log , "\n" );
    BIO_dump_indent_fp ( log , /* iv  part */ );
    fprintf( log , "\n") ; 

    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    myKey_t   Ks ;    // Basim's session key with Amal
    char     *IDa;    // Amal's Identity
    Nonce_t   Na2;    // Amal's nonce to Basim.

    // Get MSG3 from Amal
    MSG3_receive( /* ... */ ) ; 

    fprintf( log , "Basim received Message 3 from Amal on FD %d "
                   "with the following\n    Session Ks { Key , IV}\n" , fd_A2B  );
 
    //
    // .....  Missing Code
    //

    fprintf( log , "Basim also learned the following\n    IDa= '%s'\n" , IDa );
    fprintf( log , "    Na2 ( %lu Bytes ) is:\n" , NONCELEN );
 
    //
    // .....  Missing Code
    //


    //*************************************
    // Construct & Send    Message 4
    //*************************************
    Nonce_t   fNa2 , Nb ;
    uint8_t  *msg4 ;
    unsigned  LenMsg4 ;

    // Compute fNa2 = f(Na2)
 
    fprintf( log , "Basim computed this f(Na2) for MSG4:\n") ;
    //
    // .....  Missing Code
    //
 
    // Create a random Nonce by B to challenge A
    RAND_bytes( /* ... */ ); 
    fprintf( log , "Basim Created this nonce Nb for MSG4:\n") ;
    //
    // .....  Missing Code
    //

    LenMsg4 = MSG4_new( /* ... */ ) ;
    
    // Send MSG4  to  Amal
    write( /* ... */ ) ;
    write( /* ... */ );
 
    fprintf( log , "Basim Sent the above MSG4 to Amal on FD %d\n" , fd_B2A );
    fflush( log ) ;

    //
    // .....  Missing Code
    //
                  
    //*************************************
    // Receive   & Process Message 5
    //*************************************
    Nonce_t   fNb , fNbCpy;

    // Get MSG5 from Amal
    MSG5_receive( /* ... */ ) ;
    
    fprintf( log , "\nBasim expecting back this fNb in MSG5:\n") ;
    // Compute fNbCpy = f( Nb ) and dump it to log file
    //
    // .....  Missing Code
    //
                  
    fprintf( log , "Basim received Message 5 from Amal on FD %d with this f( Nb ) >>>> " , fd_A2B ) ;
    // Validate f( Nb ) 
    if ( /* fNb is the same as fNbCpy   .. use memcmp() */ )  )
    {
        fprintf( log , "VALID\n" ) ;
    }
    else
    {
        fprintf( log , "INVALID >>>> NOT Exiting\n" ) ;
    }
    // Dump received fNb to log file
    fflush( log ) ;


    //*************************************   
    // Final Clean-Up
    //*************************************

    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
