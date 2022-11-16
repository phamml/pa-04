/*----------------------------------------------------------------------------
PA-04:  Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   kdc.c          SKELETON  

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
    int       fd_A2K , fd_K2A   ;
    FILE     *log ;
    
    char *developerName = "Code by <<YOUR FULL NAMEs IN UPPERCASE>>" ;
    printf ( "\nThis is the KDC's %s\n"  , developerName ) ;
    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }
    fd_A2K    = .....  ;  // Read from Amal   File Descriptor
    fd_K2A    = .....  ;  // Send to   Amal   File Descriptor

    log = fopen("kdc/logKDC.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is the KDC's %s. Could not create log file\n"  
                        , developerName ) ;
        exit(-1) ;
    }
    fprintf( log , "\nThis is the KDC's %s\n"  , developerName ) ;
    fprintf( log , "\t<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n" 
                 , fd_A2K , fd_K2A );
    fflush( log ) ;
    
    // Get Amal's master keys with the KDC
    myKey_t  Ka ,    // Amal's master key with the KDC
             Kb ;    // Basim's master key with the KDC

    if ( ! getMasterKeyFromFiles( /* ... */ ) )
    { 
        fprintf( stderr , "\nCould not open Amal's Masker key files\n"); 
        fprintf( log , "\nCould not open Amal's Masker key files\n"); 
        fclose( log ) ; exit(-1) ; 
    }
    fprintf( log , "\nAmal has this Master Ka { key , IV }\n"  ) ;
 
    //
    // .....  Missing Code
    //

    // Get Basim's master keys with the KDC
    if( ! getMasterKeyFromFiles( /* ... */ ) )
    { 
        fprintf( stderr , "\nCould not open Basim's Masker key files\n"); 
        fprintf( log , "\nCould not open Basim's Masker key files\n"); 
        fclose( log ) ; exit(-1) ; 
    }
    fprintf( log , "Basim has this Master Kb { key , IV }\n"  ) ;
 
    //
    // .....  Missing Code
    //

    fflush( log ) ;

    //*************************************
    // Receive  & Display   Message 1
    //*************************************
    char *IDa , *IDb ;
    Nonce_t  Na ;
    
    // Get MSG1 from Amal
    MSG1_receive( log , fd_A2K , &IDa , &IDb , &Na ) ;
    
    fprintf( log , "\nKDC received message 1 from Amal on FD %d with\n"
                   "    IDa ='%s' , IDb = '%s'\n" , fd_A2K , IDa , IDb ) ;
    fprintf( log , "    Na ( %lu Bytes ) is\n" , NONCELEN ) ;
    BIO_dump_indent_fp( log , (uCharPtr) Na , NONCELEN , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;

    //*************************************   
    // Construct & Send    Message 2
    //*************************************

    myKey_t  Ks ;    // Session key for Amal & Basim to use

    // Generate a new Random Session Key  { encryption key , IV }   
 
    //
    // .....  Missing Code
    //
   
    uint8_t *msg2 ;
    unsigned LenMsg2 ;
    
    // Create MSG2
    LenMsg2 = MSG2_new( /* ... */ ) ;
    
    free( IDa ) ;   free( IDb );  // These were allocated by MSG1_receive()

    // Send MSG2 to Amal
    // First, send Len( MSG1 )
    if( ( write( /* .. */  ) != /* .. */ ) )
    {
        fprintf( log , "Unable to send all %lu bytes of of Len( MSG2 ) in KDC"
                       "... EXITING\n" , sizeof( LenMsg2 ) ) ;
        
        fflush( log ) ;  fclose( log ) ;      free( msg2 )   ;
        exitError( "\nUnable to send Len( MSG2 ) in KDC\n" );
    }

    // Next, send body of MSG1 
    if( ( write( /* .. */ ) != /* ... */  ) )
    {
        fprintf( log , "Unable to send all %u bytes of of MSG2 in KDC"
                       "... EXITING\n" , LenMsg2 ) ;
        
        fflush( log ) ;  fclose( log ) ;      free( msg2 )   ;
        exitError( "\nUnable to send MSG2 in KDC\n" );
    }

    fprintf( log ,"The KDC sent the Encrypted MSG2 via FD=%d Successfully\n" , fd_K2A );
    fflush( log ) ;

    free( msg2 )   ;

    //*************************************   
    // Final Clean-Up
    //*************************************
    
    fprintf( log , "\nThe KDC has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  
    return 0 ;
}
