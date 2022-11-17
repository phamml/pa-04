/*-------------------------------------------------------------------------------
PA-03: The Enhanced Needham-Schoeder Protocol

FILE:   dispatcher.c

Written By: 
    1- Mia Pham
    2- Emily Graff
Submitted on: 
    12-02-2022
-------------------------------------------------------------------------------*/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "wrappers.h"

#define   READ_END	0
#define   WRITE_END	1
#define   STDIN  0
#define   STDOUT 1
//--------------------------------------------------------------------------
int main( int argc , char *argv[] )
{
    pid_t  amalPID , basimPID , kdcPID; 
    int    AtoKDC_pipe[2];  // Amal-to-KDC pipe
    int    KDCtoA_pipe[2];  // KDC-to-Amal pipe
    int    AtoB_pipe[2];    // Amal-to-Basim pipe 
    int    BotA_pipe[2];    // Basim-to-Amal pipe


    char   arg1[20] , arg2[20] ,arg3[20], arg4[20];
    
    Pipe( AtoKDC_pipe );  // create pipe for Amal-to-KDC 
    Pipe( KDCtoA_pipe );  // create pipe for KDC-to-Amal
    Pipe( AtoB_pipe );    // create pipe for Amal-to-Basim
    Pipe( BotA_pipe );    // create pipe for Basim-to-Amal

    printf("\nDispatcher started and created these 4 pipes\n") ;
    printf("Amal-to-KDC pipe: read=%d  write=%d\n", AtoKDC_pipe[READ_END] , AtoKDC_pipe[WRITE_END] ) ;
    printf("KDC-to-Amal pipe: read=%d  write=%d\n", KDCtoA_pipe[READ_END] , KDCtoA_pipe[WRITE_END] ) ;
    printf("Amal-to-Basim pipe: read=%d  write=%d\n", AtoB_pipe[READ_END] , AtoB_pipe[WRITE_END] ) ;
    printf("Basim-to-Amal pipe: read=%d  write=%d\n", BotA_pipe[READ_END] , BotA_pipe[WRITE_END] ) ;


    // Create three child processes:
    kdcPID = Fork() ;
    if ( kdcPID == 0 )
    {
        // This is the KDC process
        // KDC will not use these ends of the pipes, decrement their 'count'
        close( KDCtoA_pipe[READ_END] ) ;
        close( AtoKDC_pipe[WRITE_END] ) ;

        // Prepare the file descriptors as args to Basim
        snprintf( arg1 , 20 , "%d" , AtoKDC_pipe[READ_END] ) ;
        snprintf( arg2 , 20 , "%d" , KDCtoA_pipe[WRITE_END] ) ;

        char * cmnd = "./kdc/kdc" ;
        execlp( cmnd , "Kdc" , arg1 , arg2 , NULL );

        // the above execlp() only returns if an error occurs
        perror("ERROR starting KDC" ) ;
        exit(-1) ;
    }
    else
    {
        amalPID = Fork() ;
        if ( amalPID == 0 )
        {    
            // This is the Amal process.
            // Amal will not use these ends of the pipes, decrement their 'count'
            close( AtoB_pipe[READ_END]  ) ;
            close( BotA_pipe[WRITE_END]  ) ;
            close( AtoKDC_pipe[READ_END]  ) ;
            close( KDCtoA_pipe[WRITE_END]  ) ;
            
            // Prepare the file descriptors as args to Amal
            snprintf( arg1 , 20 , "%d" , KDCtoA_pipe[READ_END] ) ;
            snprintf( arg2 , 20 , "%d" , AtoKDC_pipe[WRITE_END] ) ;
            snprintf( arg3 , 20 , "%d" , BotA_pipe[READ_END] ) ;
            snprintf( arg4 , 20 , "%d" , AtoB_pipe[WRITE_END] ) ;
            
            // Now, Start Amal
            char * cmnd = "./amal/amal" ;
            execlp( cmnd , "Amal" , arg1 , arg2 , arg3 , arg4, NULL );

            // the above execlp() only returns if an error occurs
            perror("ERROR starting Amal" );
            exit(-1) ;      
        }
        else
        {
             // This is still the Dispatcher process 
            basimPID = Fork() ;
            if ( basimPID == 0 )
            {  
                // This is the Basim process
                // Basim will not use these ends of the pipes, decrement their 'count'
                close( BotA_pipe[READ_END] ) ;
                close( AtoB_pipe[WRITE_END] ) ;
                
                // Prepare the file descriptors as args to Basim
                snprintf( arg1 , 20 , "%d" , AtoB_pipe[READ_END] ) ;
                snprintf( arg2 , 20 , "%d" , BotA_pipe[WRITE_END] ) ;

                char * cmnd = "./basim/basim" ;
                execlp( cmnd , "Basim" , arg1 , arg2 , NULL );

                // the above execlp() only returns if an error occurs
                perror("ERROR starting Basim" ) ;
                exit(-1) ;
            }
            else
            {
                // This is still the parent Dispatcher process
                // close all ends of the pipes so that their 'count' is decremented
                close( AtoB_pipe[WRITE_END] ); 
                close( AtoB_pipe[READ_END]  );   
                close( BotA_pipe[WRITE_END] ); 
                close( BotA_pipe[READ_END]  ); 
                close( AtoKDC_pipe[WRITE_END] ); 
                close( AtoKDC_pipe[READ_END]  );     
                close( KDCtoA_pipe[WRITE_END] ); 
                close( KDCtoA_pipe[READ_END]  );   

                printf("\nDispatcher is now waiting for Amal to terminate\n") ;
                int  exitStatus ;
                waitpid( amalPID , &exitStatus , 0 ) ;
                printf("\nAmal terminated ... "  ) ;
                if (  WIFEXITED( exitStatus ) )
                        printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\nDispatcher is now waiting for Basim to terminate\n") ;
                waitpid( basimPID , &exitStatus , 0 ) ;
                printf("\nBasim terminated ... " ) ;
                if (  WIFEXITED( exitStatus ) )
                        printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;
                
                printf("\nDispatcher is now waiting for KDC to terminate\n") ;
                waitpid( kdcPID , &exitStatus , 0 ) ;
                printf("\nKDC terminated ... " ) ;
                if (  WIFEXITED( exitStatus ) )
                        printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\nThe Dispatcher process has terminated\n") ;     
            } 
        }
    }  
}

