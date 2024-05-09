#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>

#define MAX_PASSWORDS 15000000
#define MAX_PASSWORD_LENGTH 128

struct DiscoveredData {
    char *hash;
    int hashLine;
    char *passwd;
    int passwdLine;    
};

sem_t sem_ADD_BUFFER, sem_ADD_BUFFER_FINISHED;
pthread_mutex_t mutex_buffer;

int nThreads;
int feederStatus=0;

char **password_list;
int password_list_id=0;

int *searchHash(char* myHash) {
	struct DiscoveredData data;
	char *currentHash;
	char *currentpPasswd;
	int currentPasswdLine;
	int currentHashLine;
        while(1)
        {
        	//Verifica se buffer esta vazio sizeof(buffer) == 0
        	if()
        	{
        		//verifica se o feeder finalizou 
        		if(feederStatus == -1)        		
        			break;
        		else
        		{
        			sem_post(&sem_ADD_BUFFER);
        			sem_wait(&sem_ADD_BUFFER_FINISHED);        			
        		}
        	}
        	else
        	{
        		//Extrai 1 hash do buffer
			pthread_mutex_lock(&mutex_buffer);  
	    			//extrai hash do buffer estilo pilha.    
	   		pthread_mutex_unlock(&mutex_buffer);
	   	
			while()
			{
				
			   	if (strcmp(shadow_hash, new_hash) == 0) {
				    printf("Password found: %s\n", password_list[i]);
				    
				}
			   	 
			}
        	}
        }
    
	return 0;    
}

int *feeder(char* myHash) {       
	
	while(1)
	{
		//verifica se lista de senha esta vazia
		if(password_list[id] == NULL)
		{
			feederStatus = -1;
			return -1;
		}
		else
		{	
			sem_wait(&sem_ADD_BUFFER);
			pthread_mutex_lock(&mutex_buffer);        
		
			//edita buffer
			    //Le senha da lista de passwords
			    //retira senha da lista numThreads e da um realloc na lista
			    
			    //extrai salt do hash
			    //gera hash criptografado da senha com salt
			    //adiciona no buffer

			pthread_mutex_unlock(&mutex_buffer);
			sem_post(&sem_ADD_BUFFER_FINISHED);
			
			password_list_id += nThreads;
		}
	} 
    
}


int main(int argc, char* argv[]) {
    // The password hash from the shadow file (user-provided example)
    char *shadow_hash;
    char salt[12];
    
    printf("arg[0] = %s\n", argv[0]);
    printf("arg[1] = %s\n", argv[1]);
    printf("arg[2] = %s\n", argv[2]);
    if(argc < 3) {
        printf("Usage: %s <hash> <dict file>\n", argv[0]);
        return 1;
    }

    int npasswd = loadpasswd(argv[2]);
    printf("npass = %d\n", npasswd);
    
    shadow_hash = argv[1];    

    // Extracting the salt from the shadow_hash, it includes "$1$" and ends before the second "$"
    strncpy(salt, shadow_hash, 11);
    salt[11] = '\0';  // Ensure null termination

    for (int i=0; i<npasswd; i++) {
    	// em multithread use crypt_r(), pois crypt() não é threadsafe. 
        char *new_hash = crypt(password_list[i], salt);
        
        
    }

    printf("Password not found!\n");
    
    return 0;
}

int loadpasswd(const char* filename) {
    char passwd[MAX_PASSWORD_LENGTH];
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen(): ");
        return -1;
    }
    password_list = malloc(MAX_PASSWORDS * sizeof(char*));

    int i = 0;
    while (i < MAX_PASSWORDS && fgets(passwd, MAX_PASSWORD_LENGTH, file) != NULL) {
        passwd[strcspn(passwd, "\n")] = 0;  // Remove newline
        password_list[i] = strdup(passwd);
        i++;
    }

    fclose(file);
    return i;
}