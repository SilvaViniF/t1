#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <crypt.h>
#include <semaphore.h>

#define HASH_SIZE 37
#define MAX_THREADS 128
#define PASS_LENGTH 30
#define BUFFER_SIZE 500

char **salt_list;
char **password_list;
char **hash_list;
char **cracked_list;
int npasswd;
int nhashes;
int num_threads;
int *foundhashes;
char *buffer[BUFFER_SIZE];
int in = 0;
int out = 0;
int count = 0;
sem_t vazio;
sem_t cheio;
pthread_mutex_t mutex_buffer;
struct ThreadData {
    int thread_id;
    struct crypt_data *crypt_data;
};


int load_hashes(const char *filename) {
    char hash[HASH_SIZE];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen()");
        return -1;
    }

    hash_list = NULL;
    int i = 0;
    while (fscanf(file, "%s", hash) != EOF) {
        char *new_hash = strdup(hash);
        if (new_hash == NULL) {
            fprintf(stderr, "Memory allocation failed for hash %d.\n", i);
            while (i > 0) {
                free(hash_list[--i]);
            }
            free(hash_list);
            fclose(file);
            return -1;
        }
        hash_list = realloc(hash_list, (i + 1) * sizeof(char *));
        if (hash_list == NULL) {
            fprintf(stderr, "Memory reallocation failed for hash list.\n");
            fclose(file);
            return -1;
        }
        hash_list[i++] = new_hash;
    }

    fclose(file);
    return i;
}


int load_passwords(const char *filename) {
    char passwd[PASS_LENGTH];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen()");
        return -1;
    }

    password_list = NULL;
    int i = 0;
    
    while (fgets(passwd, PASS_LENGTH, file) != NULL) {
        passwd[strcspn(passwd, "\n")] = 0;
        char *new_password = strdup(passwd);
        if (new_password == NULL) {
            fprintf(stderr, "Memory allocation failed for password %d.\n", i);
            while (i > 0) {
                free(password_list[--i]);
            }
            free(password_list);
            fclose(file);
            return -1;
        }
        password_list = realloc(password_list, (i + 1) * sizeof(char *));
        if (password_list == NULL) {
            fprintf(stderr, "Memory reallocation failed for password list.\n");
            fclose(file);
            return -1;
        }
        password_list[i++] = new_password;
    }

    fclose(file);
    return i;
}


char *extract_salt(char *hash) {
    char *salt = malloc(12);
    strncpy(salt, hash, 11);
    salt[11] = '\0';
    return salt;
}

void *consumer(void *thread_arg) {
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    int tid = data->thread_id;
    char *salt;
    foundhashes[tid]=0;

    while(1){
        sem_wait(&cheio);
        pthread_mutex_lock(&mutex_buffer);
        salt = buffer[out]; 
        out = (out+1)%BUFFER_SIZE;
        count--;
        pthread_mutex_unlock(&mutex_buffer);
        sem_post(&vazio);

        if (salt == NULL) {
            break;
        }

        int found = 0;
        for(int i = 0; i < npasswd; i++){
            char *newhash = crypt_r(password_list[i], salt, data->crypt_data);
            for(int j = 0; j < nhashes; j++){
                if(strcmp(hash_list[j], newhash) == 0){                    
                    printf("Thread %d: found its %d password for hash %s: %s\n", tid,foundhashes[tid]+1, hash_list[j], password_list[i]);
                    cracked_list[j] = password_list[i];
                    foundhashes[tid]++;
                    found = 1;
                    
                    break;
                }
            }
            if(found) break;
        }
    }

    pthread_exit(NULL);
}
void *feeder() {
       char *item;
       for(int i = 0; i < nhashes; i++){
           item = salt_list[i];
           sem_wait(&vazio);
           pthread_mutex_lock(&mutex_buffer);
           buffer[in] = item;
           in = (in+1) % BUFFER_SIZE;
           count++;
           pthread_mutex_unlock(&mutex_buffer);
           sem_post(&cheio);
       }

       for (int i = 0; i < num_threads; i++) {
           sem_wait(&vazio);
           pthread_mutex_lock(&mutex_buffer);
           buffer[in] = NULL;
           in = (in+1) % BUFFER_SIZE;
           count++;
           pthread_mutex_unlock(&mutex_buffer);
           sem_post(&cheio);
       }
   }
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_threads> <dictionary_file>\n", argv[0]);
        return 1;
    }
   
    num_threads = atoi(argv[1]);
    if (num_threads <= 0 || num_threads > MAX_THREADS) {
        fprintf(stderr, "Invalid number of threads. Must be between 1 and %d\n", MAX_THREADS);
        return 1;
    }

    sem_init(&vazio, 0, BUFFER_SIZE);
    sem_init(&cheio, 0, 0);
    pthread_mutex_init(&mutex_buffer, NULL);

    nhashes = load_hashes("hashes.txt");
    cracked_list = malloc(nhashes * sizeof(char *));

    if (nhashes < 0) {
        return 1;
    }

    npasswd = load_passwords(argv[2]);
    if (npasswd < 0) {
        return 1;
    }

    pthread_t threads[num_threads];
    struct ThreadData thread_data[num_threads];
    struct crypt_data crypt_data[num_threads];

    for (int i = 0; i < num_threads; i++) {
        crypt_data[i].initialized = 0;
    }
    foundhashes=malloc(nhashes*sizeof(int));
    salt_list = malloc(nhashes * sizeof(char *));
    for (int i = 0; i < nhashes; i++) {
        salt_list[i] = extract_salt(hash_list[i]);
    }

    pthread_t producer;
    int pr = pthread_create(&producer, NULL, feeder, NULL);
    if (pr) {
        fprintf(stderr, "ERROR: return code from pthread_create() is %d\n", pr);
        return 1;
    }

    for (int t = 0; t < num_threads; t++) {
        thread_data[t].thread_id = t;
        thread_data[t].crypt_data = &crypt_data[t];

        int rc = pthread_create(&threads[t], NULL, consumer, (void *)&thread_data[t]);
        if (rc) {
            fprintf(stderr, "ERROR: return code from pthread_create() is %d\n", rc);
            return 1;
        }
    }


    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_join(producer, NULL);

     FILE *resultado;
    resultado = fopen("resultado.txt","w");
    if(resultado==NULL){
        printf("error creating file");
        return 1;
    }

    int totalfoundhashes=0;
    for(int i=0;i<num_threads;i++){
        totalfoundhashes+=foundhashes[i];
    }
    if (!foundhashes) {
        printf("Password not found for any hash!\n");
    } else {
        printf("\nHashes encontrados: %d\n",totalfoundhashes);
        for (int i = 0; i < totalfoundhashes; i++) {
            printf("%s\n", cracked_list[i]);
            cracked_list[i]=strcat(cracked_list[i],"\n");
            fputs(cracked_list[i],resultado);
        }
    }

   
    pthread_mutex_destroy(&mutex_buffer);

    return 0;
}
