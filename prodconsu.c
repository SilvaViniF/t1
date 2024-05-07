#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <crypt.h>

#define MAX_HASHES 1000
#define MAX_PASSWORDS 15000000
#define MAX_PASSWORD_LENGTH 128
#define MAX_THREADS 128
#define BUFFER_SIZE 100

char **password_list;
char **hash_list;
char **cracked_list;
int npasswd;
int nhashes;
int foundhashes = 0;
pthread_mutex_t mutex;
pthread_cond_t buffer_not_full = PTHREAD_COND_INITIALIZER;
pthread_cond_t buffer_not_empty = PTHREAD_COND_INITIALIZER;

struct ThreadData {
    int thread_id;
    struct crypt_data *crypt_data;
};

struct Buffer {
    char *password;
    int index;
};

struct Buffer buffer[BUFFER_SIZE];
int in = 0, out = 0, count = 0;

// Function to load the list of hashes from the file
int load_hashes(const char *filename) {
    char hash[MAX_PASSWORD_LENGTH];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen()");
        return -1;
    }

    hash_list = malloc(MAX_HASHES * sizeof(char *));
    int i = 0;
    while (i < MAX_HASHES && fscanf(file, "%s", hash) != EOF) {
        hash_list[i] = strdup(hash);
        i++;
    }

    fclose(file);
    return i;
}

// Function to load the list of passwords from the file
int load_passwords(const char *filename) {
    char passwd[MAX_PASSWORD_LENGTH];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen()");
        return -1;
    }

    password_list = malloc(MAX_PASSWORDS * sizeof(char *));
    if (password_list == NULL) {
        fprintf(stderr, "Memory allocation failed for password list.\n");
        fclose(file);
        return -1;
    }

    int i = 0;
    while (i < MAX_PASSWORDS && fgets(passwd, MAX_PASSWORD_LENGTH, file) != NULL) {
        passwd[strcspn(passwd, "\n")] = 0; // Remove newline
        password_list[i] = strdup(passwd);
        if (password_list[i] == NULL) {
            fprintf(stderr, "Memory allocation failed for password %d.\n", i);
            // Free previously allocated memory
            while (i > 0) {
                free(password_list[--i]);
            }
            free(password_list);
            fclose(file);
            return -1;
        }
        i++;
    }

    fclose(file);
    return i;
}

void extract_salt(const char *hash, char *salt) {
    int i = 0, count = 0;
    // Iterate over the hash to extract the full salt including the hash type and the actual salt
    for (i = 0; hash[i] != '\0'; i++) {
        salt[i] = hash[i];
        if (hash[i] == '$') {
            count++;
            if (count == 3) { // Stop after the third '$' which ends the salt part
                break;
            }
        }
    }
    salt[i] = '\0'; // Null-terminate the salt
}

// Function to perform the brute force attack
void *brute_force(void *thread_arg) {
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    int tid = data->thread_id;

    while (1) {
        pthread_mutex_lock(&mutex);
        while (count == 0) {
            pthread_cond_wait(&buffer_not_empty, &mutex);
        }
        if (password_found) {
            pthread_mutex_unlock(&mutex);
            pthread_exit(NULL);
        }
        struct Buffer current_job = buffer[out];
        out = (out + 1) % BUFFER_SIZE;
        count--;
        pthread_cond_signal(&buffer_not_full);
        pthread_mutex_unlock(&mutex);

        char *password = current_job.password;
        int hash_index = current_job.index;

        char salt[11];
        extract_salt(hash_list[hash_index], salt);

        printf("Thread %d: Hash %d salt: %s\n", tid, hash_index, salt);
        for (int i = 0; i < npasswd && !password_found; i++) {
            char *new_hash = crypt_r(password_list[i], salt, data->crypt_data);
            printf("Thread %d: Trying password %s with salt %s. New hash: %s\n", tid, password_list[i], salt, new_hash);
            if (strcmp(hash_list[hash_index], new_hash) == 0) {
                pthread_mutex_lock(&mutex);
                printf("Thread %d: Password found for hash %d: %s\n", tid, hash_index, password_list[i]);
                cracked_list[hash_index] = hash_list[hash_index];
                foundhashes++;
                for (int r = hash_index; r < nhashes - 1; r++) {
                    hash_list[r] = hash_list[r + 1];
                }
                nhashes--;
                password_found = 1;
                pthread_mutex_unlock(&mutex);
            }
        }
        free(password);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_threads> <dictionary_file>\n", argv[0]);
        return 1;
    }

    int num_threads = atoi(argv[1]);
    if (num_threads <= 0 || num_threads > MAX_THREADS) {
        fprintf(stderr, "Invalid number of threads. Must be between 1 and %d\n", MAX_THREADS);
        return 1;
    }

    pthread_mutex_init(&mutex, NULL);
    cracked_list = malloc(MAX_HASHES * sizeof(char *));
    nhashes = load_hashes("hashes2.txt");
    if (nhashes < 0) {
        return 1;
    }

    npasswd = load_passwords(argv[2]);
    if (npasswd < 0) {
        return 1;
    }

    pthread_t threads[MAX_THREADS];
    struct ThreadData thread_data[num_threads];
    struct crypt_data crypt_data[num_threads];

    for (int i = 0; i < num_threads; i++) {
        crypt_data[i].initialized = 0;
    }

    for (int i = 0; i < BUFFER_SIZE; i++) {
        buffer[i].password = NULL;
    }

    for (int t = 0; t < num_threads; t++) {
        thread_data[t].thread_id = t;
        thread_data[t].crypt_data = &crypt_data[t];
        int rc = pthread_create(&threads[t], NULL, brute_force, (void *)&thread_data[t]);
        if (rc) {
            fprintf(stderr, "ERROR: return code from pthread_create() is %d\n", rc);
            return 1;
        }
    }

    for (int i = 0; i < nhashes; i++) {
        pthread_mutex_lock(&mutex);
        while (count == BUFFER_SIZE) {
            pthread_cond_wait(&buffer_not_full, &mutex);
        }
        struct Buffer current_job;
        current_job.password = strdup(password_list[i % npasswd]);
        current_job.index = i;
        buffer[in] = current_job;
        in = (in + 1) % BUFFER_SIZE;
        count++;
        pthread_cond_signal(&buffer_not_empty);
        pthread_mutex_unlock(&mutex);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    if (!foundhashes) {
        printf("Password not found for any hash!\n");
    } else {
        printf("\nHashes encontrados:\n");
        for (int i = 0; i < foundhashes - 1; i++) {
            printf("%s\n", cracked_list[i]);
        }
    }

    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&buffer_not_full);
    pthread_cond_destroy(&buffer_not_empty);

    return 0;
}
