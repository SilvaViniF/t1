#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <crypt.h>

#define MAX_HASHES 1000
#define MAX_PASSWORDS 15000000
#define MAX_PASSWORD_LENGTH 128
#define MAX_THREADS 128

char **password_list;
char **hash_list;
char salt[12];
int npasswd;
int nhashes;
int password_found = 0;
pthread_mutex_t mutex;

struct ThreadData {
    int thread_id;
    struct crypt_data *crypt_data;
};

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
    while (i < MAX_HASHES && fgets(hash, MAX_PASSWORD_LENGTH, file) != NULL) {
        hash[strcspn(hash, "\n")] = 0; // Remove newline
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
    int i = 0;
    while (i < MAX_PASSWORDS && fgets(passwd, MAX_PASSWORD_LENGTH, file) != NULL) {
        passwd[strcspn(passwd, "\n")] = 0; // Remove newline
        password_list[i] = strdup(passwd);
        i++;
    }

    fclose(file);
    return i;
}

// Function to perform the brute force attack
void *brute_force(void *thread_arg) {
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    int tid = data->thread_id;
    int start = tid * (npasswd / MAX_THREADS);
    int end = (tid == MAX_THREADS - 1) ? npasswd : ((tid + 1) * (npasswd / MAX_THREADS));

    printf("Thread %d: Processing passwords from index %d to %d\n", tid, start, end - 1);

    for (int j = 0; j < nhashes && !password_found; j++) {
        for (int i = start; i < end && !password_found; i++) {
            printf("Thread %d: Iteration %d\n", tid, i);
            printf("Thread %d: Password: %s\n", tid, password_list[i]);
            printf("Thread %d: Salt: %s\n", tid, salt);
            char *new_hash = crypt_r(password_list[i], salt, data->crypt_data);
            printf("Thread %d: New hash: %s\n", tid, new_hash);
            printf("Thread %d: Expected hash: %s\n", tid, hash_list[j]);
            if (strcmp(hash_list[j], new_hash) == 0) {
                pthread_mutex_lock(&mutex);
                printf("Thread %d: Password found for hash %d: %s\n", tid, j, password_list[i]);
                password_found = 1;
                pthread_mutex_unlock(&mutex);
            }
        }
    }

    pthread_exit(NULL);
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

    nhashes = load_hashes("hashes.txt");
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

    for (int t = 0; t < num_threads; t++) {
        thread_data[t].thread_id = t;
        thread_data[t].crypt_data = &crypt_data[t];
        int rc = pthread_create(&threads[t], NULL, brute_force, (void *)&thread_data[t]);
        if (rc) {
            fprintf(stderr, "ERROR: return code from pthread_create() is %d\n", rc);
            return 1;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    if (!password_found) {
        printf("Password not found for any hash!\n");
    }

    pthread_mutex_destroy(&mutex);

    return 0;
}
