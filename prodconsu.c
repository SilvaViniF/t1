#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <crypt.h>

#define MAX_PASSWORD_LENGTH 128
#define MAX_THREADS 128
#define MAX_QUEUE_SIZE 10000
#define MAX_HASHES 1000

char **hash_list;
int num_hashes;

int load_hashes(const char *filename) {
    char hash[MAX_PASSWORD_LENGTH];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen()");
        return -1;
    }

    hash_list = malloc(MAX_HASHES * sizeof(char *));
    if (hash_list == NULL) {
        fprintf(stderr, "Memory allocation failed for hash list.\n");
        fclose(file);
        return -1;
    }

    int i = 0;
    while (i < MAX_HASHES && fscanf(file, "%s", hash) != EOF) {
        hash_list[i] = strdup(hash);
        i++;
    }

    fclose(file);
    return i;
}
pthread_mutex_t mutex;
pthread_cond_t full_cond, empty_cond;

typedef struct {
    char *password;
    char *hash;
} PasswordHashPair;

PasswordHashPair password_queue[MAX_QUEUE_SIZE];
int queue_front = 0;
int queue_rear = 0;
int queue_size = 0;

int num_hashes;
int num_found_hashes = 0;

void enqueue(PasswordHashPair pair) {
    pthread_mutex_lock(&mutex);
    while (queue_size >= MAX_QUEUE_SIZE) {
        pthread_cond_wait(&full_cond, &mutex);
    }
    password_queue[queue_rear] = pair;
    queue_rear = (queue_rear + 1) % MAX_QUEUE_SIZE;
    queue_size++;
    pthread_cond_signal(&empty_cond);
    pthread_mutex_unlock(&mutex);
}

PasswordHashPair dequeue() {
    pthread_mutex_lock(&mutex);
    while (queue_size <= 0) {
        pthread_cond_wait(&empty_cond, &mutex);
    }
    PasswordHashPair pair = password_queue[queue_front];
    queue_front = (queue_front + 1) % MAX_QUEUE_SIZE;
    queue_size--;
    pthread_cond_signal(&full_cond);
    pthread_mutex_unlock(&mutex);
    return pair;
}

void extract_salt(const char *hash, char *salt) {
    const char *ptr = strchr(hash, '$');
    if (ptr != NULL) {
        ptr = strchr(ptr + 1, '$');
        if (ptr != NULL) {
            ptr = strchr(ptr + 1, '$');
            if (ptr != NULL) {
                strncpy(salt, hash, ptr - hash + 1);
                salt[ptr - hash + 1] = '\0';
            }
        }
    }
}

void *producer(void *thread_arg) {
    const char *filename = (const char *)thread_arg;
    char password[MAX_PASSWORD_LENGTH];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen()");
        pthread_exit(NULL);
    }

    while (fgets(password, MAX_PASSWORD_LENGTH, file) != NULL) {
        password[strcspn(password, "\n")] = '\0'; // Remove newline
        PasswordHashPair pair;
        pair.password = strdup(password);
        enqueue(pair);
    }

    fclose(file);
    pthread_exit(NULL);
}

void *consumer(void *thread_arg) {
    int tid = *((int *)thread_arg);

    while (1) {
        PasswordHashPair pair = dequeue();
        char *hash = pair.hash;
        char *password = pair.password;

        for (int j = 0; j < num_hashes; j++) {
            char salt[MAX_PASSWORD_LENGTH];
            extract_salt(hash, salt);

            char *new_hash = crypt(password, salt);
            if (strcmp(hash, new_hash) == 0) {
                pthread_mutex_lock(&mutex);
                printf("Thread %d: Password found for hash: %s - %s\n", tid, password, hash);
                num_found_hashes++;
                pthread_mutex_unlock(&mutex);
                break;
            }
        }
        free(pair.password);
    }

    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <num_threads> <hash_file> <password_file>\n", argv[0]);
        return 1;
    }

    int num_threads = atoi(argv[1]);
    if (num_threads <= 0 || num_threads > MAX_THREADS) {
        fprintf(stderr, "Invalid number of threads. Must be between 1 and %d\n", MAX_THREADS);
        return 1;
    }

    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&full_cond, NULL);
    pthread_cond_init(&empty_cond, NULL);

    num_hashes = load_hashes(argv[2]);
    if (num_hashes < 0) {
        return 1;
    }

    pthread_t producer_thread;
    pthread_create(&producer_thread, NULL, producer, argv[3]);

    pthread_t consumer_threads[MAX_THREADS];
    int thread_ids[MAX_THREADS];
    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i;
        pthread_create(&consumer_threads[i], NULL, consumer, &thread_ids[i]);
    }

    pthread_join(producer_thread, NULL);
    for (int i = 0; i < num_threads; i++) {
        pthread_join(consumer_threads[i], NULL);
    }

    if (num_found_hashes == 0) {
        printf("Password not found for any hash!\n");
    }

    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&full_cond);
    pthread_cond_destroy(&empty_cond);

    return 0;
}
