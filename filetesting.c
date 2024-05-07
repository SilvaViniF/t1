#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>

#define MAX_HASHES 1000
#define MAX_PASSWORDS 15000000
#define MAX_PASSWORD_LENGTH 128

char **password_list;
char **hash_list;
int npasswd;
int nhashes;

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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <passwords_file> <hashes_file>\n", argv[0]);
        return 1;
    }

    npasswd = load_passwords(argv[1]);
    if (npasswd < 0) {
        return 1;
    }

    nhashes = load_hashes(argv[2]);
    if (nhashes < 0) {
        return 1;
    }

    // Printing password list
    printf("Password List:\n");
    for (int i = 0; i < npasswd; i++) {
        printf("%s\n", password_list[i]);
    }

    // Printing hash list
    printf("\nHash List:\n");
    for (int i = 0; i < nhashes; i++) {
        printf("%s\n", hash_list[i]);
    }

    return 0;
}
