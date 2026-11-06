#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define DICTIONARY_NAME "only_passwords_dictionary.txt"
#define DICTIONARY_SIZE 5200
#define ENCRYPTED_DOCUMENTS_FOLDER "./PIRAS/PIRAS_salted"
#define DECRYPTED_DOCUMENTS_FOLDER "./PIRAS/PIRAS_salted_decrypted"
#define ENCRYPTED_DOCUMENT_PATH_LENGTH 34 // "./PIRAS/PIRAS_salted/doc_0000.enc" + null terminator
#define DECRYPTED_DOCUMENT_PATH_LENGTH 44 // "./PIRAS/PIRAS_salted_decrypted/doc_0000.pdf" + null terminator 
#define NUMBER_OF_DOCUMENTS 300
#define SIZE_OF_KEY 32
#define SIZE_OF_IV 16
#define SIZE_OF_SALT 8
#define SIZE_OF_SALT_PREFIX 8
#define SIZE_OF_BLOCK 16

#define CTX_INIT_ERROR 1
#define DECRYPT_INIT_ERROR 2
#define DECRYPT_UPDATE_ERROR 3
#define DECRYPT_FINAL_ERROR 4

#define DEBUG
#define LOG_MATCH_FOUND
//#define LOG_DECRYPTION_ERROR

void keyDerivation(unsigned char* password, int password_length, unsigned char salt[SIZE_OF_SALT], unsigned char key[SIZE_OF_KEY], unsigned char iv[SIZE_OF_IV]);
int decryptFile(EVP_CIPHER_CTX* ctx, FILE* encrypted_file, FILE* output_file, unsigned char* key, unsigned char* iv);
void getPasswords(FILE* dictionary, unsigned char* passwords[DICTIONARY_SIZE], int passwords_length[DICTIONARY_SIZE]);
void dumpPasswords(unsigned char *passwords[DICTIONARY_SIZE], int passwords_length[DICTIONARY_SIZE]);
void getSalt(FILE* encrypted_file, unsigned char salt[SIZE_OF_SALT]);


int main () {

    //apertura in lettura del dizionario1
    FILE *dictionary;
    if (!(dictionary = fopen(DICTIONARY_NAME, "r"))) {
        printf("Error opening dictionary file %s\n", DICTIONARY_NAME);
        return 1;
    }

    //derivazione delle chiavi e degli IV dal dizionario
    unsigned char* passwords[DICTIONARY_SIZE];
    int passwords_length[DICTIONARY_SIZE];
    unsigned char key[SIZE_OF_KEY];
    unsigned char iv[SIZE_OF_IV];
    unsigned char salt[SIZE_OF_SALT];
    //unsigned char salt_and_first_block[SIZE_OF_SALT_PREFIX + SIZE_OF_SALT + SIZE_OF_BLOCK];
    
    getPasswords(dictionary, passwords, passwords_length);
    fclose(dictionary);
    
    /*
    dumpPasswords(passwords, passwords_length);
    return 0; // Exit after dumping passwords for debugging
    */
    
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    FILE *encrypted_file;
    FILE *decrypted_file;
    
    char encrypted_filename[ENCRYPTED_DOCUMENT_PATH_LENGTH];
    char decrypted_filename[DECRYPTED_DOCUMENT_PATH_LENGTH];

    //debug
    printf("About to process files...\n");

    for (int file_index = 1; file_index <= NUMBER_OF_DOCUMENTS; file_index++) {

        snprintf(encrypted_filename, ENCRYPTED_DOCUMENT_PATH_LENGTH, "%s/doc_%04d.enc", ENCRYPTED_DOCUMENTS_FOLDER, file_index);
        snprintf(decrypted_filename, DECRYPTED_DOCUMENT_PATH_LENGTH, "%s/doc_%04d.pdf", DECRYPTED_DOCUMENTS_FOLDER, file_index);

        if ((encrypted_file = fopen(encrypted_filename, "rb")) == NULL) {
            printf("Skipping file number %d because it couldn't be opened", file_index);
            file_index++;
            continue;
        }

        if ((decrypted_file = fopen(decrypted_filename, "wb")) == NULL) {
            printf("Skipping file number %d because I couldn't open the decrypted file", file_index);
            fclose(encrypted_file);
            continue;
        }

        getSalt(encrypted_file, salt);

        for (int password_index = 0; password_index < DICTIONARY_SIZE; password_index++) {
            
            //derivazione della chiave e dell'IV
            keyDerivation(passwords[password_index], passwords_length[password_index], salt, key, iv); // Use a password based on the file index for demonstration
             
            //debug
            /*
            printf("salt: ");
            for (int i = 0; i < SIZE_OF_SALT; i++) {
                printf("%02x", salt[i]);
            }
            printf("\n");

            printf("key: ");
            for (int i = 0; i < SIZE_OF_KEY; i++) {
                printf("%02x", key[i]);
            }
            printf("\n");

            printf("iv: ");
            for (int i = 0; i < SIZE_OF_IV; i++) {
                printf("%02x", iv[i]);
            }
            printf("\n");
            exit(0);
            */

            if (decryptFile(ctx, encrypted_file, decrypted_file, key, iv) != 0) {
                #ifdef LOG_DECRYPTION_ERROR
                printf("Error occurred while decrypting file: %s\n", encrypted_filename);
                printf("Ignoring password number %d\n", password_index + 1);
                printf("Skipping to next password...\n");
                #endif
                fseek(encrypted_file, SIZE_OF_SALT_PREFIX + SIZE_OF_SALT, SEEK_SET); // Reset file pointer to the start of the encrypted data
                fseek(decrypted_file, 0, SEEK_SET); // Reset file pointer to the start of the decrypted file
                continue;
            }

            #ifdef LOG_MATCH_FOUND
            printf("Decryption successful for file: %s with password number %d\n", encrypted_filename, password_index + 1);
            #endif
            break; // Exit the password loop if decryption is successful

        }

        fclose(encrypted_file);
        fclose(decrypted_file);
    }

        
    EVP_CIPHER_CTX_free(ctx);
    fclose(dictionary);
    for (int i = 0; i < DICTIONARY_SIZE; i++) {
        free(passwords[i]);
    }

    printf("All files processed or error opening files\n");
    return 0;
    
}

void keyDerivation(unsigned char* password, int password_length, unsigned char salt[SIZE_OF_SALT], unsigned char key[SIZE_OF_KEY], unsigned char iv[SIZE_OF_IV]) {
    unsigned char derived_key_buffer[48];
    char* line_buffer = NULL;
    size_t line_buffer_size = 0;

    if (!PKCS5_PBKDF2_HMAC(
        password, password_length,
        salt, SIZE_OF_SALT,
        1000,
        EVP_sha256(),
        48,
        derived_key_buffer
    )) {
        fprintf(stderr, "Error deriving key and IV\n");
    }

    memcpy(key, derived_key_buffer, 32);
    memcpy(iv, derived_key_buffer + 32, 16);
}


int decryptFile(EVP_CIPHER_CTX* ctx, FILE* encrypted_file, FILE* output_file, unsigned char* key, unsigned char* iv) {
    const char expected_header[16] = {0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a, 0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a, 0x31};

    // Initialize decryption (NULL IV implies all-zero IV; ensure this matches encryption)
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_reset(ctx);
        //printf("faild at init");
        return DECRYPT_INIT_ERROR;
    }

    int decrypted_bytes = 0;
    int bytes_read = 0;
    unsigned char encrypted_block_buffer[16];
    unsigned char decrypted_block_buffer[32]; // slightly larger buffer to safely accommodate block size + padding


    //decrittazione del primo blocco per verificare con header
    EVP_CIPHER_CTX_set_padding(ctx, 0); // Disabilita il padding per la verifica dell'header
    bytes_read = fread(encrypted_block_buffer, 1, sizeof(encrypted_block_buffer), encrypted_file);
    if (bytes_read != sizeof(encrypted_block_buffer)) {
        fprintf(stderr, "Error reading the first block from the encrypted file\n");
        //printf("faild at first block read");
        EVP_CIPHER_CTX_reset(ctx);
        return DECRYPT_UPDATE_ERROR;
    }

    EVP_DecryptUpdate(ctx, decrypted_block_buffer, &decrypted_bytes, encrypted_block_buffer, bytes_read);
    if (memcmp(decrypted_block_buffer, expected_header, 16) != 0) {
        //printf("Decrypted block is: %s\n", decrypted_block_buffer);
        //printf("faild during first block decryption\n");
        EVP_CIPHER_CTX_reset(ctx); // Resetta il contesto per il prossimo tentativo
        return DECRYPT_UPDATE_ERROR; // Chiave non corretta, prova la prossima
    }

    fwrite(decrypted_block_buffer, 1, decrypted_bytes, output_file); // Scrive il primo blocco decifrato nel file di output
    EVP_CIPHER_CTX_set_padding(ctx, 1); // Riabilita il padding per la decrittazione completa
    //EVP_CIPHER_CTX_reset(ctx); // Resetta il contesto per la decrittazione completa

    while ((bytes_read = fread(encrypted_block_buffer, 1, sizeof(encrypted_block_buffer), encrypted_file)) > 0) {
        if (!EVP_DecryptUpdate(ctx, decrypted_block_buffer, &decrypted_bytes, encrypted_block_buffer, bytes_read)) {
            fprintf(stderr, "Error during decryption update\n");
            return DECRYPT_UPDATE_ERROR;
        }
        fwrite(decrypted_block_buffer, 1, decrypted_bytes, output_file);
    }

    if (!EVP_DecryptFinal_ex(ctx, decrypted_block_buffer, &decrypted_bytes)) {
        fprintf(stderr, "Error during decryption finalization (incorrect password or corrupted data)\n");
        return DECRYPT_FINAL_ERROR;
    } else {
        fwrite(decrypted_block_buffer, 1, decrypted_bytes, output_file);
    }
    

    // Cleanup resources
    EVP_CIPHER_CTX_reset(ctx);
    return 0;
}

void getPasswords(FILE* dictionary, unsigned char *passwords[DICTIONARY_SIZE], int passwords_length[DICTIONARY_SIZE]) {
    char* line_buffer = NULL;
    size_t line_buffer_size = 0;
    ssize_t password_length = 0;

    int password_index = 0;
    while ((password_length = getline(&line_buffer, &line_buffer_size, dictionary)) != -1) {
        if (line_buffer[password_length - 1] == '\n') {
            line_buffer[password_length - 1] = '\0';
        }
        passwords[password_index] = memcpy(malloc(password_length), line_buffer, password_length);
        passwords_length[password_index] = password_length - 1; //esclude \n
        password_index++;
    }
}

void getSalt(FILE* encrypted_file, unsigned char salt[SIZE_OF_SALT]) {

    fseek(encrypted_file, SIZE_OF_SALT_PREFIX, SEEK_SET); // Skip the "Salted__" prefix

    if (fread(salt, SIZE_OF_SALT, 1, encrypted_file) < 1) {
        printf("Error reading salt and first block from encrypted file\n");
    } 
    //debug
    /*
    for(int i = 0; i < SIZE_OF_SALT; i++) {
        printf("%02x", salt[i]);
    }
    printf("\n");
    exit(0);
    */
}

//per debug
void dumpPasswords(unsigned char *passwords[DICTIONARY_SIZE], int passwords_length[DICTIONARY_SIZE]) {
    for (int i = 0; i < DICTIONARY_SIZE; i++) {
        printf("Password %d: %.*s\n", i + 1, passwords_length[i], passwords[i]);
    }
}