#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define DICTIONARY_NAME "only_passwords_dictionary.txt"
#define DICTIONARY_SIZE 5200
#define ENCRYPTED_DOCUMENTS_FOLDER "./PIRAS/PIRAS_unsalted"
#define DECRYPTED_DOCUMENTS_FOLDER "./PIRAS/PIRAS_unsalted_decrypted"
#define ENCYPTED_DOCUMENT_PATH_LENGTH 36 // "./PIRAS/PIRAS_unsalted/doc_0000.enc" + null terminator
#define DECRYPTED_DOCUMENT_PATH_LENGTH 46 // "./PIRAS/PIRAS_unsalted_decrypted/doc_0000.pdf" + null terminator 
#define DOCUMENTS_NUMBER 300

#define CTX_INIT_ERROR 1
#define DECRYPT_INIT_ERROR 2
#define DECRYPT_UPDATE_ERROR 3
#define DECRYPT_FINAL_ERROR 4

#define DEBUG
#define LOG_MATCH_FOUND
//#define LOG_DECRYPTION_ERROR

void keyDerivation(FILE* dictionary, unsigned char** keys, unsigned char** iv);
int decryptFile(EVP_CIPHER_CTX* ctx, FILE* encrypted_file, FILE* output_file, unsigned char* key, unsigned char* iv);

int main () {

    //apertura in lettura del dizionario1
    FILE *dictionary;
    if (!(dictionary = fopen(DICTIONARY_NAME, "r"))) {
        printf("Error opening dictionary file %s\n", DICTIONARY_NAME);
        return 1;
    }

    //derivazione delle chiavi e degli IV dal dizionario
    unsigned char** keys = malloc(DICTIONARY_SIZE * sizeof(unsigned char*));
    unsigned char** iv = malloc(DICTIONARY_SIZE * sizeof(unsigned char*));
    keyDerivation(dictionary, keys, iv);

    //debug: stampa delle chiavi generate
    /*
    for(int i = 0; i < DICTIONARY_SIZE; i++) {
            printf("Key %d: ", i);
            for (int j = 0; j < 32; j++) {
                printf("%02x", (unsigned char)keys[i][j]);
            }
            printf("\n");
    }*/
    
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    int file_index = 1; //Indica il file in elaborazione, vale sia per il file cifrato che per quello decifrato

    FILE *encrypted_file;
    FILE *decrypted_file;
    
    char encrypted_filename[ENCYPTED_DOCUMENT_PATH_LENGTH];
    char decrypted_filename[DECRYPTED_DOCUMENT_PATH_LENGTH];
    /*
    char* encrypted_filename = malloc(ENCYPTED_DOCUMENT_PATH_LENGTH * sizeof(char));
    char* decrypted_filename = malloc(DECRYPTED_DOCUMENT_PATH_LENGTH * sizeof(char));
    */
    snprintf(encrypted_filename, ENCYPTED_DOCUMENT_PATH_LENGTH, "%s/doc_%04d.enc", ENCRYPTED_DOCUMENTS_FOLDER, file_index);
    snprintf(decrypted_filename, DECRYPTED_DOCUMENT_PATH_LENGTH, "%s/doc_%04d.pdf", DECRYPTED_DOCUMENTS_FOLDER, file_index);

    //debug
    printf("About to process files...\n");

    while ((encrypted_file = fopen(encrypted_filename, "rb"))) {
        if (!(decrypted_file = fopen(decrypted_filename, "wb"))) {
            printf("Error opening decrypted file %s\n", decrypted_filename);
            fclose(encrypted_file);
            break;
        }

        for (int password_index = 0; password_index < DICTIONARY_SIZE; password_index++) {
            
            if (decryptFile(ctx, encrypted_file, decrypted_file, keys[password_index], iv[password_index]) != 0) { // Placeholder call to decryptFile; actual decryption logic will be handled in the loop below
                #ifdef LOG_DECRYPTION_ERROR
                printf("Error occurred while decrypting file: %s\n", encrypted_filename);
                printf("Ignoring password number %d\n", password_index + 1);
                printf("Skipping to next password...\n");
                #endif
                rewind(encrypted_file);
                rewind(decrypted_file);
                continue;
            }

            #ifdef LOG_MATCH_FOUND
            printf("File %s decrypted successfully with password number %d\n", encrypted_filename, password_index + 1);
            #endif

            fclose(encrypted_file);
            fclose(decrypted_file);
            break; // Exit the password loop if decryption was successful
        }

        file_index++;
        snprintf(encrypted_filename, ENCYPTED_DOCUMENT_PATH_LENGTH, "%s/doc_%04d.enc", ENCRYPTED_DOCUMENTS_FOLDER, file_index);
        snprintf(decrypted_filename, DECRYPTED_DOCUMENT_PATH_LENGTH, "%s/doc_%04d.pdf", DECRYPTED_DOCUMENTS_FOLDER, file_index);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(dictionary);
    /*
    free(encrypted_filename);
    free(decrypted_filename);
    */
    for (int i = 0; i < DICTIONARY_SIZE; i++) {
        free(keys[i]);
        free(iv[i]);
    }
    free(keys);
    free(iv);

    printf("All files processed or error opening files\n");
    return 0;
    
}

void keyDerivation(FILE* dictionary, unsigned char** keys, unsigned char** iv) {
    unsigned char derived_key_buffer[48];
    char* line_buffer = NULL;
    size_t line_buffer_size = 0;
    int i = 0;
    
    

    while (getline(&line_buffer, &line_buffer_size, dictionary) != -1) {
        // Remove newline character if present
        size_t len = strlen(line_buffer);
        if (len > 0 && line_buffer[len - 1] == '\n') {
            line_buffer[len - 1] = '\0';
        }

        PKCS5_PBKDF2_HMAC(
            line_buffer, strlen(line_buffer),
            NULL, 0,
            1000,
            EVP_sha256(),
            48,
            derived_key_buffer
        );

        // Store the derived key and IV
        keys[i] = malloc(32 * sizeof(unsigned char));
        iv[i] = malloc(16 * sizeof(unsigned char));
        memcpy(keys[i], derived_key_buffer, 32);
        memcpy(iv[i], derived_key_buffer + 32, 16);
        
        i++;
    }
}

int decryptFile(EVP_CIPHER_CTX* ctx, FILE* encrypted_file, FILE* output_file, unsigned char* key, unsigned char* iv) {
    const char expected_header[16] = {0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a, 0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a, 0x31};

    //printf("Attempting decryption with provided key and IV...\n");

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