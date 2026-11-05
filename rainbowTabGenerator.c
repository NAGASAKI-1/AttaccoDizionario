#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define DICTIONARY_NAME "only_passwords_dictionary.txt"
#define DICTIONARY_SIZE 5200
#define DOCUMENTS_FOLDER "./PIRAS/PIRAS_unsalted/"
#define DOCUMENTS_NUEMBER 300

void keyDerivation(FILE* dictionary, unsigned char** keys, unsigned char** iv);

int main () {

    //apertura in lettura del dizionario
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

    FILE *encrypted_file;
    int file_index = 1;
    char* filename = malloc(36 * sizeof(char)); // path + "doc_0000.enc" + null terminator
    unsigned char* encrypted_block_buffer = malloc(16 * sizeof(unsigned char)); // AES block size is 16 bytes
    unsigned char* decrypted_block_buffer = malloc(32 * sizeof(unsigned char)); // slightly larger buffer to safely accommodate block size + padding
    snprintf(filename, 36, "./PIRAS/PIRAS_unsalted/doc_%04d.enc", file_index);
    int *decrypted_bytes = malloc(sizeof(int));

    //costante header inizio file
    const char expected_header[16] = {0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a, 0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a, 0x31};

    printf("About to process files...\n");

    while ((encrypted_file = fopen(filename, "rb"))) {
        printf("Processing file: %s\n", filename);
        for (int i = 0; i < DICTIONARY_SIZE; i++) {
            EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keys[i], iv[i]);
            fread(encrypted_block_buffer, 1, 16, encrypted_file);
            EVP_DecryptUpdate(ctx, decrypted_block_buffer, decrypted_bytes, encrypted_block_buffer, 16);
            EVP_DecryptUpdate(ctx, decrypted_block_buffer, decrypted_bytes, encrypted_block_buffer, 16);
            if (memcmp(decrypted_block_buffer, expected_header, 16) != 0) {
                //printf("Got here!\n");
                //printf("Decrypted block is: %s\n", decrypted_block_buffer);

                EVP_CIPHER_CTX_reset(ctx); // Resetta il contesto per il prossimo tentativo
                rewind(encrypted_file); // Torna all'inizio del file per il prossimo tentativo
                continue; // Chiave non corretta, prova la prossima
            }
            
            //printf("Decrypted block is: %s\n", decrypted_block_buffer);
            printf("Key %d seems to be correct, proceeding with decryption...\n", i + 1);
            char output_filename[36];
            snprintf(output_filename, 36, "./PIRAS/PIRAS_unsalted/doc_%04d.pdf", file_index);
            FILE *output_file = fopen(output_filename, "wb");
            fwrite(decrypted_block_buffer, 1, *decrypted_bytes, output_file); //
            

            while(fread(encrypted_block_buffer, 1, 16, encrypted_file) > 0) {
                EVP_DecryptUpdate(ctx, decrypted_block_buffer, decrypted_bytes, encrypted_block_buffer, 16);
                fwrite(decrypted_block_buffer, 1, *decrypted_bytes, output_file); // Scrive il blocco decifrato su output_file
            }

            int final_bytes = 0;
            if(EVP_DecryptFinal_ex(ctx, decrypted_block_buffer, &final_bytes)) {
                fwrite(decrypted_block_buffer, 1, final_bytes, output_file); // Scrive eventuali byte finali decifrati su output_file
                fclose(encrypted_file);
                fclose(output_file);
                EVP_CIPHER_CTX_reset(ctx);
                //EVP_CIPHER_CTX_free(ctx);
                printf("File %s decrypted successfully with key %d\n", filename, i + 1);
                break; // Esce dal ciclo delle chiavi, il file è stato decifrato con successo
            }
            else {
                printf("Decryption failed at last block with key %d, trying next key...\n", i + 1);
            }

            fclose(output_file);
            //remove(output_filename); // Rimuove il file se la decifratura non è riuscita
            rewind(encrypted_file); // Torna all'inizio del file per il prossimo tentativo
        }
        
        fclose(encrypted_file);
        file_index++;

        snprintf(filename, 36, "./PIRAS/PIRAS_unsalted/doc_%04d.enc", file_index);
    }

    printf("All files processed or error opening files\n");
    
    return 0;
    
    /*
    int char_read;
    if ((char_read = getline(&line_buffer, buffer_size, dictionary))) {
        strtok()
    }
    */
    /*struct csv_parser parser;*/
    /*csv_init(parser, )*/

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

        unsigned char derived_key_buffer[48];
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