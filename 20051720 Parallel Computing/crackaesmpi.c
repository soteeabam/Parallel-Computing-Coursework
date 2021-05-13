#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <mpi/mpi.h>

int success = 0;
void handleOpenSSLErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char* decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv ){

    EVP_CIPHER_CTX *ctx;
    unsigned char *plaintexts;
    int len;
    int plaintext_len;
    
    unsigned char* plaintext = malloc(ciphertext_len);
    bzero(plaintext,ciphertext_len);

    /* Create and initialise the context */
  
    if(!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleOpenSSLErrors();

  
    EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleOpenSSLErrors();
   
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    
    // return 1 if decryption successful, otherwise 0
    if(1 == EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        success = 1;
    plaintext_len += len;

   
    /* Add the null terminator */
    plaintext[plaintext_len] = 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    //delete [] plaintext;
    return plaintext;
}


size_t calcDecodeLength(char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
    return (len*3)/4 - padding;
}

void Base64Decode( char* b64message, unsigned char** buffer, size_t* length) {

    
    BIO *bio, *b64;  // A BIO is an I/O strean abstraction

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

void initAES(const unsigned char *pass, unsigned char* salt, unsigned char* key, unsigned char* iv )
{
    //initialisatio of key and iv with 0
    bzero(key,sizeof(key)); 
    bzero(iv,sizeof(iv));
  
    EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, pass, strlen(pass), 1, key, iv);
}

/*
    Function: checkPlaintext
    Operation: Compares the recently acquired result to the target plaintext.
    Inputs: char* plaintext - pointer to target plaintext
            char* result - pointer to result of decryption attempt.
    Output: return strncmp(plaintext, result, length) - value < 0 : plaintext > result
                                                        value > 0 : plaintext < result
                                                        value = 0 : plaintext = result
    Notes: Complies with the standards of a Known-Plaintext-Attack.
*/
int checkPlaintext(char* plaintext, char* result){
    int length = 10;
    return strncmp(plaintext, result, length);
}

/*
    Function: main
    Operation: primary runtime, initialise variables, generate password, create parallel region, attempt cracking.
    Inputs: int argc - the amount of arguments passed by command line.
            char argv - arguments passed by command line, in this case it will be the number of desired processes 
*/
int main (int argc, char **argv){
    //Initializing the OpenMPI specific variables used in message passing and vector assignment.
    int myrank, rbuf, sbuf, count = 1, flag, err, inc;
    MPI_Status status;
    MPI_Request req;

    //Target Ciphertext and plaintext, . Target password is zest.
    char* ciphertext_base64 = (char*) "U2FsdGVkX18IzeFxDZrMxL56zmCxpJTpMMCShpV02j9QRvgeAuvSc6V406zzfuwETgIxJXaqvFHMVuFXfR+X6ZDFm2SClHRuI9C1yL+JRRRAUZS22BrE8y0XS0Zwhk5JZS3IBRuNSRNgELQ+Fimmsw==\n";   

    //Target Ciphertext and plaintext, . Target password is 29Apr.
    //char* ciphertext_base64 = (char*) "U2FsdGVkX1/Y+mHv2oZdo5MLKEQWCATfc31jSGWXZ6D3gWuLdZYVUrRnGNecV+EdFsMYSWhEh1nsP9tMwpQaPeWMP3MZ6G0HCLVw+fjRjYY1Fi+lpuGKd/jmZh0Loylw0gVo2SUxNigSvjnn3xAGHg==\n";
   char* plaintext = "This is the top seret message in parallel computing! Please keep it in a safe place.";
      
        //Dictionary lookup varibles: 0-9 / A-Z / a-z (standard ASCII order)
          
    char dict[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        

    //Property variables.
    int decryptedtext_len, ciphertext_len, dict_len;
    size_t cipher_len;

    //Variable for unsalted ciphertext and the extracted salt.
    unsigned char* ciphertext;
    unsigned char salt[8];

    //Load libcrypto error strings.
    ERR_load_crypto_strings();

    //Decode from base64 "main.c -> b64.c -> main.c"
    Base64Decode(ciphertext_base64, &ciphertext, &cipher_len);

    //Initializes the Key and IV.
    unsigned char key[16];
    unsigned char iv[16];

    //Defines the password length.
    //uncomment the below when running second cipher because of difference in length
    //unsigned char plainpassword[] = "00000";
    unsigned char plainpassword[] = "0000";
    unsigned char* password = &plainpassword[0];
    int password_length = 3;

    //Remove the salt from the decoded ciphertext.
    if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
        memcpy(salt,&ciphertext[8],8);
        ciphertext += 16;
        cipher_len -= 16;
    }

    //define dictionary length for loops.
    dict_len = strlen(dict);
    
    //this was throwing errors so i replaced it
    //time_t begin = time(NULL);
    //time_t end;
   
   //Initialise time keeping variables, time_t didnt display time when using OpenMPI.
   int starttime, endtime;
   starttime = MPI_Wtime();

    //Initialise OpenMPI process, get assigned rank in default communication channel.
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &myrank);
    MPI_Comm_size(MPI_COMM_WORLD, &inc);

    //Post recieves, fufilled by process that finds target in the future.
    MPI_Irecv(&rbuf, count, MPI_INT, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);

    //Four for loops, determine value of password characters position, 1,2,3,4
    for(int i = myrank; i < dict_len; i = i + inc){
      for(int j=0; j<dict_len; j++){
        for(int k=0; k<dict_len; k++){
          for(int l=0; l<dict_len; l++){
          //uncomment the below for loop when running second cipher because of difference in length
            //for(int m=0; m<dict_len; m++){

                    //check if another process has broadcasted that it found the target password.
                    MPI_Test(&req, &flag, &status);
                    if(flag == 1){
                        printf("Another process has found the key, exiting...\n");
                        MPI_Finalize();
                    }

                    //Password character at postion 0 determined by rank.
                    *password = dict[i];
                    *(password+1) = dict[j];
                    *(password+2) = dict[k];
                    *(password+3) = dict[l];
                    //uncomment the below when running second cipher because of difference in length
                    //*(password+4) = dict[m];

                    //Initialize and begin AES decryption.
                    initAES(password, salt, key, iv);
                    unsigned char* result = decrypt(ciphertext, cipher_len, key, iv);

                    //test success value returned by the decrypt AES function.
                    if (success == 1){
                        //Compare decryption attempt and target plaintext (sometimes success value can return false positives).
                        if(checkPlaintext(plaintext, result)==0){
                         
                         //broadcast message to tell other process that target has been found
                            MPI_Bcast(&sbuf, count, MPI_INT, myrank, MPI_COMM_WORLD);

                            //print results.
                           printf("Password is %s\n", password);
                                
                               // time_t end = time(NULL);
                               // printf("Time elpased is %ld seconds", (end - begin));
                                //return 0;
                                endtime = MPI_Wtime();
                                printf("Time elpased is %d seconds\n", endtime-starttime);
                                

                            /*
                                MPI_Abort kills all processes related to the caller
                                It can cause data loss, but the process calling it in this case has already found the target.
                            */
                            MPI_Abort(MPI_COMM_WORLD, err);
                            //exit(0);
                        }
                    }
                    //free result memeory (program previously seg faulted due to compounding memory usage).
                    free(result);

                    
                }
            }
        }
    }
//uncomment the below when running second cipher because of difference in length
 // }


    // Clean up
    EVP_cleanup();
    ERR_free_strings();
    MPI_Finalize();
}
