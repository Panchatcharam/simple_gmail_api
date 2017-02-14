#pragma once
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define AES_KEYLEN 256
#define AES_ROUNDS 6
#define SUCCESS 0
#define FAILURE -1

class Encryptor
{
public:
	Encryptor();
	~Encryptor();
	char* EncryptGivenFile(char *filename);

private:
	int GenerateAesKey(unsigned char **aesKey, unsigned char **aesIv);
	void WriteFile(char *filename, unsigned char *file, size_t fileLength);
	int ReadFile(char *filename, unsigned char **file);
	int AESEncrypt(const unsigned char *msg, size_t msLen, unsigned char **encryptedMsg);

	// Data
	EVP_CIPHER_CTX *aesEncryptContext;
	unsigned char *aesKey;
	unsigned char *aesIv;
};