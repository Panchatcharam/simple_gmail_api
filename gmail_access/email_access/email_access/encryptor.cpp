#include "stdafx.h"
#include <iostream>
#include "encryptor.h"

Encryptor::Encryptor()
{
	// Initalize contexts
	aesEncryptContext = EVP_CIPHER_CTX_new();

	// Check if any of the contexts initializations failed
	if (aesEncryptContext == NULL)
	{
		std::cout << "\n Unable to create Encryptor" << std::endl;
		exit(1);
	}

	GenerateAesKey(&aesKey, &aesIv);
}

Encryptor::~Encryptor()
{
	EVP_CIPHER_CTX_free(aesEncryptContext);
	free(aesKey);
	free(aesIv);
}

int Encryptor::GenerateAesKey(unsigned char **aesKey, unsigned char **aesIv) 
{
	*aesKey = (unsigned char*)malloc(AES_KEYLEN / 8);
	*aesIv = (unsigned char*)malloc(AES_KEYLEN / 8);

	if (aesKey == NULL || aesIv == NULL) {
		return FAILURE;
	}
	
	if (RAND_bytes(*aesKey, AES_KEYLEN / 8) == 0) {
		return FAILURE;
	}

	if (RAND_bytes(*aesIv, AES_KEYLEN / 8) == 0) {
		return FAILURE;
	}

	return SUCCESS;
}

int Encryptor::AESEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encryptedMsg)
{
	// Allocate memory for everything
	size_t blockLength = 0;
	size_t encrypMsgLen = 0;

	*encryptedMsg = (unsigned char*)malloc(msgLen + AES_BLOCK_SIZE);
	if (encryptedMsg == NULL)
	{
		return FAILURE;
	}

	// Encrypt it!
	if (!EVP_EncryptInit_ex(aesEncryptContext, EVP_aes_256_cbc(), NULL, aesKey, aesIv))
	{
		return FAILURE;
	}

	if (!EVP_EncryptUpdate(aesEncryptContext, *encryptedMsg, (int*)&blockLength, (unsigned char*)msg, msgLen))
	{
		return FAILURE;
	}
	encrypMsgLen += blockLength;

	if (!EVP_EncryptFinal_ex(aesEncryptContext, *encryptedMsg + encrypMsgLen, (int*)&blockLength)) 
	{
		return FAILURE;
	}
	return encrypMsgLen + blockLength;
}

char* Encryptor::EncryptGivenFile(char *filename)
{
	// Read the file to encrypt
	unsigned char *file;
	size_t fileLength = ReadFile(filename, &file);
	//std::cout << fileLength << " bytes to be encrypted" << std::endl;

	// Encrypt the file
	unsigned char *encryptedFile;
	int encryptedFileLength = AESEncrypt((const unsigned char*)file, fileLength, &encryptedFile);

	if (encryptedFileLength == -1) 
	{
		std::cout << "\n Encryption failed" << std::endl;
		exit(1);
	}

	// Write the encrypted file to its own file
	WriteFile(filename, encryptedFile, encryptedFileLength);
	free(file);
	return filename;
}

void Encryptor::WriteFile(char *filename, unsigned char *file, size_t fileLength) 
{
	remove(filename);
	FILE *fd = fopen(filename, "wb");
	if (fd == NULL)
	{
		std::cout << "Failed to open file " << std::endl;
		exit(1);
	}

	size_t bytesWritten = fwrite(file, 1, fileLength, fd);

	if (bytesWritten != fileLength)
	{
		std::cout << "Failed to write file " << std::endl;
		exit(1);
	}

	fclose(fd);
}

int Encryptor::ReadFile(char *filename, unsigned char **file) 
{
	FILE *fd = fopen(filename, "rb");
	if (fd == NULL) 
	{
		std::cout << "Failed to Open file " << std::endl;
		exit(1);
	}

	// Determine size of the file
	fseek(fd, 0, SEEK_END);
	size_t fileLength = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	// Allocate space for the file
	*file = (unsigned char*)malloc(fileLength);
	if (*file == NULL) 
	{
		std::cout << "Failed to allocate memory" << std::endl;
		exit(1);
	}

	// Read the file into the buffer
	size_t bytesRead = fread(*file, 1, fileLength, fd);

	if (bytesRead != fileLength)
	{
		std::cout << "Error reading file" << std::endl;
		exit(1);
	}

	fclose(fd);

	return fileLength;
}