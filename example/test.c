#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <blowfish.h>

int randombytes_buf(unsigned char* abBuf, unsigned short wMax);
int ebc_usage(const char* szPlainText, const char* szKey);
int cbc_usage(const char* szPlainText, const char* szKey, uint64_t IV);

int ebc_usage(const char* szPlainText, const char* szKey)
{
  printf("Hello world blowfish ECB encryption mode usage!\n");

  char szWorkInput[64];
  size_t nPlainTextLen = strlen(szPlainText);
  if(nPlainTextLen >= sizeof(szWorkInput))
  {
    fprintf(stderr, "input plain text is too long! len: %zu\n", nPlainTextLen);
    return -1;
  }
  
  strcpy(szWorkInput, szPlainText);

  blowfish_t tECBCipher;
  blowfish_init(&tECBCipher, szKey, sizeof(szKey) - 1);
  blowfish_encrypt_buffer(&tECBCipher, szWorkInput, sizeof(szWorkInput) - 1);

  printf("ciphertext blowfish block1: %p, blowfish block2: %p\n", (void*)(*(uint64_t*)szWorkInput), (void*)(*((uint64_t*)szWorkInput + 1)));

  blowfish_t tECBDecryption;
  blowfish_init(&tECBDecryption, szKey, sizeof(szKey) - 1);
  blowfish_decrypt_buffer(&tECBDecryption, szWorkInput, sizeof(szWorkInput) - 1);

  if(strcmp(szPlainText, szWorkInput) != 0)
  {
    fprintf(stderr, "decrypt in failure! szPlainText: %s, szWorkInput: %s\n", szPlainText, szWorkInput);
    return -1;
  }

  printf("%s encrypt&decrypt is OK!\n", __func__);
  return 0;
}


int randombytes_buf(unsigned char* abBuf, unsigned short wMax)
{
  if(abBuf == NULL)
  {
    return -1;
  }

  FILE* fRandomDev = fopen("/dev/urandom", "rb");
  if(fRandomDev == NULL)
  {
    return -1;
  }

  size_t readNum = fread(abBuf, 1, wMax, fRandomDev);

  if(readNum != wMax)
  {
    return -1;
  }

  fclose(fRandomDev);
  return readNum;
}

int cbc_usage(const char* szPlainText, const char* szKey, uint64_t IV)
{
  printf("Hello world blowfish CCB encryption mode usage!\n");

  char szWorkInput[64];
  size_t nPlainTextLen = strlen(szPlainText);
  if(nPlainTextLen >= sizeof(szWorkInput))
  {
    fprintf(stderr, "input plain text is too long! len: %zu\n", nPlainTextLen);
    return -1;
  }
  
  strcpy(szWorkInput, szPlainText);

  blowfish_t tCCBCipher;
  blowfish_init(&tCCBCipher, szKey, sizeof(szKey) - 1);
  blowfish_encrypt_cbc_buffer(&tCCBCipher, szWorkInput, sizeof(szWorkInput) - 1, IV);

  printf("ciphertext blowfish block1: %p, blowfish block2: %p\n", (void*)(*(uint64_t*)szWorkInput), (void*)(*((uint64_t*)szWorkInput + 1)));

  blowfish_t tCCBDecryption;
  blowfish_init(&tCCBDecryption, szKey, sizeof(szKey) - 1);
  blowfish_decrypt_cbc_buffer(&tCCBDecryption, szWorkInput, sizeof(szWorkInput) - 1, IV);

  if(strcmp(szPlainText, szWorkInput) != 0)
  {
    fprintf(stderr, "CBC decrypt in failure! szPlainText: %s, szWorkInput: %s\n", szPlainText, szWorkInput);
    return -1;
  }

  printf("%s encrypt&decrypt is OK!\n", __func__);
  return 0;
}

int main(int argc, char* argv[])
{
  const char szPlainText[] = "abcdabcdabcdabcd";
  const char szKey[]       = "Hello World, blowfish!";

  int rc = ebc_usage(szPlainText, szKey);

  if(rc < 0)
  {
    return rc;
  }

  #ifndef __LINUX
  # error "Unsupported OS type! RtlGenRandom or Use libsodium's randombytes_buf function"
  fprintf(stderr, "Unsupported OS type! RtlGenRandom or Use libsodium's randombytes_buf function!\n");
  return -1;
  #endif

  
  uint64_t IV;
  rc = randombytes_buf((unsigned char*)&IV, sizeof(IV));
  if(rc != sizeof(IV))
  {
    fprintf(stderr, "randombytes_buf in failure!\n");
    return rc;
  }

  rc = cbc_usage(szPlainText, szKey, IV);

  if(rc < 0)
  {
    return rc;
  }

  printf("Exit from program !\n");
  return 0;
}
