/**
@file KISA_SHA_256.h
@brief SHA256 암호 알고리즘
@author Copyright (c) 2013 by KISA
@remarks http://seed.kisa.or.kr/
*/
#ifndef SHA256_H_
#define SHA256_H_

#include <stddef.h>
#ifdef _MSC_VER
#ifndef uint8_t
typedef unsigned __int8 uint8_t;
#endif
#ifndef uint32_t
typedef unsigned __int32 uint32_t;
#endif
#else
#include <stdint.h>
#endif
#define SHA256_DIGEST_BLOCKLEN	64
#define SHA256_DIGEST_VALUELEN	32

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
	uint8_t  szBuffer[SHA256_DIGEST_BLOCKLEN];
	uint32_t uChainVar[SHA256_DIGEST_VALUELEN / 4];
	uint32_t uHighLength[2];
	uint32_t len;
} SHA256_INFO;

/**
@brief 연쇄변수와 길이변수를 초기화하는 함수
@param Info : SHA256_Process 호출 시 사용되는 구조체
*/
void SHA256_Init(SHA256_INFO *Info);

/**
@brief 연쇄변수와 길이변수를 초기화하는 함수
@param Info : SHA256_Init 호출하여 초기화된 구조체(내부적으로 사용된다.)
@param pszMessage : 사용자 입력 평문
@param inLen : 사용자 입력 평문 길이
*/
void SHA256_Process(SHA256_INFO *Info, const void *pszMessage, size_t uDataLen);

/**
@brief 메시지 덧붙이기와 길이 덧붙이기를 수행한 후 마지막 메시지 블록을 가지고 압축함수를 호출하는 함수
@param Info : SHA256_Init 호출하여 초기화된 구조체(내부적으로 사용된다.)
@param pszDigest : 암호문
*/
void SHA256_Close(SHA256_INFO *Info, uint8_t *pszDigest);

/**
@brief 사용자 입력 평문을 한번에 처리
@param pszMessage : 사용자 입력 평문
@param pszDigest : 암호문
@remarks 내부적으로 SHA256_Init, SHA256_Process, SHA256_Close를 호출한다.
*/
void SHA256_Encrpyt(const void *pszMessage, size_t uPlainTextLen, uint8_t *pszDigest);

/**
@brief 사용자 입력 파일을 한번에 처리
@param path : 사용자 입력 파일 경로
@param pszDigest : 암호문
@remarks 파일을 읽어 내부적으로 SHA256_Init, SHA256_Process, SHA256_Close를 호출한다.
*/
void FILE_SHA256_Encrpyt(char* path,  uint8_t *pszDigest);

#ifdef __cplusplus
}
#endif

#endif
