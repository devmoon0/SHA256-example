/**
@file KISA_SHA_256.h
@brief SHA256 암호 알고리즘
@author Copyright (c) 2013 by KISA
@remarks http://seed.kisa.or.kr/
*/
#ifndef SHA256_H_
#define SHA256_H_

#if WIN32 || KISA_WINMO_32
typedef unsigned __int64	uint64_t;
typedef unsigned int		uint32_t;
typedef unsigned int		uint16_t;
typedef unsigned char		uint8_t;
#else
#include <stdint.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif


#define SHA256_DIGEST_BLOCKLEN	64	/** SHA256 블럭 크기*/
#define SHA256_DIGEST_VALUELEN	32 /** SHA256 Digest Output 크기*/

#ifdef __cplusplus
extern "C"
{
#endif

/**
@brief SHA256 Digest를 위한 SHA256 구조체
*/
typedef struct {
	uint8_t  szBuffer[SHA256_DIGEST_BLOCKLEN];
	uint32_t uChainVar[SHA256_DIGEST_VALUELEN / 4];
	uint32_t uHighLength[2];
	// uint32_t uHighLength;
	// uint32_t uLowLength;
	uint32_t len;
} SHA256_INFO;

/**
@brief 연쇄변수와 길이변수를 초기화하는 함수(SHA256 Digest를 위한 구조체 초기화 함수)
@param Info : SHA256_Process 호출 시 사용되는 구조체(미리 메모리가 할당되어 있어야 함)
@returns : 초기화 성공 (1) / 메모리가 적절히 할당되지 않았을 경우 (0)
*/
int SHA256_Init(SHA256_INFO *Info);

/**
@brief 연쇄변수와 길이변수를 초기화하는 함수
@param Info : SHA256_Init 호출하여 초기화된 구조체(내부적으로 사용된다.)
@param pszMessage : 사용자 입력 평문
@param inLen : 사용자 입력 평문 길이
@returns : 초기화 성공 (1) / 메모리가 적절히 할당되지 않았을 경우 (0)
*/
int SHA256_Process(SHA256_INFO *Info, const void *pszMessage, size_t uDataLen);

/**
@brief 메시지 덧붙이기와 길이 덧붙이기를 수행한 후 마지막 메시지 블록을 가지고 압축함수를 호출하는 함수
@param Info : SHA256_Init 호출하여 초기화된 구조체(내부적으로 사용된다.)
@param pszDigest : 암호문(해시생성 결과가 입력될 버퍼)
@returns : 초기화 성공 (1) / 메모리가 적절히 할당되지 않았을 경우 (0)
*/
int SHA256_Close(SHA256_INFO *Info, uint8_t *pszDigest);

/**
@brief 사용자 입력 평문을 한번에 처리(SHA256 Digest 처리 함수)
@param pszMessage : 사용자 입력 평문
@param uPlainTextLen : 사용자 입력 평문 길이
@param pszDigest : 암호문(해시생성 결과가 입력될 버퍼)
@remarks 내부적으로 SHA256_Init, SHA256_Process, SHA256_Close를 호출한다.
@returns : 구동 성공 (생성된 해시의 길이) / 메모리 할당 혹은 초기화가 적절히 이루어지지 않았을 경우 (0)
*/
int SHA256_Encrpyt(const void *pszMessage, size_t uPlainTextLen, uint8_t *pszDigest);

/**
@brief 사용자 입력 파일을 한번에 처리
@param path : 사용자 입력 파일 경로
@param pszDigest : 암호문(해시생성 결과가 입력될 버퍼)
@remarks 파일을 읽어 내부적으로 SHA256_Init, SHA256_Process, SHA256_Close를 호출한다.
@returns : 구동 성공 (생성된 해시의 길이) / 메모리 할당 혹은 초기화가 적절히 이루어지지 않았을 경우 (0)
*/
int FILE_SHA256_Encrpyt(char* path,  uint8_t *pszDigest);

#ifdef __cplusplus
}
#endif

#endif
