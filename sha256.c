#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FN_ inline static

static const uint32_t SHA256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#ifdef MINIMIZE_STACK_IMPACT
static uint32_t W[64];
#endif

/* -------------------------------------------------------------------------- */
FN_ uint8_t _shb(uint32_t x, uint32_t n)
{
	return ( (x >> (n & 31)) & 0xff );
} /* _shb */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _shw(uint32_t x, uint32_t n)
{
	return ( (x << (n & 31)) & 0xffffffff );
} /* _shw */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _r(uint32_t x, uint8_t n)
{
	return ( (x >> n) | _shw(x, 32 - n) );
} /* _r */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return ( (x & y) ^ ((~x) & z) );
} /* _Ch */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _Ma(uint32_t x, uint32_t y, uint32_t z)
{
	return ( (x & y) ^ (x & z) ^ (y & z) );
} /* _Ma */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _S0(uint32_t x)
{
	return ( _r(x, 2) ^ _r(x, 13) ^ _r(x, 22) );
} /* _S0 */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _S1(uint32_t x)
{
	return ( _r(x, 6) ^ _r(x, 11) ^ _r(x, 25) );
} /* _S1 */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _G0(uint32_t x)
{
	return ( _r(x, 7) ^ _r(x, 18) ^ (x >> 3) );
} /* _G0 */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _G1(uint32_t x)
{
	return ( _r(x, 17) ^ _r(x, 19) ^ (x >> 10) );
} /* _G1 */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _word(uint8_t *c)
{
	return ( _shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]) );
} /* _word */

/* -------------------------------------------------------------------------- */
FN_ void  _addbits(SHA256_INFO *Info, uint32_t n)
{
	if ( Info->uHighLength[0] > (0xffffffff - n) )
		Info->uHighLength[1] = (Info->uHighLength[1] + 1) & 0xFFFFFFFF;
	Info->uHighLength[0] = (Info->uHighLength[0] + n) & 0xFFFFFFFF;
} /* _addbits */

/* -------------------------------------------------------------------------- */
static void _hash(SHA256_INFO *Info)
{
	register uint32_t a, b, c, d, e, f, g, h, i;
	uint32_t t[2];
#ifndef MINIMIZE_STACK_IMPACT
	uint32_t W[64];
#endif

	a = Info->uChainVar[0];
	b = Info->uChainVar[1];
	c = Info->uChainVar[2];
	d = Info->uChainVar[3];
	e = Info->uChainVar[4];
	f = Info->uChainVar[5];
	g = Info->uChainVar[6];
	h = Info->uChainVar[7];

	for (i = 0; i < 64; i++) {
		if ( i < 16 )
			W[i] = _word(&Info->szBuffer[_shw(i, 2)]);
		else
			W[i] = _G1(W[i - 2]) + W[i - 7] + _G0(W[i - 15]) + W[i - 16];

		t[0] = h + _S1(e) + _Ch(e, f, g) + SHA256_K[i] + W[i];
		t[1] = _S0(a) + _Ma(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t[0];
		d = c;
		c = b;
		b = a;
		a = t[0] + t[1];
	}

	Info->uChainVar[0] += a;
	Info->uChainVar[1] += b;
	Info->uChainVar[2] += c;
	Info->uChainVar[3] += d;
	Info->uChainVar[4] += e;
	Info->uChainVar[5] += f;
	Info->uChainVar[6] += g;
	Info->uChainVar[7] += h;
}

//*********************************************************************************************************************************
// o SHA256_Init()		: 연쇄변수와 길이변수를 초기화하는 함수
// o 입력				: Info		-  SHA-256 구조체의 포인터 변수
// o 출력				: 
//*********************************************************************************************************************************
void SHA256_Init(SHA256_INFO *Info)
{
	if ( Info != NULL ) {
		Info->uHighLength[0]  = Info->uHighLength[1] = 0;
		Info->len      = 0;
		Info->uChainVar[0] = 0x6a09e667;
		Info->uChainVar[1] = 0xbb67ae85;
		Info->uChainVar[2] = 0x3c6ef372;
		Info->uChainVar[3] = 0xa54ff53a;
		Info->uChainVar[4] = 0x510e527f;
		Info->uChainVar[5] = 0x9b05688c;
		Info->uChainVar[6] = 0x1f83d9ab;
		Info->uChainVar[7] = 0x5be0cd19;
	}
}

//*********************************************************************************************************************************
// o SHA256_Process()	: 임의의 길이를 가지는 입력 메시지를 512 비트 블록 단위로 나누어 압축함수를 호출하는 함수
// o 입력				: Info		 - SHA-256 구조체의 포인터 변수
//						  pszMessage - 입력 메시지의 포인터 변수
//						  uDataLen	 - 입력 메시지의 바이트 길이
// o 출력				: 
//*********************************************************************************************************************************
void SHA256_Process(SHA256_INFO *Info, const void *pszMessage, size_t uDataLen)
{
	register size_t i;
	const uint8_t *bytes = (const uint8_t *)pszMessage;

	if ( (Info != NULL) && (bytes != NULL) )
		for (i = 0; i < uDataLen; i++) {
			Info->szBuffer[Info->len] = bytes[i];
			Info->len++;
			if (Info->len == sizeof(Info->szBuffer) ) {
				_hash(Info);
				_addbits(Info, sizeof(Info->szBuffer) * 8);
				Info->len = 0;
			}
		}
}

//*********************************************************************************************************************************
// o SHA256_Close()		: 메시지 덧붙이기와 길이 덧붙이기를 수행한 후 마지막 메시지 블록을 가지고 압축함수를 호출하는 함수
// o 입력				: Info	    - SHA-256 구조체의 포인터 변수
//						  pszDigest	- SHA-256 해쉬값을 저장할 포인터 변수
// o 출력				:
//*********************************************************************************************************************************
void SHA256_Close(SHA256_INFO *Info, uint8_t *pszDigest)
{
	register uint32_t i, j;

	if ( Info != NULL ) {
		j = Info->len % sizeof(Info->szBuffer);
		Info->szBuffer[j] = 0x80;
		for (i = j + 1; i < sizeof(Info->szBuffer); i++)
			Info->szBuffer[i] = 0x00;

		if ( Info->len > 55 ) {
			_hash(Info);
			for (j = 0; j < sizeof(Info->szBuffer); j++)
				Info->szBuffer[j] = 0x00;
		}

		_addbits(Info, Info->len * 8);
		Info->szBuffer[63] = _shb(Info->uHighLength[0],  0);
		Info->szBuffer[62] = _shb(Info->uHighLength[0],  8);
		Info->szBuffer[61] = _shb(Info->uHighLength[0], 16);
		Info->szBuffer[60] = _shb(Info->uHighLength[0], 24);
		Info->szBuffer[59] = _shb(Info->uHighLength[1],  0);
		Info->szBuffer[58] = _shb(Info->uHighLength[1],  8);
		Info->szBuffer[57] = _shb(Info->uHighLength[1], 16);
		Info->szBuffer[56] = _shb(Info->uHighLength[1], 24);
		_hash(Info);

		if ( pszDigest != NULL )
			for (i = 0, j = 24; i < 4; i++, j -= 8) {
				pszDigest[i     ] = _shb(Info->uChainVar[0], j);
				pszDigest[i +  4] = _shb(Info->uChainVar[1], j);
				pszDigest[i +  8] = _shb(Info->uChainVar[2], j);
				pszDigest[i + 12] = _shb(Info->uChainVar[3], j);
				pszDigest[i + 16] = _shb(Info->uChainVar[4], j);
				pszDigest[i + 20] = _shb(Info->uChainVar[5], j);
				pszDigest[i + 24] = _shb(Info->uChainVar[6], j);
				pszDigest[i + 28] = _shb(Info->uChainVar[7], j);
			}
	}
}
//*********************************************************************************************************************************
// o SHA256_Encrpyt()  : 사용자 입력 평문을 한번에 처리
// o 입력				: pszMessage - 사용자 입력 평문
//						 pszDigest	- SHA-256 해값을 저장할 포인터 변수
// o 출력				:
//*********************************************************************************************************************************
void SHA256_Encrpyt(const void *pszMessage, size_t uPlainTextLen, uint8_t *pszDigest)
{
	SHA256_INFO Info;

	SHA256_Init(&Info);
	SHA256_Process(&Info, pszMessage, uPlainTextLen);
	SHA256_Close(&Info, pszDigest);
}


//*********************************************************************************************************************************
// o SHA256_Encrpyt()  : 사용자 입력 파일을 한번에 처리
// o 입력				: path - 사용자 입력 파일 경로
//						 pszDigest	- SHA-256 해값을 저장할 포인터 변수
// o 출력				:
//*********************************************************************************************************************************
void FILE_SHA256_Encrpyt(char* path,  uint8_t *pszDigest)
{
	const int bufSize = 1024;
	SHA256_INFO Info;

	/*file open*/ 
  	FILE* file = fopen(path, "rb");
	if (!file) 
	{ 
		printf("File open ERR \n"); 
		return ; 
	} 
	printf("File open \n\n");

	/*sha256 init*/ 
	SHA256_Init(&Info);
	printf("SHA256 Init \n\n");

	int readlen = 0;
	unsigned char* read_buf = (unsigned char*)malloc(bufSize + 1);

	if (!read_buf) return ;
	while ((readlen = fread(read_buf, 1, bufSize, file)))
	{ 
		printf("readlen [%d]\n", readlen);
		SHA256_Process(&Info, read_buf, readlen);
		memset(read_buf, 0x00, bufSize);
	}
	printf("File read \n\n"); 
	SHA256_Close(&Info, pszDigest);

	fclose(file);
	if(read_buf)
  		free(read_buf);
}

// ref : https://github.com/ilvn/SHA256/tree/master/mark2 
int main(void)
{
	// char *buf[] = {
	// 	"abc"
	// };
	uint8_t hash[SHA256_DIGEST_VALUELEN];
	size_t i, j;

	char *path = "/home/moon/workspace/kisa_sha256/test_readme.md"; // file path

	FILE_SHA256_Encrpyt(path,hash);
	
	printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"); 
		for (j = 0; j < SHA256_DIGEST_VALUELEN; j++)
			printf("%02x%s", hash[j], ((j % 4) == 3) ? "" : "");
	printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"); 
	// for (i = 0; i < (sizeof(buf) / sizeof(buf[0])); i += 2) {
	// 	SHA256_Encrpyt(buf[i], strlen(buf[i]), hash);
	// 	printf("input = '%s'\ndigest: %s\nresult: ", buf[i], buf[i + 1]);
	// 	for (j = 0; j < SHA256_DIGEST_VALUELEN; j++)
	// 		printf("%02x%s", hash[j], ((j % 4) == 3) ? " " : "");
	// 	printf("\n\n");
	// }

	return 0;
}
