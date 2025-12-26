/**
 * file NICrypto.h
 * brief NICrypto모듈의 API목록과 필요 정보를 제공한다.
 * author Copyright (c) 2017 by NetID
 * remarks
 **/

#ifndef HEADER_NICRYPTO_H
#define HEADER_NICRYPTO_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif
	

/***************************************** 운영체제 정보 ******************************************/
/**
 * brief 운영체제 정보를 찾는과정
 * remarks 
 *		 Windows관련 매크로와 Linux관련 매크로가 둘다 정의되지 않았을 경우
 *		 운영체제는 디폴트로 Linux로 간주되며, 
 *		 Windows관련 매크로와 Linux관련 매크로가 둘다 정의되었을 경우
 *		 운영체제는 Windows로 간주된다.
 *
 *		 Windows관련 매크로에는 _WIN32, _WIN64 등이 있고,
 *		 Linux  관련 매크로에는 __linux__, linux 등이 있다.
 **/
	
/**
 * brief 디폴트 정의 운영체제 정보 : Linux
 **/
# define NICRYPTO_SYS_LINUX
	
/* ------------------------------- Windows --------------------------------- */
#if defined(_WIN32)
# undef NICRYPTO_SYS_LINUX
# define NICRYPTO_SYS_WIN32
#endif
#if defined(_WIN64)
# undef NICRYPTO_SYS_LINUX
# define NICRYPTO_SYS_WIN64
#endif
	
#if defined(NICRYPTO_SYS_WIN32) || defined(NICRYPTO_SYS_WIN64)
# undef NICRYPTO_SYS_LINUX
# define NICRYPTO_SYS_WINDOWS
#endif 
	
#if defined(NICRYPTO_SYS_WINDOWS) && defined(_WINDLL)
# define NICRYPTO_OPT_WINDLL
#endif 
	
/* -------------------------------- Linux ---------------------------------- */
#if !defined(NICRYPTO_SYS_WINDOWS) && defined(__linux__) || defined(linux)
# if !defined(NICRYPTO_SYS_LINUX)
#  define NICRYPTO_SYS_LINUX
# endif 
#endif	

/* ----------------------------- Windows DLL ------------------------------- */
#if defined(NICRYPTO_SYS_WINDOWS)
# if defined(NICRYPTO_OPT_WINDLL)
#  define NICRYPTO_API __declspec(dllexport)
# else
#  define NICRYPTO_API __declspec(dllimport)
# endif
#else
# if defined(NICRYPTO_SYS_LINUX)
#  define NICRYPTO_API 
# endif 
#endif

/****************************************** 공통 정보 *********************************************/

#define IN  
#define OUT 
#define INOUT 		

/******************************************** ARIA ***********************************************/

/**
 * brief ARIA 키길이
 * remarks
 *		 키생성API(NICryptoCreateKey)에서 사용한다.
 **/
#define ARIA128		128
#define ARIA192		192
#define ARIA256		256

/**
 * brief ARIA 운영모드 정보
 **/
#define ECB_MODE	1
#define CBC_MODE	2
#define CTR_MODE	3

/**
 * brief 'ARIA 암복호화의 기본단위'인 한블럭의 바이트크기
 **/
#define ARIA_BLOCK_SIZE	16		

/******************************************** HASH ***********************************************/

/**
 * brief HASH 알고리즘 정보
 **/
#define _SHA256 256
#define _SHA512 512

#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64

typedef uint32_t SHA256_WORD;
typedef uint64_t SHA512_WORD;

typedef union sha_word {
	SHA256_WORD sha256var;
	SHA512_WORD sha512var;
}SHA_WORD;

/**
 * brief 해시값 생성과정에서 사용될 해시 컨텍스트 구조체.
 * member is_initiated		: 해시 컨텍스트 초기화 함수를 거쳤는지 여부
 * member hash_type			: 해시 알고리즘 종류(SHA256, SHA512)
 * member chain_variable	: SHA256연쇄변수(cv256) / SHA512연쇄변수(cv512)
 * member high_length		: 해시대상이 되는 메시지의 비트 길이정보를 나타내는 변수1
 * member low_length		: 해시대상이 되는 메시지의 비트 길이정보를 나타내는 변수2
 * remarks 
 *		 is_initiated이 true여야 Hash함수 호출이 가능하다.
 */
typedef struct hash_st {
	bool	 is_initiated;
	uint32_t hash_type;	
	union
	{
		SHA256_WORD cv256[8];
		SHA512_WORD cv512[8];
	}chain_variable;
	SHA_WORD high_length;
	SHA_WORD low_length;
}HASH_CONTEXT;


/********************************************* KEY ***********************************************/
#define KEY_BUFFER_LEN 120 

/******************************* 갱신주기(초기화 함수의 인자) 정보 **********************************/
#define PREDICTION_RESISTANCE	0

/******************************************* 버전 정보 ********************************************/

/**
 * brief 버전정보 관련 텍스트가 담길 버퍼의 최소 크기
 **/
#if defined(NICRYPTO_SYS_WINDOWS)
# define VERSION_INFO_LEN 90 // copyright를 (c)로 표기할 때기준
#elif defined(NICRYPTO_SYS_LINUX)
# define VERSION_INFO_LEN 85 // copyright를 (c)로 표기할 때기준
#endif






/***************************************** NICrypto API ******************************************/
/**
 * brief NICrypto 모듈에서 제공하는 API의 함수 선언
 * remarks 
 *		 제공하는 API의 기능은 다음과 같다.
 *
 *		 [1] 암호		 : NICryptoEncrypt,	  NICryptoDecrypt,   NICryptoHashInit, NICryptoHash
 *		 [2] 키관리		 : NICryptoCreateKey, NICryptoDeleteKey, NICryptoGetKey,   NICryptoSetKey
 *		 [3] 난수생성	 : NICryptoGenerateRandom
 *		 [4] 자가시험	 : NICryptoSelfTest
 *		 [5] 초기화		 : NICryptoInitialize
 *		 [6] 종료		 : NICryptoFinalize
 *		 [7] 상태표시	 : NICryptoGetStatus
 *		 [8] 오류확인	 : NICryptoGetLastError
 *		 [9] 버전정보표시 : NICryptoGetVersion
 **/



/* ------------------------------ 암호 서비스 ------------------------------- */

/**
 @brief 암호화 키에 해당되는 운영모드로 ARIA 암호화 하는 함수
 @param key_id			: 암호화 키에 대한 참조 값
 @param plaintext		: 암호화할 평문
 @param plaintext_len	: 평문의 길이
 @param counter			: CTR모드의 경우에 사용할 카운터 값. 
 @param ciphertext		: 암호화한 암호문이 담길 버퍼
 @param ciphertext_len	: 암호문이 담길 버퍼의 크기
 @param	return_len		: 실제 성공적으로 암호화된 암호문의 크기. 
 **/
NICRYPTO_API int NICryptoEncrypt(IN const uint32_t key_id, 
								 IN const uint8_t *plaintext, IN const uint32_t plaintext_len,
								 IN const uint64_t counter, 
								 OUT uint8_t *ciphertext, IN const uint32_t ciphertext_len, 
								 OUT uint32_t *return_len);
	
/**
 @brief 암호화 키에 해당되는 운영모드로 ARIA 복호화 하는 함수
 @param key_id			: 복호화 키에 대한 참조 값
 @param ciphertext		: 복호화할 암호문
 @param ciphertext_len	: 암호문의 길이
 @param counter			: CTR모드의 경우에 사용할 카운터 값. 
 @param plaintext		: 복호화한 복호문이 담길 버퍼
 @param plaintext_len	: 복호문이 담길 버퍼의 크기
 @param return_len		: 실제 성공적으로 복호화된 복호문의 크기
 **/
NICRYPTO_API int NICryptoDecrypt(IN const uint32_t key_id, 
								 IN const uint8_t *ciphertext, IN const uint32_t ciphertext_len,
								 IN const uint64_t counter, 
								 OUT uint8_t *plaintext, IN const uint32_t plaintext_len, 
								 OUT uint32_t *return_len);

/**
 @brief NICryptoHash를 호출하기에 앞서 선행되어야 하는 해시 컨텍스트 초기화함수.
 @param hash_info : 초기화할 해시 컨텍스트
 @param hash_type : 해시 알고리즘 종류(SHA256, SHA512)
 **/
NICRYPTO_API int NICryptoHashInit(OUT HASH_CONTEXT *hash_info, IN const uint32_t hash_type);

/**
 @brief SHA256혹은 SHA512 알고리즘에 의해 해시값을 생성하는 함수
 @param hash_info	: 해시값 생성과정에서 사용되는 해시컨텍스트. 초기화가 선행되어야한다. 
 @param message		: 해시값을 생성할 대상이 되는 메시지
 @param message_len : 메시지의 바이트 길이
 @param digest		: 해시 알고리즘에 따라 생성된 해시값이 담길 버퍼
 @param digest_len	: 해시값이 담길 버퍼의 크기
 @param return_len	: 실제 성공적으로 생성된 해시값의 크기
 @remarks
 @		digest에 NULL포인터를 주고 반복문을 활용하면 큰 데이터에 대한 해시값을 구할 수 있다.
 @
 @		해시값의 대상이되는 메시지의 최대길이는 SHA알고리즘에 따라 다음과 같다.
 @		[1] SHA256 : 2^64  - 1 (bits)
 @		[2] SHA512 : 2^128 - 1 (bits)
 **/
NICRYPTO_API int NICryptoHash(INOUT HASH_CONTEXT *hash_info, 
							  IN const uint8_t *message, IN const uint64_t message_len, 
							  OUT uint8_t *digest, IN const uint32_t digest_len, 
							  OUT uint32_t *return_len);



/* ----------------------------- 키 관리 서비스 ----------------------------- */

/**
 @brief 원하는 운영모드와 키길이에 대한 키를 생성하는 함수
 @param enc_mode	: 운영모드(ECB_MODE, CBC_MODE, CTR_MODE)
 @param key_len	    : 키길이(ARIA128, ARIA192, ARIA256)
 @param key_id	    : 생성한 키에 대한 참조 값
 **/
NICRYPTO_API int NICryptoCreateKey(IN const uint8_t enc_mode,
								   IN const uint32_t key_len, 
								   OUT uint32_t *key_id);

/**
 @brief 원하는 키에 대한 정보를 삭제하는 명시적 제로화 API
 @param key_id : 삭제할 키에 대한 참조 값 
 @remarks
 @		암호화에 사용한 키는 삭제하기전에 꼭 저장해야한다.
 **/
NICRYPTO_API int NICryptoDeleteKey(IN const uint32_t key_id);

/**
 @brief 키 출력을 위한 함수. 출력 원하는 키관련 정보를 암호화한 후 
 @		일정한처리를 거쳐 생성된 바이트 열을 반환한다.		
 @param key_id			: 출력 키에 대한 참조 값
 @param key_buffer		: 반환된 바이트 열이 담길 버퍼
 @param key_buffer_len	: 바이트 열이 담길 버퍼의 크기
 @param return_len		: 실제 성공적으로 반환된 바이트 열의 크기
 @remarks
 @		출력 이후엔 기존에 존재하던 (출력한)키를 삭제할 것을 권장한다.
 **/
NICRYPTO_API int NICryptoGetKey(IN const uint32_t key_id, 
								OUT uint8_t *key_buffer, IN const uint32_t key_buffer_len,
								OUT uint32_t *return_len);

/**
 @brief 키 설정을 위한 함수. NICryptoGetKey를 통해 얻은 바이트 열을 통해 
 @		키 관련 정보를 복원하여 설정한다.
 @param key_buffer		: 기존에 NICryptoGetKey를 통해 얻은 바이트 열이 담겨있는 버퍼
 @param key_buffer_len	: 바이트 열이 담겨있는 버퍼의 크기
 @param key_id			: 설정된 키에 대한 참조 값이 담길 변수
 **/
NICRYPTO_API int NICryptoSetKey(IN const uint8_t *key_buffer, IN const uint32_t key_buffer_len, 
								OUT uint32_t *key_id);



/* ---------------------------- 난수 생성 서비스 ---------------------------- */

/**
 @brief 원하는 바이트 길이만큼의 난수를 생성하는 함수
 @param required_random_bytes	: 생성할 난수의 바이트길이
 @param random_buffer			: 생성된 난수가 담길 버퍼
 @param random_buffer_len		: 생성된 난수가 담길 버퍼의 크기
 @param return_len				: 실제 생성된 난수의 크기
 @remarks
 **/
NICRYPTO_API int NICryptoGenerateRandom(IN const uint32_t required_random_bytes, 
										OUT uint8_t *random_buffer, IN const uint32_t random_buffer_len, 
										OUT uint32_t *return_len);



/* ---------------------------- 자가시험 서비스 ----------------------------- */

/**
 @brief 무결성검증과 핵심기능테스트를 수행하는 자가시험 함수
 **/
NICRYPTO_API int NICryptoSelfTest(void);



/* ----------------------------- 초기화 서비스 ------------------------------ */

/**
 @brief 난수발생기를 초기화하고 갱신주기를 새롭게 설정하는 함수
 @param reseed_interval : 설정할 갱신주기(리씨드 주기) 
 @remarks
 @		설정할 갱신주기의 최대값은 2^48이다.
 **/
NICRYPTO_API int NICryptoInitialize(IN const uint64_t reseed_interval);



/* ------------------------------ 종료 서비스 ------------------------------- */

/**
 @brief 모듈 종료함수
 @remarks
 @		모듈 종료함수가 호출된 이후에는 다른 API를 호출할 수 없다.
 **/
NICRYPTO_API int NICryptoFinalize(void);



/* ---------------------------- 상태표시 서비스 ----------------------------- */

/**
 @brief 현재 상태정보를 반환하는 함수
 @param status_info : 반환된 상태 정보가 담길 변수
 **/
NICRYPTO_API int NICryptoGetStatus(OUT uint32_t *status_info);



/* ---------------------------- 오류확인 서비스 ----------------------------- */

/**
 @brief 가장 최근에 발생한 에러정보를 반환하는 함수
 **/
NICRYPTO_API int NICryptoGetLastError(void);



/* -------------------------- 버전 정보표시 서비스 --------------------------- */

/**
 @brief 버전정보를 반환하는 함수
 @param version_info		: 반환된 버전정보가 담길 버퍼
 @param version_info_len	: 버전정보가 담길 버퍼의 크기. VERSION_INFO_LEN보다 크거나 같아야한다. 
 @param return_len			: 실제 성공적으로 반환된 버전정보의 크기
 **/
NICRYPTO_API int NICryptoGetVersion(OUT uint8_t *version_info, IN const uint32_t version_info_len, 
									OUT uint32_t *return_len);






/******************************************* 에러 정보 ********************************************/
/**
 * brief 에러 코드 정보표
 * remarks 
 *		 에러정보의 활용은 NICryptoGetLastError API의 반환값과 표를 대조하여 
 *		 가장 최근에 발생한 에러의 원인을 파악할 수 있다.
 **/


// 정상 동작 
#define NO_ERR								   	 0 

// 메모리 동적 할당 오류
#define ERR_MEMORY							 	 10

// 자가시험 실패
#define ERR_CRITICAL							 101 

// 실행할 수 없는 상태
#define ERR_INVALID_STATUS						 102

// 입력 버퍼의 크기 오류
#define ERR_INPUT_LEN							 103

// 출력 버퍼 크기 부족
#define ERR_OUTPUT_LEN							 104

// 부적절한 NULL 값
#define ERR_INVALID_NULL						 105

// 지원하지 않는 버전
#define ERR_VERSION								 106

// 최대 값 초과
#define ERR_MAX_VALUE							 107

// 정해진 형식에 맞지 않은 데이터
#define ERR_INVALID_FORMAT						 108

// 지원하지 않는 운영모드
#define ERR_ENC_MODE							 201

// 해시 타입 오류
#define ERR_HASH_TYPE							 301

// 해시 컨텍스트 초기화 안됨
#define ERR_HASH_NOT_INIT						 302

// 지원하지 않는 키 길이
#define ERR_KEY_LEN								 401 

// 키가 존재하지 않음
#define ERR_KEY_NOT_EXIST						 402 

// 최대 키 개수 초과
#define ERR_KEY_MAX								 403

// 키 버퍼 체크섬 오류
#define ERR_KEY_CHECKSUM						 404

// 잡음원 수집 오류
#define ERR_NOISE_SOURCE						 501

// 갱신주기 오류
#define ERR_INIT_RESEED_INTERVAL				 601



/******************************************* 상태 정보 ********************************************/
/**
* brief 상태 코드 정보표
* remarks
*		 상태정보의 활용은 NICryptoGetStatus API의 반환값과 표를 대조하여
*		 현재상태를 파악할 수 있다.
**/

// 전원 꺼짐
#define ST_POWER_OFF				0

// 전원 켜짐
#define ST_POWER_ON					1

// 동작전 자가시험
#define ST_POWER_ON_SELF_TEST		2

// 서비스 대기
#define ST_IDLE						3			

// CSP 입력
#define ST_SETKEY					4

// 자가 시험
#define ST_SELF_TEST				5

// 조건부 자가 시험
#define ST_CONDITIONAL_SELF_TEST	6

// 단순한 오류
#define ST_RECOVERABLE_ERROR		7

// 심각한 오류
#define ST_CRITICAL_ERROR			8

// 종료
#define ST_FINALIZE					9







#ifdef  __cplusplus
}
#endif
#endif /* HEADER_NICRYPTO_H */