
#include "stdafx.h"
#include "TC_NICrypto.h"

#define SHA_MAX_LM_BYTE_LEN   102400 // Max Long Message byte length = 6400byte(51200bit)

bool TC_NICrypto::Run()
{
	NICryptoInitialize(1);

	// msg len = 1816
	string msg = "949589383707606EA4CC280A381D4B9BD0B6A563387C9415E7624EDDE98D78A11CB7F4879FD1FAB788EC6A62D5596003A60F09E4A94EB6E4D5822F795B6A4AF1D979BCFDD17D2E6F5B7E944316E9BADC64EE1F91D7260768E679CC21E53F757734A589A2B6522620844B4DB5E31480B174198F71AB4CAF28820ECCE06F5320BB9301057F349A07516D1B3EC12424DB073D58008C0D07D5AD120BD8BBE1EF74465F57D69B349BFC8B7DB60E6EC15FF26827751BEBE6A0A17DFC3697BC235B999F016DA4FE9F9F2A551CE366C5A30EEE5B9A3687951C5F3C22AA57B2EA1DDFB64EDF0B18";

	// 512 digest
	string answer = "515FB8387762EF74E4F137242763E8F97B3ED7AABA3F9D9000F02440B8255EC09762B66D9FEFABECB6EEFC1BA44883F2453EE9AAE319A38B189F1F3E4AB05CF8";

	string output1;
	HashTest_SingleBlock(msg, output1);


	string output2;
	HashTest_MultiBlock(msg, output2);

	NICryptoFinalize();

	return false;
}

void TC_NICrypto::HashTest_SingleBlock(const string & input, string & output)
{
	HASH_CONTEXT ctx;
	NICryptoHashInit(&ctx, _SHA512);

	uint8_t digest[64] = { 0 };
	uint32_t returnLen = 0;

	uint8_t msg[SHA_MAX_LM_BYTE_LEN];
	HexStringToByteArray(input.data(), input.size(), msg, sizeof(msg));

	NICryptoHash(&ctx, msg, input.size() / 2, digest, 64, &returnLen);

	char hexstr[64 * 2 + 1] = { 0 };
	ByteArrayToHexString(digest, 64, hexstr, sizeof(hexstr));

	output.assign(hexstr, hexstr + sizeof(hexstr));
}

void TC_NICrypto::HashTest_MultiBlock(const string & input, string & output)
{
	HASH_CONTEXT ctx;
	NICryptoHashInit(&ctx, _SHA512);

	uint8_t digest[64] = { 0 };
	uint32_t returnLen = 0;

	uint8_t msg[SHA_MAX_LM_BYTE_LEN];
	HexStringToByteArray(input.data(), input.size(), msg, sizeof(msg));

	auto t = input.size() / 2;

	// 227
	NICryptoHash(&ctx, msg, 99, nullptr, 0, nullptr);
	NICryptoHash(&ctx, msg, 128, nullptr, 0, nullptr);
	NICryptoHash(&ctx, nullptr, 0, digest, 64, &returnLen);

	char hexstr[64 * 2 + 1] = { 0 };
	ByteArrayToHexString(digest, 64, hexstr, sizeof(hexstr));

	output.assign(hexstr, hexstr + sizeof(hexstr));
}

void TC_NICrypto::HexStringToByteArray(const char * hexstr, const size_t hexstr_len, uint8_t * byte_buf, const size_t byte_buf_len)
{
	uint32_t  pos = 0;
	uint8_t  idx0 = 0, idx1 = 0;

	// 1바이트를 16진수로 표기하면 2글자씩 나옴. 즉, 2의 배수임을 전제.
	if (hexstr_len % 2 != 0)
		return;

	// 1은 NULL을 고려한 것
	if (byte_buf_len * 2 < hexstr_len - 1)
		return;

	// mapping of ASCII characters to hex values
	static const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
	};

	memset(byte_buf, 0, hexstr_len / 2);
	for (pos = 0; ((pos < (hexstr_len)) && (pos < strlen(hexstr))); pos += 2)
	{
		idx0 = ((uint8_t)hexstr[pos + 0] & 0x1F) ^ 0x10;
		idx1 = ((uint8_t)hexstr[pos + 1] & 0x1F) ^ 0x10;
		byte_buf[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
}

void TC_NICrypto::ByteArrayToHexString(const uint8_t * byte_buf, const size_t byte_buf_len, char * hexstr, size_t hexstr_len)
{
	// byte_buf_len * 2 + 1의 1은 NULL을 고려한 것
	if (hexstr_len < byte_buf_len * 2 + 1)
		return;

	for (size_t i = 0; i < byte_buf_len; i++, byte_buf++)
		sprintf_s(hexstr + i * 2, 3, "%02X", *byte_buf);
}

