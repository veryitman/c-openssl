#include <stdio.h>
#include <string.h>

#include "mzc_base64.h"
#include "mzc_rsa.h"

void example_base64() 
{
	//Take the web's url of my blog as example:http://veryitman.com
	char *text = "http:\/\/veryitman.com";

	//Encode To Base64
	char *base64EncodeOutput;
	mzc_base64_encode(text, strlen(text), &base64EncodeOutput);
	printf("Base64 encode output: %s\n\n", base64EncodeOutput);

	//Decode From Base64
	char* base64DecodeOutput;
	size_t decode_output_length;
	const char *base64Encode_str = "aHR0cDovL3ZlcnlpdG1hbi5jb20=";
	mzc_base64_decode(base64Encode_str, &base64DecodeOutput, &decode_output_length);
	printf("Base64 decode output: %s, length:%d\n\n", base64DecodeOutput, decode_output_length);
}

/* 私钥加密， 公钥解密 */
void example_rsa()
{
	//原始数据为字符串：www.veryitman.com
	unsigned char plainText[] = "www.veryitman.com";

	unsigned char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrPgCMJW17JN2DW7tZFk/FB6pU\n"
		"pLvLOo6G/EuND8XZptffXbyiY2VscMRhP+kKVeaLO9HuEYR3Zl78x8oR6prytstc\n"
	    "/MueersWDxh4iGSHsZXGxA41hXrXLRElrSTRc43ea18o0zMxZoVZiR2JFt7QcgM+\n"
		"T6eOrvj59MhXv9O46QIDAQAB\n"
		"-----END PUBLIC KEY-----\n";

	unsigned char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
		"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKs+AIwlbXsk3YNb\n"
		"u1kWT8UHqlSku8s6job8S40Pxdmm199dvKJjZWxwxGE/6QpV5os70e4RhHdmXvzH\n"
		"yhHqmvK2y1z8y556uxYPGHiIZIexlcbEDjWFetctESWtJNFzjd5rXyjTMzFmhVmJ\n"
		"HYkW3tByAz5Pp46u+Pn0yFe/07jpAgMBAAECgYBj1YH8MtXhNVzveEuBZMCc3hsv\n"
		"vdq+YSU3DV/+nXN7sQmp77xJ8CjxT80t5VS38dy2z+lUImJYOhamyNPGHkC2y84V\n"
		"7i5+e6ScQve1gnwHqRKGBjtSCaYOqm9rTDECCTT1oMU26sfYznWlJqMrkJp1jWn7\n"
		"aAwr+3FcX2XhD74ZAQJBAN34Y6fmHLRPv21MsdgGqUjKgyFvJfLUmtFFgb6sLEWc\n"
		"k22J3BAFAcNCTLYHFZwMhL/nwaw9/7rIUJD+lcl6n3cCQQDFfrN14qKC3GJfoBZ8\n"
		"k9S6F7Ss514DDPzIuenbafhoUjZDVcjLw9EmYZQjpfsQ3WdNICUKRrDHZay1Pz+s\n"
		"YkKfAkB+OKfaquS5t/t/2LPsxuTuipIEqiKnMjSTOfYsidVnBEFlcZZc2awF76aV\n"
		"f/PO1+OJCO2910ebXBtMSCi++GbDAkEAmc7zNPwsVH4OnyquWJdJNSUBMSd/sCCN\n"
		"PkaMOrVtINHmMMq+dvMqEBoupRS/U4Ma0JYYQsiLJL+qof2AOWDNQQJAcquLGHLT\n"
		"eGDDLluHo+kkIGwZi4aK/fDoylZ0NCEtYyMtShQ3JmllST9kmb9NJX2gMsejsirc\n"
		"H6ObxqZPbka6UA==\n"
		"-----END RSA PRIVATE KEY-----\n";

	unsigned char encrypted_str[128];
	unsigned char decrypted_str[128];

	// 需要初始化，否则解密出来的字符串会有多余的乱码
	memset(encrypted_str, '\0', sizeof(encrypted_str));
	memset(decrypted_str, '\0', sizeof(decrypted_str));

	size_t len = strlen((const char *)plainText);
	printf("Original string length =%d\n\n", len);

	// 私钥加密
	int encrypted_length = private_key_encrypt(plainText, len, privateKey, encrypted_str);
	if (-1 == encrypted_length)
	{
		printf("Private Encrypt failed\n");
		exit(0);
	}
	printf("Encrypted length =%d\n\n", encrypted_length);

	// 公钥解密
	int decrypted_length = public_key_decrypt(encrypted_str, encrypted_length, publicKey, decrypted_str);
	if (-1 == decrypted_length)
	{
		printf("Public Decrypt failed\n");
		exit(0);
	}

	printf("Decrypted Text =%s\n\n", decrypted_str);
	printf("Decrypted Length =%d\n\n", decrypted_length);
}

/* 公钥加密， 私钥解密 */
void example_rsa2()
{
	//原始数据为字符串：www.veryitman.com
	unsigned char plainText[] = "www.veryitman.com";

	unsigned char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrPgCMJW17JN2DW7tZFk/FB6pU\n"
		"pLvLOo6G/EuND8XZptffXbyiY2VscMRhP+kKVeaLO9HuEYR3Zl78x8oR6prytstc\n"
		"/MueersWDxh4iGSHsZXGxA41hXrXLRElrSTRc43ea18o0zMxZoVZiR2JFt7QcgM+\n"
		"T6eOrvj59MhXv9O46QIDAQAB\n"
		"-----END PUBLIC KEY-----\n";

	unsigned char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
		"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKs+AIwlbXsk3YNb\n"
		"u1kWT8UHqlSku8s6job8S40Pxdmm199dvKJjZWxwxGE/6QpV5os70e4RhHdmXvzH\n"
		"yhHqmvK2y1z8y556uxYPGHiIZIexlcbEDjWFetctESWtJNFzjd5rXyjTMzFmhVmJ\n"
		"HYkW3tByAz5Pp46u+Pn0yFe/07jpAgMBAAECgYBj1YH8MtXhNVzveEuBZMCc3hsv\n"
		"vdq+YSU3DV/+nXN7sQmp77xJ8CjxT80t5VS38dy2z+lUImJYOhamyNPGHkC2y84V\n"
		"7i5+e6ScQve1gnwHqRKGBjtSCaYOqm9rTDECCTT1oMU26sfYznWlJqMrkJp1jWn7\n"
		"aAwr+3FcX2XhD74ZAQJBAN34Y6fmHLRPv21MsdgGqUjKgyFvJfLUmtFFgb6sLEWc\n"
		"k22J3BAFAcNCTLYHFZwMhL/nwaw9/7rIUJD+lcl6n3cCQQDFfrN14qKC3GJfoBZ8\n"
		"k9S6F7Ss514DDPzIuenbafhoUjZDVcjLw9EmYZQjpfsQ3WdNICUKRrDHZay1Pz+s\n"
		"YkKfAkB+OKfaquS5t/t/2LPsxuTuipIEqiKnMjSTOfYsidVnBEFlcZZc2awF76aV\n"
		"f/PO1+OJCO2910ebXBtMSCi++GbDAkEAmc7zNPwsVH4OnyquWJdJNSUBMSd/sCCN\n"
		"PkaMOrVtINHmMMq+dvMqEBoupRS/U4Ma0JYYQsiLJL+qof2AOWDNQQJAcquLGHLT\n"
		"eGDDLluHo+kkIGwZi4aK/fDoylZ0NCEtYyMtShQ3JmllST9kmb9NJX2gMsejsirc\n"
		"H6ObxqZPbka6UA==\n"
		"-----END RSA PRIVATE KEY-----\n";

	unsigned char encrypted_str[128];
	unsigned char decrypted_str[128];

	// 需要初始化，否则解密出来的字符串会有多余的乱码
	memset(encrypted_str, '\0', sizeof(encrypted_str));
	memset(decrypted_str, '\0', sizeof(decrypted_str));

	size_t len = strlen((const char *)plainText);
	printf("Original string length =%d\n\n", len);

	// 公钥加密
	int encrypted_length = public_key_encrypt(plainText, len, publicKey, encrypted_str);
	if (-1 == encrypted_length)
	{
		printf("Private Encrypt failed\n");
		exit(0);
	}

	// 私钥解密
	int decrypted_length = private_key_decrypt(encrypted_str, encrypted_length, privateKey, decrypted_str);
	if (-1 == decrypted_length)
	{
		printf("Public Decrypt failed\n");
		exit(0);
	}

	printf("Decrypted Text =%s\n\n", decrypted_str);
	printf("Decrypted Length =%d\n", decrypted_length);
}

/* 综合示例：私钥加密 -> base64 encode -> base64 decode -> 公钥分段解密 */
void example_rsa3()
{
	// 原始数据为字符串：www.veryitman.com
	unsigned char plainText[] = "www.veryitman.com";

	unsigned char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrPgCMJW17JN2DW7tZFk/FB6pU\n"
		"pLvLOo6G/EuND8XZptffXbyiY2VscMRhP+kKVeaLO9HuEYR3Zl78x8oR6prytstc\n"
		"/MueersWDxh4iGSHsZXGxA41hXrXLRElrSTRc43ea18o0zMxZoVZiR2JFt7QcgM+\n"
		"T6eOrvj59MhXv9O46QIDAQAB\n"
		"-----END PUBLIC KEY-----\n";

	unsigned char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
		"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKs+AIwlbXsk3YNb\n"
		"u1kWT8UHqlSku8s6job8S40Pxdmm199dvKJjZWxwxGE/6QpV5os70e4RhHdmXvzH\n"
		"yhHqmvK2y1z8y556uxYPGHiIZIexlcbEDjWFetctESWtJNFzjd5rXyjTMzFmhVmJ\n"
		"HYkW3tByAz5Pp46u+Pn0yFe/07jpAgMBAAECgYBj1YH8MtXhNVzveEuBZMCc3hsv\n"
		"vdq+YSU3DV/+nXN7sQmp77xJ8CjxT80t5VS38dy2z+lUImJYOhamyNPGHkC2y84V\n"
		"7i5+e6ScQve1gnwHqRKGBjtSCaYOqm9rTDECCTT1oMU26sfYznWlJqMrkJp1jWn7\n"
		"aAwr+3FcX2XhD74ZAQJBAN34Y6fmHLRPv21MsdgGqUjKgyFvJfLUmtFFgb6sLEWc\n"
		"k22J3BAFAcNCTLYHFZwMhL/nwaw9/7rIUJD+lcl6n3cCQQDFfrN14qKC3GJfoBZ8\n"
		"k9S6F7Ss514DDPzIuenbafhoUjZDVcjLw9EmYZQjpfsQ3WdNICUKRrDHZay1Pz+s\n"
		"YkKfAkB+OKfaquS5t/t/2LPsxuTuipIEqiKnMjSTOfYsidVnBEFlcZZc2awF76aV\n"
		"f/PO1+OJCO2910ebXBtMSCi++GbDAkEAmc7zNPwsVH4OnyquWJdJNSUBMSd/sCCN\n"
		"PkaMOrVtINHmMMq+dvMqEBoupRS/U4Ma0JYYQsiLJL+qof2AOWDNQQJAcquLGHLT\n"
		"eGDDLluHo+kkIGwZi4aK/fDoylZ0NCEtYyMtShQ3JmllST9kmb9NJX2gMsejsirc\n"
		"H6ObxqZPbka6UA==\n"
		"-----END RSA PRIVATE KEY-----\n";

	unsigned char encrypted_str[128];
	unsigned char decrypted_str[128];

	// 需要初始化，否则解密出来的字符串会有多余的乱码
	memset(encrypted_str, '\0', sizeof(encrypted_str));
	memset(decrypted_str, '\0', sizeof(decrypted_str));

	size_t len = strlen((const char *)plainText);
	printf("Original content length：%d\n\n", len);

	// 私钥加密
	int encrypted_length = private_key_encrypt(plainText, len, privateKey, encrypted_str);
	if (-1 == encrypted_length)
	{
		printf("Private Encrypt failed\n");
		exit(0);
	}
	printf("Encrypted string: %s\n\n", encrypted_str);
	printf("Encrypted string's length =%d\n\n", encrypted_length);

	// base64 编码
	char *base64_content;
	size_t encrypted_str_length = strlen(encrypted_str);
	int encode_res = mzc_base64_encode(encrypted_str, encrypted_str_length, &base64_content);
	if (0 != encode_res)
	{
		printf("Base64 encode failed\n");
		exit(0);
	}
	printf("Base64 encode content: %s\n\n", base64_content);
	printf("Base64 encode content's length: %i\n\n", strlen(base64_content));


	// base64 解码
	char *base64DecodeOutput;
	size_t decode_output_length;
	int decode_res = mzc_base64_decode(base64_content, &base64DecodeOutput, &decode_output_length);
	printf("base64 decode content: %s\n\n", base64DecodeOutput);
	printf("base64 decode content's length: %i\n\n", strlen(base64DecodeOutput)); //160
	printf("base64 decode content's length: %i\n\n", decode_output_length); //160
	if (0 != decode_res)
	{
		printf("Base64 decode failed\n");
		exit(0);
	}

	// 最大解密长度
	#define RSA_MAX_DECRYPT_SIZE 128

	// 每段解密的长度
	int chunk = 0;
	unsigned char tmp_dstr[RSA_MAX_DECRYPT_SIZE];
	memset(tmp_dstr, '\0', sizeof(tmp_dstr));

	// （数据被）分段解密（公钥解密）
	while (chunk <= decode_output_length)
	{
		int decrypted_length = public_key_decrypt(base64DecodeOutput, RSA_MAX_DECRYPT_SIZE, publicKey, tmp_dstr);
		memcpy(decrypted_str, tmp_dstr, decrypted_length);
		printf("Current decrypted content length =%d\n", decrypted_length);
		if (-1 == decrypted_length)
		{
			printf("Public Decrypt failed\n");
			exit(0);
		}
		chunk += decrypted_length;
	}

	printf("......\n\n");
	printf("Final decrypted string =%s\n", decrypted_str);
}

int main()
{
	//example_base64();

	//example_rsa();

	//example_rsa2();

	example_rsa3();

	return 0;
}