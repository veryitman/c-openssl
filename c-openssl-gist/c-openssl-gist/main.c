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
	printf("Base64 encode output: %s\n", base64EncodeOutput);

	//Decode From Base64
	char* base64DecodeOutput;
	size_t decode_output_length;
	const char *base64Encode_str = "aHR0cDovL3ZlcnlpdG1hbi5jb20=";
	mzc_base64_decode(base64Encode_str, &base64DecodeOutput, &decode_output_length);
	printf("Base64 decode output: %s, length:%d\n", base64DecodeOutput, decode_output_length);
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
	printf("Encrypted length =%d\n", len);

	// 私钥加密
	int encrypted_length = private_key_encrypt(plainText, len, privateKey, encrypted_str);
	if (encrypted_length == -1)
	{
		printf("Private Encrypt failed\n");
		exit(0);
	}
	printf("Encrypted length =%d\n", encrypted_length);

	// 公钥解密
	int decrypted_length = public_key_decrypt(encrypted_str, encrypted_length, publicKey, decrypted_str);
	if (decrypted_length == -1)
	{
		printf("Public Decrypt failed\n");
		exit(0);
	}

	printf("Decrypted Text =%s\n", decrypted_str);
	printf("Decrypted Length =%d\n", decrypted_length);
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
	printf("Encrypted length =%d\n", len);

	// 公钥加密
	int encrypted_length = public_key_encrypt(plainText, len, publicKey, encrypted_str);
	if (encrypted_length == -1)
	{
		printf("Private Encrypt failed\n");
		exit(0);
	}

	// 私钥解密
	int decrypted_length = private_key_decrypt(encrypted_str, encrypted_length, privateKey, decrypted_str);
	if (decrypted_length == -1)
	{
		printf("Public Decrypt failed\n");
		exit(0);
	}

	printf("Decrypted Text =%s\n", decrypted_str);
	printf("Decrypted Length =%d\n", decrypted_length);
}

int main()
{
	//example_base64();

	//example_rsa();

	example_rsa2();

	return 0;
}