#include <stdio.h>
#include <string.h>

#include "mzc_base64.h"

int main()
{
	//Encode To Base64
	char *base64EncodeOutput;

	//Take the web's url of my blog as example:http://veryitman.com
	char *text = "http:\/\/veryitman.com";

	mzc_base64_encode(text, strlen(text), &base64EncodeOutput);
	printf("Base64 encode output: %s\n", base64EncodeOutput);

	//Decode From Base64
	char* base64DecodeOutput;
	size_t decode_output_length;
	const char *base64Encode_str = "aHR0cDovL3ZlcnlpdG1hbi5jb20=";
	mzc_base64_decode(base64Encode_str, &base64DecodeOutput, &decode_output_length);
	printf("Base64 decode output: %s, length:%d\n", base64DecodeOutput, decode_output_length);

	return 0;
}