#pragma once

/************************************************************************/
/* From: https://gist.github.com/barrysteyn/7308212                     */
/************************************************************************/

//Decodes a base64 encoded string
int mzc_base64_decode(char *b64message, unsigned char **buffer, size_t *length); 

//Encodes a binary safe base 64 string
int mzc_base64_encode(const unsigned char *buffer, size_t length, char **b64text);