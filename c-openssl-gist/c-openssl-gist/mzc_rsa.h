#pragma once

/* ¹«Ô¿½âÃÜ */
int public_key_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);

/* Ë½Ô¿¼ÓÃÜ */
int private_key_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);

/* ¹«Ô¿¼ÓÃÜ */
int public_key_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);

/* Ë½Ô¿½âÃÜ */
int private_key_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);
