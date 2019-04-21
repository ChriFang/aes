#include <stdio.h>
#include <string.h>

#include "Aes.h"

char my_key[64] = {0};
int  my_key_len = 16;

void usage()
{
	printf("Usage: aes [-e/-d <file> <key> <key length>]\n");
	printf("eg. Decrypt: aes -d test.txt.aes 123abc 128\n");
	printf("eg. Encrypt: aes -e test.txt 123abc 128\n");
}

// 补全密码，如果密码不足指定的位数，用1补全
void fill_key(char* src_key, char* dest_key, int len)
{
	int src_len = strlen(src_key);
	if(len == 16){
		if(src_len < 16){
			strncpy(dest_key, src_key, src_len);
			strncpy(&dest_key[src_len], "1111111111111111", 16-src_len);
		}
	}
	else if(len == 24){
		if(src_len < 24){
			strncpy(dest_key, src_key, src_len);
			strncpy(&dest_key[src_len], "111111111111111111111111", 24-src_len);
		}
	}
	else{
		if(src_len < 32){
			strncpy(dest_key, src_key, src_len);
			strncpy(&dest_key[src_len], "11111111111111111111111111111111", 32-src_len);
		}
	}
}

int get_key(char* key, char* key_bits)
{
	if(key == NULL || key_bits == NULL){
		return -1;
	}
	if(strcmp(key_bits, "128") == 0){
		my_key_len = 16;
	}else if(strcmp(key_bits, "192") == 0){
		my_key_len = 24;
	}else if(strcmp(key_bits, "256") == 0){
		my_key_len = 32;
	}else{
		printf("Invalid key length %s, you can choose \"128, 192, 256\"\n", key_bits);
		return -1;
	}
	
	memset(my_key, 0, sizeof(my_key));
	fill_key(key, my_key, my_key_len);
	return 0;
}

// encrypt a file
int aes_encrypt_file(char* file_name){
	char out_file_name[128] = {0};
	if(file_name == NULL){
		printf("Invalid file name.\n");
		return -1;
	}
	FILE* fp_in = fopen(file_name, "rb");
	if(fp_in == NULL){
		printf("Cannot open file %s\n", file_name);
		return -1;
	}
	fseek(fp_in,0,SEEK_END);
	long lFileLen=ftell(fp_in); //ftell()函数返回文件位置指示符的当前值，即如果现在是在文件结尾，则这个值就是文件长度
	fseek(fp_in,0,SEEK_SET);
	long blocknum=lFileLen/16;
	long leftnum=lFileLen%16;
	
	snprintf(out_file_name, 128-1, "%s.aes", file_name);
	FILE* fp_out = fopen(out_file_name, "wb");
	if(fp_out == NULL){
		printf("Cannot open output file %s\n", out_file_name);
		return -1;
	}
	
	int i=0;
	unsigned char inBuff[25],ouBuff[25];
	Aes aes(my_key_len, (unsigned char*)my_key);
	for(i=0;i<blocknum;i++)
	{
		memset(inBuff, 0, sizeof(inBuff));
		memset(ouBuff, 0, sizeof(ouBuff));
		fread(inBuff,1,16,fp_in);  //读取16个对象，每个对象的长度是1字节
		aes.Cipher(inBuff,ouBuff);
		fwrite(ouBuff,1,16,fp_out);
	}
	if(leftnum)		// 处理最后16个字节
	{
		memset(inBuff,0,16);
		fread(inBuff,1,leftnum,fp_in);
		inBuff[16-1] = leftnum;
		aes.Cipher(inBuff,ouBuff);
		fwrite(ouBuff,1,16,fp_out);
	}
	else	// 末尾加16个空字节
	{
		memset(inBuff,0,16);
		aes.Cipher(inBuff,ouBuff);
		fwrite(ouBuff,1,16,fp_out);
	}
	fclose(fp_in);
	fclose(fp_out);
	
	return 0;
}

// dcrypt a file
int aes_decrypt_file(char* file_name){
	char out_file_name[128] = {0};
	if(file_name == NULL){
		printf("Invalid file name.\n");
		return -1;
	}
	FILE* fp_in = fopen(file_name, "rb");
	if(fp_in == NULL){
		printf("Cannot open file %s\n", file_name);
		return -1;
	}
	fseek(fp_in,0,SEEK_END);
	long lFileLen=ftell(fp_in); //ftell()函数返回文件位置指示符的当前值，即如果现在是在文件结尾，则这个值就是文件长度
	fseek(fp_in,0,SEEK_SET);
	long blocknum=lFileLen/16;
	
	int in_file_len = strlen(file_name);
	if(in_file_len >= 4){
		if(strcmp(file_name+(in_file_len-4), ".aes") == 0){
			strncpy(out_file_name, file_name, in_file_len-4);
		}else{
			snprintf(out_file_name, 128-1, "%s.decrypt", file_name);
		}
	}else{
		snprintf(out_file_name, 128-1, "%s.decrypt", file_name);
	}
	
	FILE* fp_out = fopen(out_file_name, "wb");
	if(fp_out == NULL){
		printf("Cannot open output file %s\n", out_file_name);
		return -1;
	}
	
	int i=0;
	unsigned char inBuff[25],ouBuff[25];
	Aes aes(my_key_len, (unsigned char*)my_key);
	
	for(i=0;i<blocknum-1;i++)
	{
		memset(inBuff, 0, sizeof(inBuff));
		memset(ouBuff, 0, sizeof(ouBuff));
		fread(inBuff,1,16,fp_in);  //读取16个对象，每个对象的长度是1字节
		aes.InvCipher(inBuff,ouBuff);
		fwrite(ouBuff,1,16,fp_out);
	}
	// 处理最后16个字节
	memset(inBuff, 0, sizeof(inBuff));
	memset(ouBuff, 0, sizeof(ouBuff));
	fread(inBuff,1,16,fp_in);
	aes.InvCipher(inBuff,ouBuff);
	fwrite(ouBuff,1,ouBuff[16-1],fp_out);
	
	fclose(fp_in);
	fclose(fp_out);
	return 0;
}

int main(int argc, char* argv[])
{
	if(argc != 5){
		usage();
		return -1;
	}
	if(strcmp(argv[1], "-d")!=0 && strcmp(argv[1], "-e")!=0){
		printf("Unknown type %s\n", argv[1]);
		usage();
		return -1;
	}
	
	if(-1 == get_key(argv[3], argv[4])){
		return -1;
	}
	
	if(strcmp(argv[1], "-e") == 0){
		if(-1 == aes_encrypt_file(argv[2])){
			printf("Encrypt file %s fail.\n", argv[2]);
			return -1;
		}else{
			printf("Encrypt file %s success.\n", argv[2]);
			return 0;
		}
	}else if(strcmp(argv[1], "-d") == 0){
		if(-1 == aes_decrypt_file(argv[2])){
			printf("Decrypt file %s fail.\n", argv[2]);
			return -1;
		}else{
			printf("Decrypt file %s success.\n", argv[2]);
			return 0;
		}
	}else{
		usage();
		return -1;
	}
	
	
	return 0;
}
