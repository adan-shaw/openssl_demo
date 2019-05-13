//编译: g++ -ggdb3 -o aes_test aes2.cpp -lssl -lcrypto


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/aes.h>


//注意1: key_str buf 长度, 应为: AES_BLOCK_SIZE*n 倍, 不足补'\n'
//注意2: 密文缓冲区buf, 长度应为:	AES_BLOCK_SIZE*n 倍, 不足补04

//key 结构体:
//AES_KEY key;

//aes ebc 模式(仍然是循环加密, 解密的ebc 模式! 每次'加密/解密'一个AES_BLOCK_SIZE 长度):
//AES_set_encrypt_key()		//设置aes ebc 加密key
//AES_encrypt()						//执行aes ebc 加密
//AES_set_decrypt_key()		//设置aes ebc 解密key
//AES_decrypt()						//执行aes ebc 解密


//aes cbc 模式
//AES_set_encrypt_key()		//设置aes cbc 加密key
//AES_cbc_encrypt()				//执行aes cbc 加密
//AES_set_decrypt_key()		//设置aes cbc 解密key
//AES_cbc_decrypt()				//执行aes cbc 解密



//aes cbc 加密(注意in buf和out buf 长度应当一致, 且为AES_BLOCK_SIZE*n倍, 不足补04)
//key and iv 的长度, 应该相等, 也应该是AES_BLOCK_SIZE*n 倍!
//(另外, 为了防止key and vi 内容冲突, 务必初始化为:
//	memset(key,'\0',sizeof(key));buflen_key = sizeof(key);
//如果你不知道数据的具体长度, 那么就创建n+8 大小的缓冲区.
void aes_cbc_encrypt(char* key, char* iv, int buflen_key,\
		char* data, char* out, int buflen){
	AES_KEY key_aes;
	//int iv_len = strlen(iv) + 1;
	int datalen = strlen(data) + 1;
	int tmp = 0;


	//参数检查
	if(buflen_key%AES_BLOCK_SIZE != 0){
		printf("des_cbc_encrypt() fail, 'char* iv' length != AES_BLOCK_SIZE\n");
		return;
	}
	if(buflen%AES_BLOCK_SIZE != 0){
		printf("des_cbc_encrypt() fail, data length % AES_BLOCK_SIZE != 0\n");
		return;
	}
	memset(out,'\0',buflen);//如果这里崩溃了, 也容易发现


	tmp = AES_set_encrypt_key((unsigned char*)key, buflen_key, &key_aes);
	if(tmp < 0){
		printf("des_cbc_encrypt() fail, AES_set_encrypt_key() fail!!\n \
				errno = %d\n", tmp);
		return ;
	}

	datalen = (datalen%AES_BLOCK_SIZE == 0) ? datalen : datalen + AES_BLOCK_SIZE;
	AES_cbc_encrypt((unsigned char*)data, (unsigned char*)out, datalen, \
			&key_aes, (unsigned char*)iv, AES_ENCRYPT);
	return ;
}






void aes_cbc_decrypt(char* key, char* iv, int buflen_key, \
		char* data, char* out, int buflen){
	AES_KEY key_aes;
	//int iv_len = strlen(iv) + 1;
	int datalen = strlen(data) + 1;
	int tmp = 0;


	//参数检查
	if(buflen_key%AES_BLOCK_SIZE != 0){
		printf("aes_cbc_decrypt() fail, 'char* iv' length != AES_BLOCK_SIZE\n");
		return;
	}
	if(buflen%AES_BLOCK_SIZE != 0){
		printf("aes_cbc_decrypt() fail, data length % AES_BLOCK_SIZE != 0\n");
		return;
	}
	memset(out,'\0',buflen);//如果这里崩溃了, 也容易发现


	tmp = AES_set_decrypt_key((unsigned char*)key, buflen_key, &key_aes);
	if(tmp < 0){
		printf("des_cbc_decrypt() fail, AES_set_decrypt_key() fail!!\n \
				errno = %d\n", tmp);
		return ;
	}

	datalen = (datalen%AES_BLOCK_SIZE == 0) ? datalen : datalen + AES_BLOCK_SIZE;
	AES_cbc_encrypt((unsigned char*)data, (unsigned char*)out, datalen, \
			&key_aes, (unsigned char*)iv, AES_DECRYPT);
	return ;
}



int main(void){
	char *key = (char*)malloc(AES_BLOCK_SIZE);
	char *iv = (char*)malloc(AES_BLOCK_SIZE);
	int buflen_key = AES_BLOCK_SIZE;

	char *data = (char*)malloc(AES_BLOCK_SIZE*100);
	char *out = (char*)malloc(AES_BLOCK_SIZE*100);
	int buflen = AES_BLOCK_SIZE*100;

	memset(key,'\0',AES_BLOCK_SIZE);
	memset(iv,'\0',AES_BLOCK_SIZE);
	strncpy(key, "fuck you bitch", AES_BLOCK_SIZE);
	strncpy(iv, "fuck you whore", AES_BLOCK_SIZE);
	//memset(iv,'\0',2560);
	strncpy(data, "fuck you whore and bitch ..sdfsdf....", AES_BLOCK_SIZE*100);


	printf("before:\n%s\n\n",data);
	aes_cbc_encrypt(key,iv,buflen_key,data,out,buflen);
	printf("after encrypt:\n%s\n\n",out);

	memset(data,'\0',AES_BLOCK_SIZE*100);
	aes_cbc_decrypt(key,iv,buflen_key,out,data,buflen);
	printf("after decrypt:\n%s\n\n",data);

	free(key);
	free(iv);
	free(data);
	free(out);
	return 0;
}

