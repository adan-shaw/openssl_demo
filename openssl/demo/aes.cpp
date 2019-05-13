//编译: g++ -ggdb3 -o aes_test aes.cpp -lssl -lcrypto

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



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/aes.h>


//#define AES_KEY_LEN AES_BLOCK_SIZE*8		//128 bit aes
//#define AES_KEY_LEN AES_BLOCK_SIZE*12 //192 bit aes
#define AES_KEY_LEN AES_BLOCK_SIZE*16 //192 bit aes

#define AES_KEY_STR "Email:adan_shaw@qq.com"//'共知密钥'
#define AES_ENCRYPT_BUF_SIZE AES_KEY_LEN*10	//'共知-约定的加密数据长度'
																					//每段默认长度为: AES_KEY_LEN
//测试数据
#define TEST_DATA "11111111111222222222222222333333333333444444444445555555555 \
	fuck you bitch, i want to fuck you up bitch,,, just leave me alone !!!"



//***
//ebc 版本
//***
void aes_ebc(void){
	unsigned char key_str[AES_KEY_LEN];
	unsigned char *data = (unsigned char *)malloc(AES_ENCRYPT_BUF_SIZE);//原数据buf
	unsigned char *encrypt = (unsigned char *)malloc(AES_ENCRYPT_BUF_SIZE);//密文buf
	unsigned char *decrypt = (unsigned char *)malloc(AES_ENCRYPT_BUF_SIZE);//解密文buf

	int len = 0, tmp = 0;
	AES_KEY key;



	memset((void *)key_str, '\0', AES_KEY_LEN);//初始化'加密钥匙'的内容
	memset((void *)data, '\0', AES_ENCRYPT_BUF_SIZE);//初始化'原始数据'的内容
	memset((void *)encrypt, 04, AES_ENCRYPT_BUF_SIZE);//初始化'密文buf'
	memset((void *)decrypt, '\0', AES_ENCRYPT_BUF_SIZE);//初始化'解密文buf'
	//我的篡改
	strncpy((char*)key_str, AES_KEY_STR, AES_KEY_LEN);//初始化'共知密钥'
	strncpy((char*)data, TEST_DATA, AES_ENCRYPT_BUF_SIZE);//初始化原文数据

	//初始化aes 加密key; 并明确aes 密钥的长度 = AES_BLOCK_SIZE*8 = AES_ENCRYPT_BUF_SIZE.
	AES_set_encrypt_key(key_str, AES_KEY_LEN, &key);


	//打印原文数据
	printf("data: \n");
	printf("%s\n",data);
	printf("TEST_DATA len = %d\n",sizeof(TEST_DATA));
	printf("data len: %d <==> %d\n\n", strlen((char*)data), AES_ENCRYPT_BUF_SIZE);

	//循环加密, 每次只能加密AES_BLOCK_SIZE长度的数据!!
	//所以: 定义, 原数据buf or 密文buf or 解密文buf,, 都应该是AES_BLOCK_SIZE*n 倍
	len = 0;
	tmp = strlen((char*)data);
	//printf("data len=%d\n",tmp);
	//while(len < AES_ENCRYPT_BUF_SIZE){
	while(len < tmp){
		AES_encrypt(data+len, encrypt+len, &key);
		len += AES_BLOCK_SIZE;
	}

	//打印密文
	printf("encrypt: \n");
	for(tmp = 0; tmp < AES_ENCRYPT_BUF_SIZE; tmp++){
		printf("%.2x ", encrypt[tmp]);
		if((tmp+1) % 32 == 0){
			printf("\n");
		}
	}
	printf("encrypt text:\n%s\n\n",encrypt);

	//打印加密钥匙
	printf("加密钥匙: \n");
	printf("%s\n\n\n\n",key_str);



	//重置数据, 防止作弊
	memset((void *)&key, '\0', sizeof(key));//重置key
	memset((void *)key_str, '\0', AES_KEY_LEN);//重置'共知钥匙字符串'
	strncpy((char*)key_str, AES_KEY_STR, AES_KEY_LEN);//初始化'共知密钥'
	//初始化aes 解密key; 并明确aes 密钥的长度 = AES_BLOCK_SIZE*8.
	AES_set_decrypt_key(key_str, AES_KEY_LEN, &key);


	//循环解密
	len = 0;
	tmp = strlen((char*)encrypt);
	printf("encrypt len=%d\n",tmp);
	while(len < AES_ENCRYPT_BUF_SIZE){
		AES_decrypt(encrypt+len, decrypt+len, &key);
		len += AES_BLOCK_SIZE;
	}

	//解密后与原数据是否一致
	if(!memcmp(decrypt, data, strlen((char*)data))){
		printf("test success\n\n");
	}
	else{
		printf("test failed\n\n");
	}

	//打印解密文
	printf("decrypt: \n");
	printf("%s\n\n",decrypt);

	//打印解密钥匙
	printf("解密钥匙: \n");
	printf("%s\n\n\n\n",key_str);

	free(data);
	free(encrypt);
	free(decrypt);

	return ;
}





//***
//cbc 版本
//***
#define AES_BITS 128
#define MSG_LEN 128

//, int olen)可能会设置buf长度
int aes_encrypt(char* in, char* key, char* out){
	unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
	for(int i=0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		iv[i]=0;
	AES_KEY aes;

	if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
		return 0;

	int len=strlen(in);
	//这里的长度是char*in的长度，但是如果in中间包含'\0'字符的话
	//那么就只会加密前面'\0'前面的一段，所以，这个len可以作为参数传进来，记录in的长度
	//至于解密也是一个道理，光以'\0'来判断字符串长度，确有不妥，后面都是一个道理。
	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
	return 1;
}






int aes_decrypt(char* in, char* key, char* out){
	unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
	for(int i=0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		iv[i]=0;
	AES_KEY aes;

	if(AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
		return 0;

	int len=strlen(in);
	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
	return 1;
}

void aes_cbc(void){
	char sourceStringTemp[MSG_LEN];
	char dstStringTemp[MSG_LEN];
	memset((char*)sourceStringTemp, 0 ,MSG_LEN);
	memset((char*)dstStringTemp, 0 ,MSG_LEN);
	strcpy((char*)sourceStringTemp, "123456789 123456789 123456789 12a");
	//strcpy((char*)sourceStringTemp, argv[1]);


	char key[AES_BLOCK_SIZE];
	int i;
	for(i = 0; i < 16; i++)//可自由设置密钥
		key[i] = 32 + i;

	if(!aes_encrypt(sourceStringTemp,key,dstStringTemp)){
		printf("encrypt error\n");
		return ;
	}
	printf("enc %d:",strlen((char*)dstStringTemp));

	for(i= 0;dstStringTemp[i];i+=1){
		printf("%x",(unsigned char)dstStringTemp[i]);
	}
	memset((char*)sourceStringTemp, 0 ,MSG_LEN);
	if(!aes_decrypt(dstStringTemp,key,sourceStringTemp)){
		printf("decrypt error\n");
		return ;
	}
	printf("\n");
	printf("dec %d:",strlen((char*)sourceStringTemp));
	printf("%s\n",sourceStringTemp);
	for(i= 0;sourceStringTemp[i];i+=1){
		printf("%x",(unsigned char)sourceStringTemp[i]);
	}
	printf("\n");
	return ;

}










//***
//EVP 虽然方便, 但是版本不对, 改动太大. 新版本貌似不兼容EVP_CIPHER_CTX ctx; 结构
//***


//EVP框架是对openssl提供的所有算法进行了封装, 
//在使用工程中只需要修改少量的代码就可以选择不同的加密算法, 在工作中通常采用这种方式. 

//在上述两个示例中, 直接使用API提供的接口, 没有使用padding, 在EVP中同样需要声明不可以使用padding方式, 
//否则即使要加密的数据长度是AES_BLOCK_SIZE的整数倍, EVP默认也会对原始数据进行追加, 导致结果不同, 
//所以在试验中通过EVP_CIPHER_CTX_set_padding(&ctx, 0)函数关闭的EVP的padding功能, 
//同样在解密的时候也需要进行关闭. 



/*

#include <openssl/evp.h>
#include <openssl/aes.h>

int evp_aes(void){
	char key_str[EVP_MAX_KEY_LENGTH];
	char iv[EVP_MAX_IV_LENGTH];
	unsigned char *data = (unsigned char *)malloc(AES_ENCRYPT_BUF_SIZE);
	unsigned char *encrypt = (unsigned char *)malloc(AES_BLOCK_SIZE*6);
	unsigned char *decrypt = (unsigned char *)malloc(AES_BLOCK_SIZE*6);
	EVP_CIPHER_CTX ctx;
	int ret;
	int tlen = 0;
	int mlen = 0;
	int flen = 0;

	memset((void *)key_str, 'k', EVP_MAX_KEY_LENGTH);
	memset((void *)iv, 'i', EVP_MAX_IV_LENGTH);
	memset((void *)data, 'p', AES_ENCRYPT_BUF_SIZE);
	memset((void *)encrypt, 0, AES_BLOCK_SIZE*6);
	memset((void *)decrypt, 0, AES_BLOCK_SIZE*6);

	//初始化ctx
	EVP_CIPHER_CTX_init(&ctx);

	//指定加密算法及key和iv(此处IV没有用)
	ret = EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key_str, iv);
	if(ret != 1){
		printf("EVP_EncryptInit_ex failed\n");
		exit(-1);
	}

	//禁用padding功能
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	//进行加密操作
	ret = EVP_EncryptUpdata(&ctx, encrypt, &mlen, data, AES_ENCRYPT_BUF_SIZE);
	if(ret != 1){
		printf("EVP_EncryptUpdata failed\n");
		exit(-1);
	}
	//结束加密操作
	ret = EVP_EncryptFinal_ex(&ctx, encrypt+mlen, &flen);
	if(ret != 1){
		printf("EVP_EncryptFinal_ex failed\n");
		exit(-1);
	}

	tlen = mlen + flen;

	tlen = 0;
	mlen = 0;
	flen = 0;

	EVP_CIPHER_CTX_cleanup(&ctx);
	EVP_CIPHER_CTX_init(&ctx);
	 
	ret = EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key_str, iv);
	if(ret != 1){
		printf("EVP_DecryptInit_ex failed\n");
		exit(-1);
	}

	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	ret = EVP_DecryptUpdata(&ctx, decrypt, &mlen, encrypt, AES_ENCRYPT_BUF_SIZE);
	if(ret != 1){
		printf("EVP_DecryptUpdata failed\n");
		exit(-1);
	}

	ret = EVP_DecryptFinal_ex(&ctx, decrypt+mlen, &flen);
	if(ret != 1){
		printf("EVP_DecryptFinal_ex failed\n");
		exit(-1);
	}

	//对比解密后与原数据是否一致
	if(!memcmp(decrypt, data, AES_ENCRYPT_BUF_SIZE)){
		printf("test success\n");
	}
	else{
		printf("test failed\n");
	}

	printf("encrypt: ");
	int i;
	for(i = 0; i < AES_ENCRYPT_BUF_SIZE; i ++){
		printf("%.2x ", encrypt[i]);
		if((i+1)%32 == 0){
			printf("\n");
		}
	}
	printf("\n");

	return 0;
}

*/



int main(void){
	aes_ebc();
	aes_cbc();
	//evp_aes();
	return 0;
}



