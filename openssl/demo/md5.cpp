//编译: g++ -ggdb3 -o md5 md5.cpp -lcrypto
//散列算法（签名算法）

#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/crypto.h>//OPENSSL_cleanse()


const char *str_test_data = "hello world"; //测试数据

// 打印函数
void printHash(unsigned char *md, int len){
	int i = 0;

	for(; i < len; i++)
		printf("%02x", md[i]);
	printf("\n");
}


void myMD5(){
	printf("myHash1()\n");
	//简单用法
	MD5_CTX c;
	unsigned char md[MD5_DIGEST_LENGTH];

	//单串快捷方法
	MD5((unsigned char *)str_test_data, strlen(str_test_data), md);
	printHash(md, MD5_DIGEST_LENGTH);



	//复杂用法
	MD5_Init(&c);
	MD5_Update(&c, str_test_data, strlen(str_test_data));//多串叠加计算.
	MD5_Update(&c, str_test_data, strlen(str_test_data));
	MD5_Update(&c, str_test_data, strlen(str_test_data));
	MD5_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));

	printHash(md, MD5_DIGEST_LENGTH);
	printf("\n\n");
}


int main(){
	myMD5();
	return 0;
}
