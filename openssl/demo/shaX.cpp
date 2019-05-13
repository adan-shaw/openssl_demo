//编译: g++ -ggdb3 -o sha_all_test shaX.cpp -lcrypto
//用法: 散列算法(签名算法)
//	sha 系列校验码计算, 是不可能反向的!!
//	sha 系列校验算法, 不是一种数据加密手段. 不能用作数据加密!!
//		所以, 如果你对其反向, 肯定能成功, 但是没有意义.(或者你分析别人的报文的时候, 才有意义.)
//	sha 系列校验算法的作用, 基本只能保证数据完整性, 不可随意篡改性. 而不是加密!!

//	但是对方仍然可以修改你的数据, 然后又重新算一个新的'sha 校验码'粘帖上去,
//	这样仍然可以篡改, 只是麻烦更多而已.
//	但是如果只对'sha 校验码'加密, 那么就没有被篡改的可能了.

//	加密了校验码, 到了'对端', 再解密校验码,
//	对'收到的数据'重新计算sha 校验码, 比对是否一致, 一致则没有被篡改.

//	md5 同理.
//	所以, sha 系列校验算法, 并不需要反向操作, 求解.
//	只需求两次, 对比是否一致, 即可知道数据是否被篡改.

//	为了防止校验码被篡改, 从而数据可能被改写, 你可以对'sha校验码'进行加密!!



#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>//包含sha1 224 256 384 512
#include <openssl/crypto.h>//OPENSSL_cleanse()


const char *str_test_data = "hello world";	//测试数据
const char *str_test_data2 = "hello world2";
const char *str_test_data3 = "hello world3";


// 打印函数
void printHash(unsigned char *md, int len){
	int i = 0;

	for(; i < len; i++)
		printf("%02x", md[i]);
	printf("\n");
}


void mySHA1(){
	printf("mySHA1()\n");

	//简单用法(适合单串数据)
	SHA_CTX c;
	unsigned char md[SHA_DIGEST_LENGTH];

	//执行SHA1 校验计算
	SHA1((unsigned char *)str_test_data, strlen(str_test_data), md);
	printHash(md, SHA_DIGEST_LENGTH);//打印结果



	//复杂用法(适合多串数据, 全部累加在一起, 计算出一个校验和.)
	memset(&c, 0, sizeof(SHA_CTX));
	memset(&md, 0, sizeof(md));

	SHA1_Init(&c);
	SHA1_Update(&c, str_test_data, strlen(str_test_data));//多串数据
	SHA1_Update(&c, str_test_data2, strlen(str_test_data2));
	SHA1_Update(&c, str_test_data3, strlen(str_test_data3));
	SHA1_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));

	printHash(md, SHA_DIGEST_LENGTH);//打印结果
	printf("\n\n");
}


void mySHA224(){
	printf("mySHA224()\n");

	//简单用法(适合单串数据)
	SHA256_CTX c;
	unsigned char md[SHA224_DIGEST_LENGTH];

	SHA224((unsigned char *)str_test_data, strlen(str_test_data), md);
	printHash(md, SHA224_DIGEST_LENGTH);



	//复杂用法(适合多串数据)
	memset(&c, 0, sizeof(SHA_CTX));
	memset(&md, 0, sizeof(md));

	SHA224_Init(&c);
	SHA224_Update(&c, str_test_data, strlen(str_test_data));
	SHA224_Update(&c, str_test_data2, strlen(str_test_data2));
	SHA224_Update(&c, str_test_data3, strlen(str_test_data3));
	SHA224_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));

	printHash(md, SHA224_DIGEST_LENGTH);
	printf("\n\n");
}


void myHash256(){
	printf("myHash256()\n");

	//简单用法(适合单串数据)
	SHA256_CTX c;
	unsigned char md[SHA256_DIGEST_LENGTH];

	SHA256((unsigned char *)str_test_data, strlen(str_test_data), md);
	printHash(md, SHA256_DIGEST_LENGTH);



	//复杂用法(适合多串数据)
	SHA256_Init(&c);
	SHA256_Update(&c, str_test_data, strlen(str_test_data));
	SHA256_Update(&c, str_test_data2, strlen(str_test_data2));
	SHA256_Update(&c, str_test_data3, strlen(str_test_data3));
	SHA256_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));

	printHash(md, SHA256_DIGEST_LENGTH);
	printf("\n\n");
}


void mySHA384(){
	printf("mySHA384()\n");

	//简单用法(适合单串数据)
	SHA512_CTX c;
	unsigned char md[SHA384_DIGEST_LENGTH];

	SHA384((unsigned char *)str_test_data, strlen(str_test_data), md);
	printHash(md, SHA384_DIGEST_LENGTH);



	//复杂用法(适合多串数据)
	SHA384_Init(&c);
	SHA384_Update(&c, str_test_data, strlen(str_test_data));
	SHA384_Update(&c, str_test_data2, strlen(str_test_data2));
	SHA384_Update(&c, str_test_data3, strlen(str_test_data3));
	SHA384_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));

	printHash(md, SHA384_DIGEST_LENGTH);
	printf("\n\n");
}


void mySHA512(){
	printf("mySHA512()\n");

	//简单用法(适合单串数据)
	SHA512_CTX c;
	unsigned char md[SHA512_DIGEST_LENGTH];

	SHA512((unsigned char *)str_test_data, strlen(str_test_data), md);
	printHash(md, SHA512_DIGEST_LENGTH);



	//复杂用法(适合多串数据)
	SHA512_Init(&c);
	SHA512_Update(&c, str_test_data, strlen(str_test_data));
	SHA512_Update(&c, str_test_data2, strlen(str_test_data2));
	SHA512_Update(&c, str_test_data3, strlen(str_test_data3));
	SHA512_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));

	printHash(md, SHA512_DIGEST_LENGTH);
	printf("\n\n");
}



int main(){
	mySHA1();
	mySHA224();
	myHash256();
	mySHA384();
	mySHA512();
	return 0;
}

