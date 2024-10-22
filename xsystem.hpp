﻿/*****************************************************************************
*  @file     xsystem.h                                                       *
*  @brief    跨平台库															 *
*  Details.                                                                  *
*                                                                            *
*  @author   FreetBash                                                       *
*  @email    freet-bash@qq.com												 *
*  @version  0																 *
*  @date     2023/1/18														 *
*  @license  (MIT)															 *
*****************************************************************************/
#ifndef SSL_ENABLE
#define SSL_ENABLE 0
#endif // !SSL_ENABLE

#pragma once
#ifndef __XSYSTEM__
#define __XSYSTEM__
#if SSL_ENABLE
#include <openssl/ssl.h>
#include <openssl/err.h>

#endif

// windows ok!
#if _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1
#pragma warning(disable:4996)
#pragma warning(disable:4267)
#include <Winsock2.h>
#pragma comment (lib, "ws2_32.lib") 
#include <direct.h> // path
#include <io.h>


#if SSL_ENABLE
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

#endif

// linux ok!
#else 
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>
#define SOCKET int

#endif

// c++
#include <string>
using std::string;
using std::to_string;
using std::stoull;
using std::stoul;

#include <iostream>
using std::cout;
using std::endl;

#include <map>
using std::map;
using std::pair;

#include <vector>
using std::vector;

#include <memory>
using std::shared_ptr;

#include <mutex>
using std::mutex;

#include <chrono>
#include <time.h>
#include <stdint.h>
#include <sys/stat.h>




namespace xsystem {

	namespace crypt {

		class Base64 {
		public:
			static string Encode(const unsigned char *data, int len) {
				//编码表
				const char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
				//返回值
				string strEncode;
				unsigned char Tmp[4] = { 0 };
				int LineLength = 0;
				for(int i = 0; i < (int)(len / 3); i++) {
					Tmp[1] = *data++;
					Tmp[2] = *data++;
					Tmp[3] = *data++;
					strEncode += EncodeTable[Tmp[1] >> 2];
					strEncode += EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
					strEncode += EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
					strEncode += EncodeTable[Tmp[3] & 0x3F];
					if(LineLength += 4, LineLength == 76) { strEncode += "\r\n"; LineLength = 0; }
				}
				//对剩余数据进行编码
				int Mod = len % 3;
				if(Mod == 1) {
					Tmp[1] = *data++;
					strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
					strEncode += EncodeTable[((Tmp[1] & 0x03) << 4)];
					strEncode += "==";
				} else if(Mod == 2) {
					Tmp[1] = *data++;
					Tmp[2] = *data++;
					strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
					strEncode += EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xF0) >> 4)];
					strEncode += EncodeTable[((Tmp[2] & 0x0F) << 2)];
					strEncode += "=";
				}

				return strEncode;

			} // class Base64 Encode()

			static string Decode(const char *data, int len, int *outlen) {
				//解码表
				const char DecodeTable[] =
				{
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					62, // '+'
					0, 0, 0,
					63, // '/'
					52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // '0'-'9'
					0, 0, 0, 0, 0, 0, 0,
					0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
					13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 'A'-'Z'
					0, 0, 0, 0, 0, 0,
					26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
					39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // 'a'-'z'
				};
				//返回值
				string strDecode;
				int nValue;
				int i = 0;
				while(i < len) {
					if(*data != '\r' && *data != '\n') {
						nValue = DecodeTable[*data++] << 18;
						nValue += DecodeTable[*data++] << 12;
						strDecode += (nValue & 0x00FF0000) >> 16;
						(*outlen)++;
						if(*data != '=') {
							nValue += DecodeTable[*data++] << 6;
							strDecode += (nValue & 0x0000FF00) >> 8;
							(*outlen)++;
							if(*data != '=') {
								nValue += DecodeTable[*data++];
								strDecode += nValue & 0x000000FF;
								(*outlen)++;
							}
						}
						i += 4;
					} else// 回车换行,跳过
					{
						data++;
						i++;
					}
				}
				return strDecode;

			}// class Base64 Decode()

		public:
			Base64() {}
			~Base64() {}

		}; // class Base64

		namespace hash {

			string sha256(const unsigned char *str, size_t length) {
			#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))
			#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))
			#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
			#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
			#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
			#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
			#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
			#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))
				char SHA256[257];
				char *pp, *ppend;
				long l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
				H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
				H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
				long K[64] = {
					long(0x428a2f98), long(0x71374491), long(0xb5c0fbcf), long(0xe9b5dba5), long(0x3956c25b), long(0x59f111f1), long(0x923f82a4), long(0xab1c5ed5),
					long(0xd807aa98), long(0x12835b01), long(0x243185be), long(0x550c7dc3), long(0x72be5d74), long(0x80deb1fe), long(0x9bdc06a7), long(0xc19bf174),
					long(0xe49b69c1), long(0xefbe4786), long(0x0fc19dc6), long(0x240ca1cc), long(0x2de92c6f), long(0x4a7484aa), long(0x5cb0a9dc), long(0x76f988da),
					long(0x983e5152), long(0xa831c66d), long(0xb00327c8), long(0xbf597fc7), long(0xc6e00bf3), long(0xd5a79147), long(0x06ca6351), long(0x14292967),
					long(0x27b70a85), long(0x2e1b2138), long(0x4d2c6dfc), long(0x53380d13), long(0x650a7354), long(0x766a0abb), long(0x81c2c92e), long(0x92722c85),
					long(0xa2bfe8a1), long(0xa81a664b), long(0xc24b8b70), long(0xc76c51a3), long(0xd192e819), long(0xd6990624), long(0xf40e3585), long(0x106aa070),
					long(0x19a4c116), long(0x1e376c08), long(0x2748774c), long(0x34b0bcb5), long(0x391c0cb3), long(0x4ed8aa4a), long(0x5b9cca4f), long(0x682e6ff3),
					long(0x748f82ee), long(0x78a5636f), long(0x84c87814), long(0x8cc70208), long(0x90befffa), long(0xa4506ceb), long(0xbef9a3f7), long(0xc67178f2),
				};
				l = long(length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64)));
				if(!(pp = (char *)malloc((unsigned long)l))) return "";
				for(i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
				for(pp[i + 3 - 2 * (i % 4)] = (char)128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = (char)0, i++);
				*((long *)(pp + l - 4)) = length << 3;
				*((long *)(pp + l - 8)) = length >> 29;
				for(ppend = pp + l; pp < ppend; pp += 64) {
					for(i = 0; i < 16; W[i] = ((long *)pp)[i], i++);
					for(i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
					A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
					for(i = 0; i < 64; i++) {
						T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
						T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
						H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
					}
					H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
				}
				free(pp - l);
				sprintf(SHA256, "%08X%08X%08X%08X%08X%08X%08X%08X", (unsigned int)H0, (unsigned int)H1, (unsigned int)H2, (unsigned int)H3, (unsigned int)H4, (unsigned int)H5, (unsigned int)H6, (unsigned int)H7);
				SHA256[256] = '\0';
				return SHA256;

			}// namespace hash sha256()

			// for md5
			unsigned char PADDING[] = { 0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
			typedef struct {
				unsigned int count[2];
				unsigned int state[4];
				unsigned char buffer[64];
			}MD5_CTX;

			class Md5 {
			#define F(x,y,z) ((x & y) | (~x & z))
			#define G(x,y,z) ((x & z) | (y & ~z))
			#define H(x,y,z) (x^y^z)
			#define I(x,y,z) (y ^ (x | ~z))
			#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
			#define FF(a,b,c,d,x,s,ac) { a += F(b,c,d) + x + ac; a = ROTATE_LEFT(a,s); a += b; }
			#define GG(a,b,c,d,x,s,ac) { a += G(b,c,d) + x + ac; a = ROTATE_LEFT(a,s); a += b; }
			#define HH(a,b,c,d,x,s,ac) { a += H(b,c,d) + x + ac; a = ROTATE_LEFT(a,s); a += b; }
			#define II(a,b,c,d,x,s,ac) { a += I(b,c,d) + x + ac; a = ROTATE_LEFT(a,s); a += b; }
			public:

				static void MD5Init(MD5_CTX *context) {
					context->count[0] = 0;
					context->count[1] = 0;
					context->state[0] = 0x67452301;
					context->state[1] = 0xEFCDAB89;
					context->state[2] = 0x98BADCFE;
					context->state[3] = 0x10325476;
				}// class Md5 MD5Init()

				static void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen) {
					unsigned int i = 0, index = 0, partlen = 0;
					index = (context->count[0] >> 3) & 0x3F;
					partlen = 64 - index;
					context->count[0] += inputlen << 3;
					if(context->count[0] < (inputlen << 3)) {
						context->count[1]++;
					}
					context->count[1] += inputlen >> 29;

					if(inputlen >= partlen) {
						memcpy(&context->buffer[index], input, partlen);
						MD5Transform(context->state, context->buffer);
						for(i = partlen; i + 64 <= inputlen; i += 64) {
							MD5Transform(context->state, &input[i]);
						}
						index = 0;
					} else {
						i = 0;
					}

					memcpy(&context->buffer[index], &input[i], inputlen - i);
				}// class Md5 MD5Update()

				static void MD5Final(MD5_CTX *context, unsigned char digest[16]) {
					unsigned int index = 0, padlen = 0;
					unsigned char bits[8];
					index = (context->count[0] >> 3) & 0x3F;
					padlen = (index < 56) ? (56 - index) : (120 - index);
					MD5Encode(bits, context->count, 8);
					MD5Update(context, PADDING, padlen);
					MD5Update(context, bits, 8);
					MD5Encode(digest, context->state, 16);
				}// class Md5 MD5Final()

				static void MD5Transform(unsigned int state[4], unsigned char block[64]) {
					unsigned int a = state[0];
					unsigned int b = state[1];
					unsigned int c = state[2];
					unsigned int d = state[3];
					unsigned int x[64];

					MD5Decode(x, block, 64);

					FF(a, b, c, d, x[0], 7, 0xd76aa478);
					FF(d, a, b, c, x[1], 12, 0xe8c7b756);
					FF(c, d, a, b, x[2], 17, 0x242070db);
					FF(b, c, d, a, x[3], 22, 0xc1bdceee);
					FF(a, b, c, d, x[4], 7, 0xf57c0faf);
					FF(d, a, b, c, x[5], 12, 0x4787c62a);
					FF(c, d, a, b, x[6], 17, 0xa8304613);
					FF(b, c, d, a, x[7], 22, 0xfd469501);
					FF(a, b, c, d, x[8], 7, 0x698098d8);
					FF(d, a, b, c, x[9], 12, 0x8b44f7af);
					FF(c, d, a, b, x[10], 17, 0xffff5bb1);
					FF(b, c, d, a, x[11], 22, 0x895cd7be);
					FF(a, b, c, d, x[12], 7, 0x6b901122);
					FF(d, a, b, c, x[13], 12, 0xfd987193);
					FF(c, d, a, b, x[14], 17, 0xa679438e);
					FF(b, c, d, a, x[15], 22, 0x49b40821);

					GG(a, b, c, d, x[1], 5, 0xf61e2562);
					GG(d, a, b, c, x[6], 9, 0xc040b340);
					GG(c, d, a, b, x[11], 14, 0x265e5a51);
					GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
					GG(a, b, c, d, x[5], 5, 0xd62f105d);
					GG(d, a, b, c, x[10], 9, 0x2441453);
					GG(c, d, a, b, x[15], 14, 0xd8a1e681);
					GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
					GG(a, b, c, d, x[9], 5, 0x21e1cde6);
					GG(d, a, b, c, x[14], 9, 0xc33707d6);
					GG(c, d, a, b, x[3], 14, 0xf4d50d87);
					GG(b, c, d, a, x[8], 20, 0x455a14ed);
					GG(a, b, c, d, x[13], 5, 0xa9e3e905);
					GG(d, a, b, c, x[2], 9, 0xfcefa3f8);
					GG(c, d, a, b, x[7], 14, 0x676f02d9);
					GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);


					HH(a, b, c, d, x[5], 4, 0xfffa3942);
					HH(d, a, b, c, x[8], 11, 0x8771f681);
					HH(c, d, a, b, x[11], 16, 0x6d9d6122);
					HH(b, c, d, a, x[14], 23, 0xfde5380c);
					HH(a, b, c, d, x[1], 4, 0xa4beea44);
					HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
					HH(c, d, a, b, x[7], 16, 0xf6bb4b60);
					HH(b, c, d, a, x[10], 23, 0xbebfbc70);
					HH(a, b, c, d, x[13], 4, 0x289b7ec6);
					HH(d, a, b, c, x[0], 11, 0xeaa127fa);
					HH(c, d, a, b, x[3], 16, 0xd4ef3085);
					HH(b, c, d, a, x[6], 23, 0x4881d05);
					HH(a, b, c, d, x[9], 4, 0xd9d4d039);
					HH(d, a, b, c, x[12], 11, 0xe6db99e5);
					HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
					HH(b, c, d, a, x[2], 23, 0xc4ac5665);


					II(a, b, c, d, x[0], 6, 0xf4292244);
					II(d, a, b, c, x[7], 10, 0x432aff97);
					II(c, d, a, b, x[14], 15, 0xab9423a7);
					II(b, c, d, a, x[5], 21, 0xfc93a039);
					II(a, b, c, d, x[12], 6, 0x655b59c3);
					II(d, a, b, c, x[3], 10, 0x8f0ccc92);
					II(c, d, a, b, x[10], 15, 0xffeff47d);
					II(b, c, d, a, x[1], 21, 0x85845dd1);
					II(a, b, c, d, x[8], 6, 0x6fa87e4f);
					II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
					II(c, d, a, b, x[6], 15, 0xa3014314);
					II(b, c, d, a, x[13], 21, 0x4e0811a1);
					II(a, b, c, d, x[4], 6, 0xf7537e82);
					II(d, a, b, c, x[11], 10, 0xbd3af235);
					II(c, d, a, b, x[2], 15, 0x2ad7d2bb);
					II(b, c, d, a, x[9], 21, 0xeb86d391);
					state[0] += a;
					state[1] += b;
					state[2] += c;
					state[3] += d;
				}// class Md5 MD5Transform()

				static void MD5Encode(unsigned char *output, unsigned int *input, unsigned int len) {
					unsigned int i = 0, j = 0;
					while(j < len) {
						output[j] = input[i] & 0xFF;
						output[j + 1] = (input[i] >> 8) & 0xFF;
						output[j + 2] = (input[i] >> 16) & 0xFF;
						output[j + 3] = (input[i] >> 24) & 0xFF;
						i++;
						j += 4;
					}
				}// class Md5 MD5Encode()

				static void MD5Decode(unsigned int *output, unsigned char *input, unsigned int len) {
					unsigned int i = 0, j = 0;
					while(j < len) {
						output[i] = (input[j]) | (input[j + 1] << 8) | (input[j + 2] << 16) | (input[j + 3] << 24);
						i++;
						j += 4;
					}
				}// class Md5 MD5Decode()

				static string Encode(unsigned char *data, size_t len) {
					MD5_CTX md5;
					unsigned char decrypt[16];
					string str;
					char temp[3];
					MD5Init(&md5);
					MD5Update(&md5, data, len);
					MD5Final(&md5, decrypt);
					for(int i = 0; i < 16; ++i) {
						sprintf(temp, "%02x", decrypt[i]);  //02x前需要加上 %
						str += temp;
					}
					return str;
				}// class Md5 Encode()

				static string FileEncode(string file_path) {
					MD5_CTX md5;
					unsigned char decrypt[16];
					string str;
					char temp[3];
					FILE *fp = fopen(file_path.c_str(), "rb");
					if(fp == NULL) {
						fprintf(stderr, "File %s not exists, errno = %d, error = %s\n", file_path.c_str(), errno, strerror(errno));
					}

					MD5Init(&md5);

					do {
						unsigned char encrypt[1024];
						while(!feof(fp)) {
							MD5Update(&md5, encrypt, fread(encrypt, 1, sizeof(encrypt), fp));
						}
						fclose(fp);
					} while(0);

					MD5Final(&md5, decrypt);

					for(int i = 0; i < 16; i++) {
						sprintf(temp, "%02x", decrypt[i]);  //02x前需要加上 %
						str += temp;
					}

					return str;
				}// class Md5 FileEncode()

			public:
				Md5() {}
				~Md5() {}

			};// class Md5

		};// namespace hash

	};// namespace crypt

	namespace net {

		class Address {
		public:
			string host;
			unsigned int port;
			struct sockaddr_in addr;

		public:
			Address() {
				memset(&this->addr, 0, sizeof(this->addr));
			}

			~Address() {}
		};// namespace net class Adress

		class Socket {
		#if SSL_ENABLE
		public:
			SSL *ssl;
		#endif
		public:
			Address address;
			Address target;
			SOCKET fd;


		public:
			static string domain2ip(string domain) {
				char ip[16];
			#if _WIN32
				HOSTENT *host = gethostbyname(domain.c_str());
				if(host == nullptr) throw "eeeeeeeeeeeeeerrrrrrror";
				strcpy(ip, inet_ntoa(*(struct in_addr *)*host->h_addr_list));
			#else
				struct hostent *host = gethostbyname(domain.c_str());
				strcpy(ip, inet_ntoa(*((struct in_addr *)host->h_addr)));
			#endif
				return string(ip);
			}// class Socket domain2ip()

			static int Init() {
			#if SSL_ENABLE
				SSL_load_error_strings();
				SSLeay_add_ssl_algorithms();
			#endif

			#if _WIN32
				WSADATA wsData;
				WORD wsVersion = MAKEWORD(2, 2);
				return WSAStartup(wsVersion, &wsData);
			#else
				return 0;
			#endif
			}// class Socket Init()

			static int Exit() {
			#if _WIN32
				return WSACleanup();
			#else
				return 0;
			#endif
			}// class Socket Exit()

			int Bind(string host, unsigned int port) {
				// check your Init()
				// try catch exception
				this->address.host = host;
				this->address.port = port;

				this->address.addr.sin_port = htons(port);
			#if _WIN32
				this->address.addr.sin_addr.S_un.S_addr = inet_addr(host.c_str());
			#else
				this->address.addr.sin_addr.s_addr = inet_addr(host.c_str());
			#endif
				return bind(this->fd, (struct sockaddr *)(&this->address.addr), sizeof(this->address.addr));
			}// class Socket Bind()

			int Listen(int backlog) {
				return listen(this->fd, backlog);
			}// class Socket Listen()

			int Connect(string host, unsigned int port) {
				// client
			#if SSL_ENABLE
				this->ssl = SSL_new(SSL_CTX_new(SSLv23_client_method()));
			#endif

				this->target.addr.sin_family = this->address.addr.sin_family;
				this->target.addr.sin_port = htons(port);
			#if _WIN32
				this->target.addr.sin_addr.S_un.S_addr = inet_addr(host.c_str());
			#else
				this->target.addr.sin_addr.s_addr = inet_addr(host.c_str());
			#endif
				return connect(this->fd, (const struct sockaddr *)(&this->target.addr), sizeof(this->target.addr));

			}// class Socket Connect()

			int Send(const char *buf, size_t len, int flags = 0) {
				return send(this->fd, buf, (int)len, flags);
			}// class Socket Send()

			int Recv(char *buf, size_t len, int flags = 0) {
				return recv(this->fd, buf, (int)len, flags);
			}// class Socket Recv()

			shared_ptr<Socket> Accept() {
				shared_ptr<Socket> client(new Socket);
				int c_size = sizeof(struct sockaddr);
			#if _WIN32
				client->fd = accept(this->fd, (struct sockaddr *)(&client->address.addr), &c_size);
			#else
				client->fd = accept(this->fd, (struct sockaddr *)(&client->address.addr), (socklen_t *)&c_size);
			#endif
				client->address.host = inet_ntoa(client->address.addr.sin_addr);
				client->address.port = ntohs(client->address.addr.sin_port);
				return client;
			}// class Socket Accpet()

		#if SSL_ENABLE
			int SSL_Connect(string host, unsigned int port) {
				this->Connect(host, port);
				SSL_set_fd(this->ssl, this->fd);
				return SSL_connect(this->ssl);;

			}// class Socket SSL_Connect()

			int SSL_Send(const char *buf, size_t len) {
				return SSL_write(this->ssl, buf, (int)len);
			}// class Socket SSL_Send()

			int SSL_Recv(char *buf, size_t len) {
				return SSL_read(this->ssl, buf, (int)len);
			}// class Socket SSL_Recv()

			shared_ptr<Socket> SSL_Accept() {
				shared_ptr<Socket> client = this->Accept();
			#if SSL_ENABLE
				client->ssl = SSL_new(SSL_CTX_new(SSLv23_server_method()));
				SSL_set_fd(client->ssl, client->fd);
				if(SSL_accept(client->ssl) == -1) {
					perror("SSL accpet error");
					exit(EXIT_FAILURE);
				}
			#endif
				return client;
			}// class SSL_Socket Accpet()

		#endif // SSL SOCKET

			int Close() {
			#if SSL_ENABLE
				SSL_shutdown(this->ssl);
				SSL_free(this->ssl);
			#endif
			#if _WIN32
				return closesocket(this->fd);
			#else
				return close(this->fd);
			#endif
			}// class Socket Close()

			int SetSockOpt(int level, int optname, const char *optval, int optlen) {
				return setsockopt(this->fd, level, optname, optval, optlen);
			}// class Socket SetSockOpt

			int GetSockOpt(int level, int optname, char *optval, int *optlen) {
			#if _WIN32
				return getsockopt(this->fd, level, optname, optval, optlen);
			#else
				return getsockopt(this->fd, level, optname, optval, (socklen_t *)optlen);
			#endif
			}// class Socket GetSockOpt

			Socket(int protofamily, int type, int protocol = 0) {
				this->fd = socket(protofamily, type, protocol);
				this->address.addr.sin_family = protofamily;
			}

			Socket() {
				this->fd = -1;
			}

			~Socket() {
				this->Close();
			}
		};// class Socket

		namespace http {

			const string HTTP_DELIM = "\r\n";
			const string HTTP_VERSION = "HTTP/1.1";
			const string HTTP_USERAGENT = "xsystem-request/0";

			static int HttpInit() {
				return Socket::Init();
			}// namespace http HttpInit()

			static int HttpExit() {
				return Socket::Exit();
			}// namespace http HttpExit()

			enum HTTP_METHOD {
				GET,
				POST,
				CONNECT
			};// namespace http HTTP_METHOD

			class Response {
			public:
				string all;
				string status_code;
				string status;
				string url;
				string text;
				char *data;
				map<string, string> headers;

			public:
				Response() {
					this->data = (char *)malloc(sizeof(char) * 1024);
					if(this->data != 0) memset(this->data, '\0', 1024);
				}

				Response(string url): url(url) {
					this->data = (char *)malloc(sizeof(char) * 1024);
					if(this->data != 0) memset(this->data, '\0', 1024);
				}

				~Response() {
					free(this->data);
				}

			};// namespace http class Response

			class Request {
			public:
				string base;// http://www.baidu.com
				string domain;
				string ip;
				string body;
				unsigned int port = 80;
				map<string, string> headers;
				shared_ptr<Socket> client;
				int https = 0;

			private:
				int proxy = 0;
				string proxy_url;
				int keep_connection = 0; // client exist

			public:
				string GetProxy() {
					return this->proxy_url;
				}// class Request GetProxy()

				int UnsetProxy() {
					Request temp(this->base);
					this->ip = temp.ip;
					this->port = temp.port;
					this->domain = temp.domain;
					return (this->proxy = 0);
				}// class Request UnsetProxy()

				shared_ptr<Response> Get(string path = "/") {// /getip/id=3
					return this->PrepareHttpRequest(path, GET);
				}// class Request Get()

				shared_ptr<Response> Post(string path = "/") {
					return this->PrepareHttpRequest(path, POST);
				}// class Request Post()
				// proxy
				shared_ptr<Response> Connect(string proxy_url) {
					this->proxy_url = proxy_url;
					Request temp(proxy_url);
					shared_ptr<Socket> client(new Socket(AF_INET, SOCK_STREAM, 0));
				#if SSL_ENABLE
					if(this->https) client->SSL_Connect(Socket::domain2ip(temp.ip), temp.port);
					else client->Connect(Socket::domain2ip(temp.ip), temp.port);
				#else
					client->Connect(Socket::domain2ip(temp.ip), temp.port);
				#endif
					this->ip = temp.ip;
					this->port = temp.port;
					this->domain = temp.domain;
					this->client = client;
					this->keep_connection = 1;
					shared_ptr<Response> response = this->FuckHandleHttpRequest(this->client, "/", CONNECT);
					//cout << response->all << endl;// getall
					return response;
				}// class Request Connect()

			private:
				shared_ptr<Response> PrepareHttpRequest(string path, HTTP_METHOD method) {
					this->headers.insert({ "Accept","*/*" });
					this->headers.insert({ "Host", this->domain });
					this->headers.insert({ "User-Agent", HTTP_USERAGENT });

					if(!this->headers.count("Connection")) {
						this->headers.insert({ "Connection","close" });
					}

					if(this->keep_connection) {
						shared_ptr<Response> response = this->FuckHandleHttpRequest(this->client, path, method);
						if(this->headers["Connection"] == "close") {
							this->keep_connection = 0;
							this->client = NULL; // 释放之前
						}

						return response;
					} else {
						shared_ptr<Socket> client(new Socket(AF_INET, SOCK_STREAM, 0));
						client->Connect(this->ip, this->port); // vital connect
						if(!(this->headers["Connection"] == "close")) {
							this->keep_connection = 1;
							this->client = client;
						}

						return this->FuckHandleHttpRequest(client, path, method);

					}
				}// class Request PrepareHttpRequest()

				shared_ptr<Response> FuckHandleHttpRequest(shared_ptr<Socket> client, string path, HTTP_METHOD method) {
					shared_ptr<Response> response(new Response(this->base + path));
					// http packet construction
					string http_packet;
					switch(method) {
						case xsystem::net::http::GET:
							http_packet = "GET "; break;
						case xsystem::net::http::POST:
							http_packet = "POST "; break;
						default:
							http_packet = "GET "; break;
					}

					if(this->proxy) http_packet += this->base;
					http_packet += path + " " + HTTP_VERSION + HTTP_DELIM;

					for(pair<string, string> item : this->headers) {
						http_packet += item.first + ": " + item.second + HTTP_DELIM;
					}

					http_packet += HTTP_DELIM;
					switch(method) {
						case xsystem::net::http::GET:
							break;
						case xsystem::net::http::POST:
							http_packet += this->body; break;
							break;
						case xsystem::net::http::CONNECT:
							http_packet = "CONNECT " + this->base + path + " " + HTTP_VERSION + HTTP_DELIM
								+ "Host: " + this->domain + HTTP_DELIM
								+ "User-Agent: " + HTTP_USERAGENT + HTTP_DELIM
								+ HTTP_DELIM
								;
							break;
					}

					char c;// vital
				#if SSL_ENABLE
					if(this->https) client->SSL_Send(http_packet.c_str(), http_packet.length());
					else client->Send(http_packet.c_str(), http_packet.length(), 0);
					// first line

					// (this->https ? (client->SSL_Recv(&c, 1) && c != ' ') : (client->Recv(&c, 1, 0) && c != ' '));
					while((this->https ? (client->SSL_Recv(&c, 1) && c != ' ') : (client->Recv(&c, 1, 0) && c != ' '))) response->all += c;

					while((this->https ? (client->SSL_Recv(&c, 1) && c != ' ') : (client->Recv(&c, 1, 0) && c != ' '))) response->status_code += c;

					while((this->https ? (client->SSL_Recv(&c, 1) && c != '\r') : (client->Recv(&c, 1, 0) && c != '\r'))) response->status += c;

					this->all += " " + response->status_code + " " + response->status + "\r";

					// others
					for(;;) {
						string first, second;
						while(int len = (this->https ? (client->SSL_Recv(&c, 1)) : (client->Recv(&c, 1, 0)))) {
							response->all += c;
							if(c == '\n') {
								(this->https ? (client->SSL_Recv(&c, 1)) : (client->Recv(&c, 1, 0)));
								response->all += c;
								if(c == '\r') {
									(this->https ? (client->SSL_Recv(&c, 1)) : (client->Recv(&c, 1, 0)));
									response->all += c;
									if(c == '\n') {
										goto HTTP_CONTENT;
									}
								}
							}// check if down to body
							if(c != ':') {
								first += c;
							} else break;
						}

						(this->https ? (client->SSL_Recv(&c, 1)) : (client->Recv(&c, 1, 0)));// Space

						while((this->https ? (client->SSL_Recv(&c, 1)) : (client->Recv(&c, 1, 0))) && c != '\r') second += c;

						response->all += first + ": " + second + "\r";
						response->headers.insert({ first, second });
					}
				#else
					client->Send(http_packet.c_str(), http_packet.length(), 0);
					// first line
					while(client->Recv(&c, 1, 0) && c != ' ') response->all += c;
					while(client->Recv(&c, 1, 0) && c != ' ') response->status_code += c;
					while(client->Recv(&c, 1, 0) && c != '\r') response->status += c;
					response->all += " " + response->status_code + " " + response->status + "\r";

					// others
					for(;;) {
						string first, second;
						while(client->Recv(&c, 1)) {
							response->all += c;
							if(c == '\n') {
								client->Recv(&c, 1);
								response->all += c;
								if(c == '\r') {
									client->Recv(&c, 1);
									response->all += c;
									if(c == '\n') {
										goto HTTP_CONTENT;
									}
								}
							}// check if down to body
							if(c != ':') {
								first += c;
							} else break;
						}

						client->Recv(&c, 1, 0);// Space

						while(client->Recv(&c, 1, 0) && c != '\r') second += c;

						response->all += first + ": " + second + "\r";
						response->headers.insert({ first, second });
					}
				#endif

HTTP_CONTENT:

					if(response->headers.count("Content-Length")) {
						size_t size = stoull(response->headers["Content-Length"]);
						if(size > 1024) {
							free(response->data);
							response->data = (char *)malloc(sizeof(char) * size);
							memset(response->data, '\0', size);
						}
					}

					char buffer[1024] = { '\0' };
					size_t total = 0;

				#if SSL_ENABLE
					if(this->https) {
						while(int size = client->SSL_Recv(buffer, 1024)) {
							response->all += buffer;
							strncpy(response->data, buffer, size);
							if(size > 1024) response->data[total] = '\0';
							total += size;
						}
					} else {
						while(int size = client->Recv(buffer, 1024, 0)) {
							response->all += buffer;
							strncpy(response->data, buffer, size);
							if(size > 1024) response->data[total] = '\0';
							total += size;
						}
					}

				#else
					while(int size = client->Recv(buffer, 1024, 0)) {
						response->all += buffer;
						strncpy(response->data, buffer, size);
						if(size > 1024) response->data[total] = '\0';
						total += size;
					}
				#endif

					response->text = string(response->data);

					return response;
				}// class Request FuckHandleHttpRequest()

			public:
				Request(string base):base(base) {
					if(this->base.length() > 7) {
						if(this->base.at(4) == 's' || this->base.at(4) == 'S') {
							this->https = 1;
							this->port = 443;
						}


						size_t index = 0;
						while(this->base.at(index) != ':') index++;
						this->domain = this->base.substr((size_t)(index + 3), this->base.length());// : split

						if(size_t t = this->domain.find(':')) {
							this->ip = Socket::domain2ip(this->domain.substr(0, t));
							// if(size_t s =this->ip.)


							int f = this->domain.length() - this->ip.length();
							if(f > 1) {
								string port = this->domain.substr(t + 1, this->domain.length());
								this->port = stoul(port);
							}




						}
					}
				}

				Request() {}

				~Request() {}

			};// namespace http class Request

			const map<string, string> HttpCode = { {"100", "Continue"}, {"101", "Switching Protocols"}, {"102", "Processing"}, {"103", "Early Hints"}, {"200", "OK"}, {"201", "Created"}, {"202", "Accepted"}, {"203", "Non-Authoritative Information"}, {"204", "No Content"}, {"205", "Reset Content"}, {"206", "Partial Content"}, {"207", "Multi-Status"}, {"208", "Already Reported"}, {"226", "IM Used"}, {"300", "Multiple Choices"}, {"301", "Moved Permanently"}, {"302", "Found"}, {"303", "See Other"}, {"304", "Not Modified"}, {"305", "Use Proxy"}, {"307", "Temporary Redirect"}, {"308", "Permanent Redirect"}, {"400", "Bad Request"}, {"401", "Unauthorized"}, {"402", "Payment Required"}, {"403", "Forbidden"}, {"404", "Not Found"}, {"405", "Method Not Allowed"}, {"406", "Not Acceptable"}, {"407", "Proxy Authentication Required"}, {"408", "Request Timeout"}, {"409", "Conflict"}, {"410", "Gone"}, {"411", "Length Required"}, {"412", "Precondition Failed"}, {"413", "Request Entity Too Large"}, {"414", "Request-URI Too Long"}, {"415", "Unsupported Media Type"}, {"416", "Requested Range Not Satisfiable"}, {"417", "Expectation Failed"}, {"418", "I'm a Teapot"}, {"421", "Misdirected Request"}, {"422", "Unprocessable Entity"}, {"423", "Locked"}, {"424", "Failed Dependency"}, {"425", "Too Early"}, {"426", "Upgrade Required"}, {"428", "Precondition Required"}, {"429", "Too Many Requests"}, {"431", "Request Header Fields Too Large"}, {"451", "Unavailable For Legal Reasons"}, {"500", "Internal Server Error"}, {"501", "Not Implemented"}, {"502", "Bad Gateway"}, {"503", "Service Unavailable"}, {"504", "Gateway Timeout"}, {"505", "HTTP Version Not Supported"}, {"506", "Variant Also Negotiates"}, {"507", "Insufficient Storage"}, {"508", "Loop Detected"}, {"510", "Not Extended"}, {"511", "Network Authentication Required"} };
			const map<string, string> MimeType = { {"aac",  "audio/aac"}, {"abw",  "application/x-abiword"}, {"arc",  "application/x-freearc"}, {"avi",  "video/x-msvideo"}, {"azw",  "application/vnd.amazon.ebook"}, {"bin",  "application/octet-stream"}, {"bmp",  "image/bmp"}, {"bz",  "application/x-bzip"}, {"bz2",  "application/x-bzip2"}, {"csh",  "application/x-csh"}, {"css",  "text/css"}, {"csv",  "text/csv"}, {"doc",  "application/msword"}, {"docx",  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}, {"eot",  "application/vnd.ms-fontobject"}, {"epub",  "application/epub+zip"}, {"gif",  "image/gif"}, {"htm",  "text/html"}, {"html",  "text/html"}, {"ico",  "image/vnd.microsoft.icon"}, {"ics",  "text/calendar"}, {"jar",  "application/java-archive"}, {"jpeg",  "image/jpeg"}, {"jpg",  "image/jpeg"}, {"js",  "text/javascript"}, {"json",  "application/json"}, {"jsonld",  "application/ld+json"}, {"mid",  "audio/midi"}, {"midi",  "audio/x-midi"}, {"mjs",  "text/javascript"}, {"mp3",  "audio/mpeg"}, {"mpeg",  "video/mpeg"}, {"mpkg",  "application/vnd.apple.installer+xml"}, {"odp",  "application/vnd.oasis.opendocument.presentation"}, {"ods",  "application/vnd.oasis.opendocument.spreadsheet"}, {"odt",  "application/vnd.oasis.opendocument.text"}, {"oga",  "audio/ogg"}, {"ogv",  "video/ogg"}, {"ogx",  "application/ogg"}, {"otf",  "font/otf"}, {"png",  "image/png"}, {"pdf",  "application/pdf"}, {"ppt",  "application/vnd.ms-powerpoint"}, {"pptx",  "application/vnd.openxmlformats-officedocument.presentationml.presentation"}, {"rar",  "application/x-rar-compressed"}, {"rtf",  "application/rtf"}, {"sh",  "application/x-sh"}, {"svg",  "image/svg+xml"}, {"swf",  "application/x-shockwave-flash"}, {"tar",  "application/x-tar"}, {"tif",  "image/tiff"}, {"tiff",  "image/tiff"}, {"ttf",  "font/ttf"}, {"txt",  "text/plain"}, {"vsd",  "application/vnd.visio"}, {"wav",  "audio/wav"}, {"weba",  "audio/webm"}, {"webm",  "video/webm"}, {"webp",  "image/webp"}, {"woff",  "font/woff"}, {"woff2",  "font/woff2"}, {"xhtml",  "application/xhtml+xml"}, {"xls",  "application/vnd.ms-excel"}, {"xlsx",  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}, {"xml",  "text/xml"}, {"xul",  "application/vnd.mozilla.xul+xml"}, {"zip",  "application/zip"}, {"3gp",  "audio/video "}, {"3g2",  "audio/video "}, {"7z",  "application/x-7z-compressed"} };

			string GetHttpCode(string status_code) {
				if(HttpCode.count(status_code)) return HttpCode.find(status_code)->second;
				else return "No Status";
			}

			string GetMimeType(string suffix) {
				if(MimeType.count(suffix)) return MimeType.find(suffix)->second;
				else return MimeType.find("html")->second;
			}

		};// namespace http

	};// namespace net

	namespace os {
		// for path
	#if _WIN32
		const string SYSTEM_PATH_DELIM = "\\\\";
	#else
		const string SYSTEM_PATH_DELIM = "/";
	#endif
		string GetEnv(string key) {
			char *p = getenv(key.c_str());
			if(p != NULL) return p;
			else return "NO ENV";
		}// namespace os GetEnv()

		string GetCwd() {
			char *p = NULL;
			p = getcwd(NULL, 0);
			if(p != NULL) return p;
			else return "ERROR CWD";
		}// namespace os GetCwd()

		int Chdir(string path) {
			return chdir(path.c_str());
		}// namespace os Chidr()

		int Mkdir(string path) {
		#if _WIN32
			return mkdir(path.c_str());
		#else
			return mkdir(path.c_str(), 0755);
		#endif
		}// namespace os Mkdir()

		int Rmdir(string path) {
			return rmdir(path.c_str());
		}// namespace os Rmdir()

		int Remove(string path) {
			return remove(path.c_str());
		}// namespace os Remove()

		int FileExist(string file_path) {
			int flag = 0;
			FILE *f = fopen(file_path.c_str(), "r");
			if(f != NULL) {
				fclose(f);
				flag = 1;
			}
			return flag;
		}// namespace os FileExist()

		int DirExist(string dir_path) {
			int flag = 0;
		#if _WIN32
			struct _stat filestat;
			if((_stat(dir_path.c_str(), &filestat) == 0) && (filestat.st_mode & _S_IFDIR)) {
				flag = 1;
			}
		#else
			struct  stat filestat;
			if((stat(dir_path.c_str(), &filestat) == 0) && S_ISDIR(filestat.st_mode)) {
				flag = 1;
			}
		#endif
			return flag;
		}// namespace os DirExist()

		string JoinPath(string base, vector<string> other) {
			string path = base;
			for(string temp : other) {
				path += SYSTEM_PATH_DELIM + temp;
			}
			return path;
		}
	#if _WIN32
		void __get_all_from(string path, vector<string> &files) {
			intptr_t hFile = 0;
			struct _finddata_t fileinfo;
			string p;
			if((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)//若查找成功，则进入
			{
				do {
					files.push_back(fileinfo.name);
				} while(_findnext(hFile, &fileinfo) == 0);
				_findclose(hFile);
			}
		}// __get__all__from()
	#endif

		vector<string> ListDir(string path) {
			vector<string> dirs;
		#if _WIN32
			__get_all_from(path, dirs);
		#else 
			DIR *dp;
			struct dirent *dirp;
			if((dp = opendir(path.c_str())) == NULL) throw "ERROR";
			while((dirp = readdir(dp)) != NULL) {
				dirs.push_back(dirp->d_name);
			}
			closedir(dp);
		#endif
			return dirs;
		}// namespace os ListDir()

	};// namespace os

	namespace when {
		string gmt_time() {
			time_t now = time(0);
			tm *gmt = gmtime(&now);
			const char *fmt = "%a, %d %b %Y %H:%M:%S GMT";
			char tstr[30];
			strftime(tstr, sizeof(tstr), fmt, gmt);
			return tstr;
		}// namespace time gmt_time()


	};// namespace time

	namespace file {
		size_t GetFileSize(const char *path) {
			if(!os::FileExist(path)) return 0;
			struct stat statbuf;
			stat(path, &statbuf);
			return  statbuf.st_size;
		}
		string GetFileLastModified(const char *path) {
			if(!os::FileExist(path)) return "";
			struct stat statbuf;
			stat(path, &statbuf);
			time_t m = statbuf.st_mtime;
			tm *gmt = gmtime(&m);
			const char *fmt = "%a, %d %b %Y %H:%M:%S GMT";
			char tstr[30];
			strftime(tstr, sizeof(tstr), fmt, gmt);
			return tstr;
		}

	};// namespace file

	namespace tools {
		class Logger {
		private:
			mutex f;
			FILE *log_file = NULL;
			int file_ok = 0;
			int debug_ok = 0;

			void BASE(string status, string text) {
				time_t now = time(&now);
				struct tm ti;
				#if _WIN32
				localtime_s(&ti, &now);
				#else
				localtime_r(&now, &ti);
				#endif
				std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
				auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
				std::time_t timestamp = tmp.count();
				string time_date = "[" + to_string(ti.tm_year + 1900)
					+ "-" + to_string(ti.tm_mon + 1)
					+ "-" + to_string(ti.tm_mday)
					+ " " + to_string(ti.tm_hour)
					+ ":" + to_string(ti.tm_min)
					+ ":" + to_string(ti.tm_sec)
					+ "." + to_string(timestamp)
					+ "] ";
				string all = time_date + "[" + status + "] " + text + "\n";

				cout << all;
				if(file_ok) {
					if(this->f.try_lock()) {
						fprintf(this->log_file, "%s", all.c_str());
						this->f.unlock();
					}
				}
			}
		public:
			Logger(const char *file_path, int debug = 0, const char *mode = "a") {
				this->debug_ok = debug;
				this->log_file = fopen(file_path, mode);
				if(this->log_file != NULL) this->file_ok = 1;
				else perror("File can not create"), exit(EXIT_FAILURE);
			}
			Logger() {}
			~Logger() {}

			void info(string text) { this->BASE("INFO", text); }
			void debug(string text) {
				if(this->debug_ok) this->BASE("DEBUG", text);
			}
			void warn(string text) { this->BASE("WARN", text); }
			void fatal(string text) { this->BASE("FATAL", text); }
			void error(string text) { this->BASE("ERROR", text); }
			void common(string text) {
				text += "\n";
				cout << text;
				if(file_ok) {
					if(this->f.try_lock()) {
						fprintf(this->log_file, "%s", text.c_str());
						this->f.unlock();
					}
				}
			}
			void setDebug(int o) {
				this->debug_ok = o;
			}
		};


	};

};// namespace xsystem

#endif
