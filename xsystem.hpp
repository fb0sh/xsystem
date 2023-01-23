/*****************************************************************************
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
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>
#define SOCKET int

#endif

// c++
#include <string>
using std::string;
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

#include <time.h>
#include <stdint.h>

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
					exit(-1);
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

			const map<string, string> HttpCode = {
				{"100", "Continue"},
				{"101", "Switching Protocols"},
				{"102", "Processing"},
				{"103", "Early Hints"},
				{"200", "OK"},
				{"201", "Created"},
				{"202", "Accepted"},
				{"203", "Non-Authoritative Information"},
				{"204", "No Content"},
				{"205", "Reset Content"},
				{"206", "Partial Content"},
				{"207", "Multi-Status"},
				{"208", "Already Reported"},
				{"226", "IM Used"},
				{"300", "Multiple Choices"},
				{"301", "Moved Permanently"},
				{"302", "Found"},
				{"303", "See Other"},
				{"304", "Not Modified"},
				{"305", "Use Proxy"},
				{"307", "Temporary Redirect"},
				{"308", "Permanent Redirect"},
				{"400", "Bad Request"},
				{"401", "Unauthorized"},
				{"402", "Payment Required"},
				{"403", "Forbidden"},
				{"404", "Not Found"},
				{"405", "Method Not Allowed"},
				{"406", "Not Acceptable"},
				{"407", "Proxy Authentication Required"},
				{"408", "Request Timeout"},
				{"409", "Conflict"},
				{"410", "Gone"},
				{"411", "Length Required"},
				{"412", "Precondition Failed"},
				{"413", "Request Entity Too Large"},
				{"414", "Request-URI Too Long"},
				{"415", "Unsupported Media Type"},
				{"416", "Requested Range Not Satisfiable"},
				{"417", "Expectation Failed"},
				{"418", "I'm a Teapot"},
				{"421", "Misdirected Request"},
				{"422", "Unprocessable Entity"},
				{"423", "Locked"},
				{"424", "Failed Dependency"},
				{"425", "Too Early"},
				{"426", "Upgrade Required"},
				{"428", "Precondition Required"},
				{"429", "Too Many Requests"},
				{"431", "Request Header Fields Too Large"},
				{"451", "Unavailable For Legal Reasons"},
				{"500", "Internal Server Error"},
				{"501", "Not Implemented"},
				{"502", "Bad Gateway"},
				{"503", "Service Unavailable"},
				{"504", "Gateway Timeout"},
				{"505", "HTTP Version Not Supported"},
				{"506", "Variant Also Negotiates"},
				{"507", "Insufficient Storage"},
				{"508", "Loop Detected"},
				{"510", "Not Extended"},
				{"511", "Network Authentication Required"}
			};
			const map<string, string> MimeType = {
				{"js","application/javascript"},
				{"mjs","application/javascript"},
				{"json","application/json"},
				{"webmanifest","application/manifest+json"},
				{"doc","application/msword"},
				{"dot","text/vnd.graphviz"},
				{"wiz","application/msword"},
				{"bin","application/octet-stream"},
				{"a","text/vnd.a"},
				{"dll","application/octet-stream"},
				{"exe","application/octet-stream"},
				{"o","application/octet-stream"},
				{"obj","model/obj"},
				{"so","application/octet-stream"},
				{"oda","application/ODA"},
				{"pdf","application/pdf"},
				{"p7c","application/pkcs7-mime"},
				{"ps","application/postscript"},
				{"ai","application/postscript"},
				{"eps","application/postscript"},
				{"m3u","audio/x-mpegurl"},
				{"m3u8","application/vnd.apple.mpegurl"},
				{"xls","application/vnd.ms-excel"},
				{"xlb","application/vnd.ms-excel"},
				{"ppt","application/vnd.ms-powerpoint"},
				{"pot","application/vnd.ms-powerpoint"},
				{"ppa","application/vnd.ms-powerpoint"},
				{"pps","application/vnd.ms-powerpoint"},
				{"pwz","application/vnd.ms-powerpoint"},
				{"wasm","application/wasm"},
				{"bcpio","application/x-bcpio"},
				{"cpio","application/x-cpio"},
				{"csh","application/x-csh"},
				{"dvi","application/x-dvi"},
				{"gtar","application/x-gtar"},
				{"hdf","application/x-hdf"},
				{"h5","application/mipc"},
				{"latex","application/x-latex"},
				{"mif","application/vnd.mif"},
				{"cdf","application/x-netcdf"},
				{"nc","application/x-netcdf"},
				{"p12","application/pkcs12"},
				{"pfx","application/pkcs12"},
				{"ram","audio/x-pn-realaudio"},
				{"pyc","application/x-python-code"},
				{"pyo","model/vnd.pytha.pyox"},
				{"sh","application/x-sh"},
				{"shar","application/x-shar"},
				{"swf","application/vnd.adobe.flash.movie"},
				{"sv4cpio","application/x-sv4cpio"},
				{"sv4crc","application/x-sv4crc"},
				{"tar","application/x-tar"},
				{"tcl","application/x-tcl"},
				{"tex","application/x-tex"},
				{"texi","application/x-texinfo"},
				{"texinfo","application/x-texinfo"},
				{"roff","text/troff"},
				{"t","text/troff"},
				{"tr","text/troff"},
				{"man","application/x-troff-man"},
				{"me","application/x-troff-me"},
				{"ms","application/x-troff-ms"},
				{"ustar","application/x-ustar"},
				{"src","application/x-wais-source"},
				{"xsl","application/xslt+xml"},
				{"rdf","application/rdf+xml"},
				{"wsdl","application/wsdl+xml"},
				{"xpdl","application/xml"},
				{"zip","application/zip"},
				{"3gp","video/3gpp"},
				{"3gpp","video/3gpp"},
				{"3g2","video/3gpp2"},
				{"3gpp2","video/3gpp2"},
				{"aac","audio/aac"},
				{"adts","audio/aac"},
				{"loas","audio/usac"},
				{"ass","audio/aac"},
				{"au","audio/basic"},
				{"snd","audio/basic"},
				{"mp3","audio/mpeg"},
				{"mp2","audio/mpeg"},
				{"opus","audio/ogg"},
				{"aif","audio/x-aiff"},
				{"aifc","audio/x-aiff"},
				{"aiff","audio/x-aiff"},
				{"ra","audio/x-realaudio"},
				{"wav","audio/x-wav"},
				{"bmp","image/bmp"},
				{"gif","image/gif"},
				{"ief","image/ief"},
				{"jpg","image/jpeg"},
				{"jpe","image/jpeg"},
				{"jpeg","image/jpeg"},
				{"heic","image/heic"},
				{"heif","image/heif"},
				{"png","image/png"},
				{"svg","image/svg+xml"},
				{"tiff","image/tiff"},
				{"tif","image/tiff"},
				{"ico","image/vnd.microsoft.icon"},
				{"ras","image/x-cmu-raster"},
				{"pnm","image/x-portable-anymap"},
				{"pbm","image/x-portable-bitmap"},
				{"pgm","image/x-portable-graymap"},
				{"ppm","image/x-portable-pixmap"},
				{"rgb","image/x-rgb"},
				{"xbm","image/x-xbitmap"},
				{"xpm","image/x-xpixmap"},
				{"xwd","image/x-xwindowdump"},
				{"eml","message/rfc822"},
				{"mht","message/rfc822"},
				{"mhtml","message/rfc822"},
				{"nws","message/rfc822"},
				{"css","text/css"},
				{"csv","text/csv"},
				{"html","text/html"},
				{"htm","text/html"},
				{"txt","text/plain"},
				{"bat","text/plain"},
				{"c","text/plain"},
				{"h","text/plain"},
				{"ksh","text/plain"},
				{"pl","application/x-perl"},
				{"rtx","text/richtext"},
				{"tsv","text/tab-separated-values"},
				{"py","text/x-python"},
				{"etx","text/x-setext"},
				{"sgm","text/SGML"},
				{"sgml","text/SGML"},
				{"vcf","text/vcard"},
				{"xml","text/xml"},
				{"mp4","video/mp4"},
				{"mpeg","video/mpeg"},
				{"m1v","video/mpeg"},
				{"mpa","video/mpeg"},
				{"mpe","video/mpeg"},
				{"mpg","video/mpeg"},
				{"mov","video/quicktime"},
				{"qt","video/quicktime"},
				{"webm","video/webm"},
				{"avi","video/x-msvideo"},
				{"movie","video/x-sgi-movie"},
				{"a2l","application/A2L"},
				{"aml","application/AML"},
				{"ez","application/andrew-inset"},
				{"atf","application/ATF"},
				{"atfx","application/ATFX"},
				{"atxml","application/ATXML"},
				{"atom","application/atom+xml"},
				{"atomcat","application/atomcat+xml"},
				{"atomdeleted","application/atomdeleted+xml"},
				{"atomsvc","application/atomsvc+xml"},
				{"dwd","application/atsc-dwd+xml"},
				{"held","application/atsc-held+xml"},
				{"rsat","application/atsc-rsat+xml"},
				{"apxml","application/auth-policy+xml"},
				{"xdd","application/bacnet-xdd+zip"},
				{"xcs","application/calendar+xml"},
				{"cbor","application/cbor"},
				{"c3ex","application/cccex"},
				{"ccmp","application/ccmp+xml"},
				{"ccxml","application/ccxml+xml"},
				{"cdfx","application/CDFX+XML"},
				{"cdmia","application/cdmi-capability"},
				{"cdmic","application/cdmi-container"},
				{"cdmid","application/cdmi-domain"},
				{"cdmio","application/cdmi-object"},
				{"cdmiq","application/cdmi-queue"},
				{"cea","application/CEA"},
				{"cellml","application/cellml+xml"},
				{"cml","application/cellml+xml"},
				{"1clr","application/clr"},
				{"clue","application/clue_info+xml"},
				{"cmsc","application/cms"},
				{"cpl","application/cpl+xml"},
				{"csrattrs","application/csrattrs"},
				{"mpd","application/dash+xml"},
				{"mpdd","application/dashdelta"},
				{"davmount","application/davmount+xml"},
				{"dcd","application/DCD"},
				{"dcm","application/dicom"},
				{"dii","application/DII"},
				{"dit","application/DIT"},
				{"xmls","application/dskpp+xml"},
				{"dssc","application/dssc+der"},
				{"xdssc","application/dssc+xml"},
				{"dvc","application/dvcs"},
				{"es","application/ecmascript"},
				{"efi","application/efi"},
				{"emma","application/emma+xml"},
				{"emotionml","application/emotionml+xml"},
				{"epub","application/epub+zip"},
				{"exi","application/exi"},
				{"finf","application/fastinfoset"},
				{"fdt","application/fdt+xml"},
				{"pfr","application/font-tdpfr"},
				{"geojson","application/geo+json"},
				{"gpkg","application/geopackage+sqlite3"},
				{"glbin","application/gltf-buffer"},
				{"glbuf","application/gltf-buffer"},
				{"gml","application/gml+xml"},
				{"gz","application/gzip"},
				{"tar.gz","application/octet-stream"},
				{"tgz","application/gzip"},
				{"stk","application/hyperstudio"},
				{"ink","application/inkml+xml"},
				{"inkml","application/inkml+xml"},
				{"ipfix","application/ipfix"},
				{"its","application/its+xml"},
				{"jrd","application/jrd+json"},
				{"json-patch","application/json-patch+json"},
				{"jsonld","application/ld+json"},
				{"lgr","application/lgr+xml"},
				{"wlnk","application/link-format"},
				{"lostxml","application/lost+xml"},
				{"lostsyncxml","application/lostsync+xml"},
				{"lpf","application/lpf+zip"},
				{"lxf","application/LXF"},
				{"hqx","application/mac-binhex40"},
				{"mads","application/mads+xml"},
				{"mrc","application/marc"},
				{"mrcx","application/marcxml+xml"},
				{"nb","application/mathematica"},
				{"ma","application/mathematica"},
				{"mb","application/mathematica"},
				{"mml","application/mathml+xml"},
				{"mbox","application/mbox"},
				{"meta4","application/metalink4+xml"},
				{"mets","application/mets+xml"},
				{"mf4","application/MF4"},
				{"maei","application/mmt-aei+xml"},
				{"musd","application/mmt-usd+xml"},
				{"mods","application/mods+xml"},
				{"m21","application/mp21"},
				{"mp21","application/mp21"},
				{"mxf","application/mxf"},
				{"nq","application/n-quads"},
				{"nt","application/n-triples"},
				{"orq","application/ocsp-request"},
				{"ors","application/ocsp-response"},
				{"lha","application/octet-stream"},
				{"lzh","application/octet-stream"},
				{"class","application/octet-stream"},
				{"img","application/octet-stream"},
				{"iso","application/octet-stream"},
				{"odx","application/ODX"},
				{"opf","application/oebps-package+xml"},
				{"ogx","application/ogg"},
				{"oxps","application/oxps"},
				{"relo","application/p2p-overlay+xml"},
				{"pdx","application/PDX"},
				{"pem","application/pem-certificate-chain"},
				{"pgp","application/pgp-encrypted"},
				{"sig","application/pgp-signature"},
				{"p10","application/pkcs10"},
				{"p7m","application/pkcs7-mime"},
				{"p7s","application/pkcs7-signature"},
				{"p8","application/pkcs8"},
				{"p8e","application/pkcs8-encrypted"},
				{"cer","application/pkix-cert"},
				{"crl","application/pkix-crl"},
				{"pkipath","application/pkix-pkipath"},
				{"pki","application/pkixcmp"},
				{"pls","application/pls+xml"},
				{"provx","application/provenance+xml"},
				{"cw","application/prs.cww"},
				{"cww","application/prs.cww"},
				{"hpub","application/prs.hpub+zip"},
				{"rnd","application/prs.nprend"},
				{"rct","application/prs.nprend"},
				{"rdf-crypt","application/prs.rdf-xml-crypt"},
				{"xsf","application/prs.xsf+xml"},
				{"pskcxml","application/pskc+xml"},
				{"rapd","application/route-apd+xml"},
				{"sls","application/route-s-tsid+xml"},
				{"rusd","application/route-usd+xml"},
				{"rif","application/reginfo+xml"},
				{"rnc","application/relax-ng-compact-syntax"},
				{"rld","application/resource-lists-diff+xml"},
				{"rl","application/resource-lists+xml"},
				{"rfcxml","application/rfc+xml"},
				{"rs","application/rls-services+xml"},
				{"gbr","application/rpki-ghostbusters"},
				{"mft","application/rpki-manifest"},
				{"roa","application/rpki-roa"},
				{"rtf","application/rtf"},
				{"sarif-external-properties","application/sarif-external-properties+json"},
				{"sarif-external-properties.json","application/sarif-external-properties+json"},
				{"sarif","application/sarif+json"},
				{"sarif.json","application/sarif+json"},
				{"scim","application/scim+json"},
				{"scq","application/scvp-cv-request"},
				{"scs","application/scvp-cv-response"},
				{"spq","application/scvp-vp-request"},
				{"spp","application/scvp-vp-response"},
				{"sdp","application/sdp"},
				{"senml-etchc","application/senml-etch+cbor"},
				{"senml-etchj","application/senml-etch+json"},
				{"senmlc","application/senml+cbor"},
				{"senml","application/senml+json"},
				{"senmlx","application/senml+xml"},
				{"senmle","application/senml-exi"},
				{"sensmlc","application/sensml+cbor"},
				{"sensml","application/sensml+json"},
				{"sensmlx","application/sensml+xml"},
				{"sensmle","application/sensml-exi"},
				{"soc","application/sgml-open-catalog"},
				{"shf","application/shf+xml"},
				{"siv","application/sieve"},
				{"sieve","application/sieve"},
				{"cl","application/simple-filter+xml"},
				{"smil","application/smil+xml"},
				{"smi","application/smil+xml"},
				{"sml","application/smil+xml"},
				{"rq","application/sparql-query"},
				{"srx","application/sparql-results+xml"},
				{"sql","application/sql"},
				{"gram","application/srgs"},
				{"grxml","application/srgs+xml"},
				{"sru","application/sru+xml"},
				{"ssml","application/ssml+xml"},
				{"stix","application/stix+json"},
				{"swidtag","application/swid+xml"},
				{"tau","application/tamp-apex-update"},
				{"auc","application/tamp-apex-update-confirm"},
				{"tcu","application/tamp-community-update"},
				{"cuc","application/tamp-community-update-confirm"},
				{"jsontd","application/td+json"},
				{"ter","application/tamp-error"},
				{"tsa","application/tamp-sequence-adjust"},
				{"sac","application/tamp-sequence-adjust-confirm"},
				{"tur","application/tamp-update"},
				{"tuc","application/tamp-update-confirm"},
				{"tei","application/tei+xml"},
				{"teiCorpus","application/tei+xml"},
				{"odd","application/tei+xml"},
				{"tfi","application/thraud+xml"},
				{"tsq","application/timestamp-query"},
				{"tsr","application/timestamp-reply"},
				{"tsd","application/timestamped-data"},
				{"trig","application/trig"},
				{"ttml","application/ttml+xml"},
				{"gsheet","application/urc-grpsheet+xml"},
				{"rsheet","application/urc-ressheet+xml"},
				{"td","application/urc-targetdesc+xml"},
				{"uis","application/urc-uisocketdesc+xml"},
				{"1km","application/vnd.1000minds.decision-model+xml"},
				{"plb","application/vnd.3gpp.pic-bw-large"},
				{"psb","application/vnd.3gpp.pic-bw-small"},
				{"pvb","application/vnd.3gpp.pic-bw-var"},
				{"sms","application/vnd.3gpp2.sms"},
				{"tcap","application/vnd.3gpp2.tcap"},
				{"imgcal","application/vnd.3lightssoftware.imagescal"},
				{"pwn","application/vnd.3M.Post-it-Notes"},
				{"aso","application/vnd.accpac.simply.aso"},
				{"imp","application/vnd.accpac.simply.imp"},
				{"acu","application/vnd.acucobol"},
				{"atc","application/vnd.acucorp"},
				{"acutc","application/vnd.acucorp"},
				{"fcdt","application/vnd.adobe.formscentral.fcdt"},
				{"fxp","application/vnd.adobe.fxp"},
				{"fxpl","application/vnd.adobe.fxp"},
				{"xdp","application/vnd.adobe.xdp+xml"},
				{"xfdf","application/vnd.adobe.xfdf"},
				{"list3820","application/vnd.afpc.modca"},
				{"listafp","application/vnd.afpc.modca"},
				{"afp","application/vnd.afpc.modca"},
				{"pseg3820","application/vnd.afpc.modca"},
				{"ovl","application/vnd.afpc.modca-overlay"},
				{"psg","application/vnd.afpc.modca-pagesegment"},
				{"ahead","application/vnd.ahead.space"},
				{"azf","application/vnd.airzip.filesecure.azf"},
				{"azs","application/vnd.airzip.filesecure.azs"},
				{"azw3","application/vnd.amazon.mobi8-ebook"},
				{"acc","application/vnd.americandynamics.acc"},
				{"ami","application/vnd.amiga.ami"},
				{"ota","application/vnd.android.ota"},
				{"apkg","application/vnd.anki"},
				{"cii","application/vnd.anser-web-certificate-issue-initiation"},
				{"fti","application/vnd.anser-web-funds-transfer-initiation"},
				{"dist","application/vnd.apple.installer+xml"},
				{"distz","application/vnd.apple.installer+xml"},
				{"pkg","application/vnd.apple.installer+xml"},
				{"mpkg","application/vnd.apple.installer+xml"},
				{"keynote","application/vnd.apple.keynote"},
				{"numbers","application/vnd.apple.numbers"},
				{"pages","application/vnd.apple.pages"},
				{"swi","application/vnd.aristanetworks.swi"},
				{"artisan","application/vnd.artisan+json"},
				{"iota","application/vnd.astraea-software.iota"},
				{"aep","application/vnd.audiograph"},
				{"package","application/vnd.autopackage"},
				{"bmml","application/vnd.balsamiq.bmml+xml"},
				{"ac2","application/vnd.banana-accounting"},
				{"bmpr","application/vnd.balsamiq.bmpr"},
				{"mpm","application/vnd.blueice.multipass"},
				{"ep","application/vnd.bluetooth.ep.oob"},
				{"le","application/vnd.bluetooth.le.oob"},
				{"bmi","application/vnd.bmi"},
				{"rep","application/vnd.businessobjects"},
				{"tlclient","application/vnd.cendio.thinlinc.clientconf"},
				{"cdxml","application/vnd.chemdraw+xml"},
				{"pgn","application/vnd.chess-pgn"},
				{"mmd","application/vnd.chipnuts.karaoke-mmd"},
				{"cdy","application/vnd.cinderella"},
				{"csl","application/vnd.citationstyles.style+xml"},
				{"cla","application/vnd.claymore"},
				{"rp9","application/vnd.cloanto.rp9"},
				{"c4g","application/vnd.clonk.c4group"},
				{"c4d","application/vnd.clonk.c4group"},
				{"c4f","application/vnd.clonk.c4group"},
				{"c4p","application/vnd.clonk.c4group"},
				{"c4u","application/vnd.clonk.c4group"},
				{"c11amc","application/vnd.cluetrust.cartomobile-config"},
				{"c11amz","application/vnd.cluetrust.cartomobile-config-pkg"},
				{"coffee","application/vnd.coffeescript"},
				{"xodt","application/vnd.collabio.xodocuments.document"},
				{"xott","application/vnd.collabio.xodocuments.document-template"},
				{"xodp","application/vnd.collabio.xodocuments.presentation"},
				{"xotp","application/vnd.collabio.xodocuments.presentation-template"},
				{"xods","application/vnd.collabio.xodocuments.spreadsheet"},
				{"xots","application/vnd.collabio.xodocuments.spreadsheet-template"},
				{"cbr","application/vnd.comicbook-rar"},
				{"cbz","application/vnd.comicbook+zip"},
				{"ica","application/vnd.commerce-battelle"},
				{"icf","application/vnd.commerce-battelle"},
				{"icd","application/vnd.commerce-battelle"},
				{"ic0","application/vnd.commerce-battelle"},
				{"ic1","application/vnd.commerce-battelle"},
				{"ic2","application/vnd.commerce-battelle"},
				{"ic3","application/vnd.commerce-battelle"},
				{"ic4","application/vnd.commerce-battelle"},
				{"ic5","application/vnd.commerce-battelle"},
				{"ic6","application/vnd.commerce-battelle"},
				{"ic7","application/vnd.commerce-battelle"},
				{"ic8","application/vnd.commerce-battelle"},
				{"csp","application/vnd.commonspace"},
				{"cst","application/vnd.commonspace"},
				{"cdbcmsg","application/vnd.contact.cmsg"},
				{"ign","application/vnd.coreos.ignition+json"},
				{"ignition","application/vnd.coreos.ignition+json"},
				{"cmc","application/vnd.cosmocaller"},
				{"clkx","application/vnd.crick.clicker"},
				{"clkk","application/vnd.crick.clicker.keyboard"},
				{"clkp","application/vnd.crick.clicker.palette"},
				{"clkt","application/vnd.crick.clicker.template"},
				{"clkw","application/vnd.crick.clicker.wordbank"},
				{"wbs","application/vnd.criticaltools.wbs+xml"},
				{"ssvc","application/vnd.crypto-shade-file"},
				{"c9r","application/vnd.cryptomator.encrypted"},
				{"c9s","application/vnd.cryptomator.encrypted"},
				{"cryptomator","application/vnd.cryptomator.vault"},
				{"pml","application/vnd.ctc-posml"},
				{"ppd","application/vnd.cups-ppd"},
				{"curl","application/vnd.curl"},
				{"dart","application/vnd.dart"},
				{"rdz","application/vnd.data-vision.rdz"},
				{"dbf","application/vnd.dbf"},
				{"deb","application/vnd.debian.binary-package"},
				{"udeb","application/vnd.debian.binary-package"},
				{"uvf","application/vnd.dece.data"},
				{"uvvf","application/vnd.dece.data"},
				{"uvd","application/vnd.dece.data"},
				{"uvvd","application/vnd.dece.data"},
				{"uvt","application/vnd.dece.ttml+xml"},
				{"uvvt","application/vnd.dece.ttml+xml"},
				{"uvx","application/vnd.dece.unspecified"},
				{"uvvx","application/vnd.dece.unspecified"},
				{"uvz","application/vnd.dece.zip"},
				{"uvvz","application/vnd.dece.zip"},
				{"fe_launch","application/vnd.denovo.fcselayout-link"},
				{"dsm","application/vnd.desmume.movie"},
				{"dna","application/vnd.dna"},
				{"docjson","application/vnd.document+json"},
				{"scld","application/vnd.doremir.scorecloud-binary-document"},
				{"dpg","application/vnd.dpgraph"},
				{"mwc","application/vnd.dpgraph"},
				{"dpgraph","application/vnd.dpgraph"},
				{"dfac","application/vnd.dreamfactory"},
				{"fla","application/vnd.dtg.local.flash"},
				{"ait","application/vnd.dvb.ait"},
				{"svc","application/vnd.dvb.service"},
				{"geo","application/vnd.dynageo"},
				{"dzr","application/vnd.dzr"},
				{"mag","application/vnd.ecowin.chart"},
				{"nml","application/vnd.enliven"},
				{"esf","application/vnd.epson.esf"},
				{"msf","application/vnd.epson.msf"},
				{"qam","application/vnd.epson.quickanime"},
				{"slt","application/vnd.epson.salt"},
				{"ssf","application/vnd.epson.ssf"},
				{"qcall","application/vnd.ericsson.quickcall"},
				{"qca","application/vnd.ericsson.quickcall"},
				{"espass","application/vnd.espass-espass+zip"},
				{"es3","application/vnd.eszigno3+xml"},
				{"et3","application/vnd.eszigno3+xml"},
				{"asice","application/vnd.etsi.asic-e+zip"},
				{"sce","application/vnd.etsi.asic-e+zip"},
				{"asics","application/vnd.etsi.asic-s+zip"},
				{"tst","application/vnd.etsi.timestamp-token"},
				{"mpw","application/vnd.exstream-empower+zip"},
				{"pub","application/vnd.exstream-package"},
				{"ecigprofile","application/vnd.evolv.ecig.profile"},
				{"ecig","application/vnd.evolv.ecig.settings"},
				{"ecigtheme","application/vnd.evolv.ecig.theme"},
				{"ez2","application/vnd.ezpix-album"},
				{"ez3","application/vnd.ezpix-package"},
				{"dim","application/vnd.fastcopy-disk-image"},
				{"fdf","application/vnd.fdf"},
				{"msd","application/vnd.fdsn.mseed"},
				{"mseed","application/vnd.fdsn.mseed"},
				{"seed","application/vnd.fdsn.seed"},
				{"dataless","application/vnd.fdsn.seed"},
				{"flb","application/vnd.ficlab.flb+zip"},
				{"zfc","application/vnd.filmit.zfc"},
				{"gph","application/vnd.FloGraphIt"},
				{"ftc","application/vnd.fluxtime.clip"},
				{"sfd","application/vnd.font-fontforge-sfd"},
				{"fm","application/vnd.framemaker"},
				{"fnc","application/vnd.frogans.fnc"},
				{"ltf","application/vnd.frogans.ltf"},
				{"fsc","application/vnd.fsc.weblaunch"},
				{"oas","application/vnd.fujitsu.oasys"},
				{"oa2","application/vnd.fujitsu.oasys2"},
				{"oa3","application/vnd.fujitsu.oasys3"},
				{"fg5","application/vnd.fujitsu.oasysgp"},
				{"bh2","application/vnd.fujitsu.oasysprs"},
				{"ddd","application/vnd.fujixerox.ddd"},
				{"xdw","application/vnd.fujixerox.docuworks"},
				{"xbd","application/vnd.fujixerox.docuworks.binder"},
				{"xct","application/vnd.fujixerox.docuworks.container"},
				{"fzs","application/vnd.fuzzysheet"},
				{"txd","application/vnd.genomatix.tuxedo"},
				{"g3","application/vnd.geocube+xml"},
				{"g³","application/vnd.geocube+xml"},
				{"ggb","application/vnd.geogebra.file"},
				{"ggs","application/vnd.geogebra.slides"},
				{"ggt","application/vnd.geogebra.tool"},
				{"gex","application/vnd.geometry-explorer"},
				{"gre","application/vnd.geometry-explorer"},
				{"gxt","application/vnd.geonext"},
				{"g2w","application/vnd.geoplan"},
				{"g3w","application/vnd.geospace"},
				{"gmx","application/vnd.gmx"},
				{"kml","application/vnd.google-earth.kml+xml"},
				{"kmz","application/vnd.google-earth.kmz"},
				{"gqf","application/vnd.grafeq"},
				{"gqs","application/vnd.grafeq"},
				{"gac","application/vnd.groove-account"},
				{"ghf","application/vnd.groove-help"},
				{"gim","application/vnd.groove-identity-message"},
				{"grv","application/vnd.groove-injector"},
				{"gtm","application/vnd.groove-tool-message"},
				{"tpl","application/vnd.groove-tool-template"},
				{"vcg","application/vnd.groove-vcard"},
				{"hal","application/vnd.hal+xml"},
				{"zmm","application/vnd.HandHeld-Entertainment+xml"},
				{"hbci","application/vnd.hbci"},
				{"hbc","application/vnd.hbci"},
				{"kom","application/vnd.hbci"},
				{"upa","application/vnd.hbci"},
				{"pkd","application/vnd.hbci"},
				{"bpd","application/vnd.hbci"},
				{"hdt","application/vnd.hdt"},
				{"les","application/vnd.hhe.lesson-player"},
				{"hpgl","application/vnd.hp-HPGL"},
				{"hpi","application/vnd.hp-hpid"},
				{"hpid","application/vnd.hp-hpid"},
				{"hps","application/vnd.hp-hps"},
				{"jlt","application/vnd.hp-jlyt"},
				{"pcl","application/vnd.hp-PCL"},
				{"sfd-hdstx","application/vnd.hydrostatix.sof-data"},
				{"x3d","application/vnd.hzn-3d-crossword"},
				{"emm","application/vnd.ibm.electronic-media"},
				{"mpy","application/vnd.ibm.MiniPay"},
				{"irm","application/vnd.ibm.rights-management"},
				{"sc","application/vnd.ibm.secure-container"},
				{"icc","application/vnd.iccprofile"},
				{"icm","application/vnd.iccprofile"},
				{"1905.1","application/vnd.ieee.1905"},
				{"igl","application/vnd.igloader"},
				{"imf","application/vnd.imagemeter.folder+zip"},
				{"imi","application/vnd.imagemeter.image+zip"},
				{"ivp","application/vnd.immervision-ivp"},
				{"ivu","application/vnd.immervision-ivu"},
				{"imscc","application/vnd.ims.imsccv1p1"},
				{"igm","application/vnd.insors.igm"},
				{"xpw","application/vnd.intercon.formnet"},
				{"xpx","application/vnd.intercon.formnet"},
				{"i2g","application/vnd.intergeo"},
				{"qbo","application/vnd.intu.qbo"},
				{"qfx","application/vnd.intu.qfx"},
				{"rcprofile","application/vnd.ipunplugged.rcprofile"},
				{"irp","application/vnd.irepository.package+xml"},
				{"xpr","application/vnd.is-xpr"},
				{"fcs","application/vnd.isac.fcs"},
				{"jam","application/vnd.jam"},
				{"rms","application/vnd.jcp.javame.midlet-rms"},
				{"jisp","application/vnd.jisp"},
				{"joda","application/vnd.joost.joda-archive"},
				{"ktz","application/vnd.kahootz"},
				{"ktr","application/vnd.kahootz"},
				{"karbon","application/vnd.kde.karbon"},
				{"chrt","application/vnd.kde.kchart"},
				{"kfo","application/vnd.kde.kformula"},
				{"flw","application/vnd.kde.kivio"},
				{"kon","application/vnd.kde.kontour"},
				{"kpr","application/vnd.kde.kpresenter"},
				{"kpt","application/vnd.kde.kpresenter"},
				{"ksp","application/vnd.kde.kspread"},
				{"kwd","application/vnd.kde.kword"},
				{"kwt","application/vnd.kde.kword"},
				{"htke","application/vnd.kenameaapp"},
				{"kia","application/vnd.kidspiration"},
				{"kne","application/vnd.Kinar"},
				{"knp","application/vnd.Kinar"},
				{"sdf","application/vnd.Kinar"},
				{"skp","application/vnd.koan"},
				{"skd","application/vnd.koan"},
				{"skm","application/vnd.koan"},
				{"skt","application/vnd.koan"},
				{"sse","application/vnd.kodak-descriptor"},
				{"las","application/vnd.las"},
				{"lasjson","application/vnd.las.las+json"},
				{"lasxml","application/vnd.las.las+xml"},
				{"lbd","application/vnd.llamagraphics.life-balance.desktop"},
				{"lbe","application/vnd.llamagraphics.life-balance.exchange+xml"},
				{"lcs","application/vnd.logipipe.circuit+zip"},
				{"lca","application/vnd.logipipe.circuit+zip"},
				{"loom","application/vnd.loom"},
				{"123","application/vnd.lotus-1-2-3"},
				{"wk4","application/vnd.lotus-1-2-3"},
				{"wk3","application/vnd.lotus-1-2-3"},
				{"wk1","application/vnd.lotus-1-2-3"},
				{"apr","application/vnd.lotus-approach"},
				{"vew","application/vnd.lotus-approach"},
				{"prz","application/vnd.lotus-freelance"},
				{"pre","application/vnd.lotus-freelance"},
				{"nsf","application/vnd.lotus-notes"},
				{"ntf","application/vnd.lotus-notes"},
				{"ndl","application/vnd.lotus-notes"},
				{"ns4","application/vnd.lotus-notes"},
				{"ns3","application/vnd.lotus-notes"},
				{"ns2","application/vnd.lotus-notes"},
				{"nsh","application/vnd.lotus-notes"},
				{"nsg","application/vnd.lotus-notes"},
				{"or3","application/vnd.lotus-organizer"},
				{"or2","application/vnd.lotus-organizer"},
				{"org","application/vnd.lotus-organizer"},
				{"scm","application/vnd.lotus-screencam"},
				{"lwp","application/vnd.lotus-wordpro"},
				{"sam","application/vnd.lotus-wordpro"},
				{"portpkg","application/vnd.macports.portpkg"},
				{"mvt","application/vnd.mapbox-vector-tile"},
				{"mdc","application/vnd.marlin.drm.mdcf"},
				{"mmdb","application/vnd.maxmind.maxmind-db"},
				{"mcd","application/vnd.mcd"},
				{"mc1","application/vnd.medcalcdata"},
				{"cdkey","application/vnd.mediastation.cdkey"},
				{"mwf","application/vnd.MFER"},
				{"mfm","application/vnd.mfmp"},
				{"flo","application/vnd.micrografx.flo"},
				{"igx","application/vnd.micrografx.igx"},
				{"daf","application/vnd.Mobius.DAF"},
				{"dis","application/vnd.Mobius.DIS"},
				{"mbk","application/vnd.Mobius.MBK"},
				{"mqy","application/vnd.Mobius.MQY"},
				{"msl","application/vnd.Mobius.MSL"},
				{"plc","application/vnd.Mobius.PLC"},
				{"txf","application/vnd.Mobius.TXF"},
				{"mpn","application/vnd.mophun.application"},
				{"mpc","application/vnd.mophun.certificate"},
				{"xul","application/vnd.mozilla.xul+xml"},
				{"3mf","application/vnd.ms-3mfdocument"},
				{"cil","application/vnd.ms-artgalry"},
				{"asf","application/vnd.ms-asf"},
				{"cab","application/vnd.ms-cab-compressed"},
				{"xlm","application/vnd.ms-excel"},
				{"xla","application/vnd.ms-excel"},
				{"xlc","application/vnd.ms-excel"},
				{"xlt","application/vnd.ms-excel"},
				{"xlw","application/vnd.ms-excel"},
				{"xltm","application/vnd.ms-excel.template.macroEnabled.12"},
				{"xlam","application/vnd.ms-excel.addin.macroEnabled.12"},
				{"xlsb","application/vnd.ms-excel.sheet.binary.macroEnabled.12"},
				{"xlsm","application/vnd.ms-excel.sheet.macroEnabled.12"},
				{"eot","application/vnd.ms-fontobject"},
				{"chm","application/vnd.ms-htmlhelp"},
				{"ims","application/vnd.ms-ims"},
				{"lrm","application/vnd.ms-lrm"},
				{"thmx","application/vnd.ms-officetheme"},
				{"ppam","application/vnd.ms-powerpoint.addin.macroEnabled.12"},
				{"pptm","application/vnd.ms-powerpoint.presentation.macroEnabled.12"},
				{"sldm","application/vnd.ms-powerpoint.slide.macroEnabled.12"},
				{"ppsm","application/vnd.ms-powerpoint.slideshow.macroEnabled.12"},
				{"potm","application/vnd.ms-powerpoint.template.macroEnabled.12"},
				{"mpp","application/vnd.ms-project"},
				{"mpt","application/vnd.ms-project"},
				{"tnef","application/vnd.ms-tnef"},
				{"tnf","application/vnd.ms-tnef"},
				{"docm","application/vnd.ms-word.document.macroEnabled.12"},
				{"dotm","application/vnd.ms-word.template.macroEnabled.12"},
				{"wcm","application/vnd.ms-works"},
				{"wdb","application/vnd.ms-works"},
				{"wks","application/vnd.ms-works"},
				{"wps","application/vnd.ms-works"},
				{"wpl","application/vnd.ms-wpl"},
				{"xps","application/vnd.ms-xpsdocument"},
				{"msa","application/vnd.msa-disk-image"},
				{"mseq","application/vnd.mseq"},
				{"crtr","application/vnd.multiad.creator"},
				{"cif","application/vnd.multiad.creator.cif"},
				{"mus","application/vnd.musician"},
				{"msty","application/vnd.muvee.style"},
				{"taglet","application/vnd.mynfc"},
				{"nebul","application/vnd.nebumind.line"},
				{"line","application/vnd.nebumind.line"},
				{"entity","application/vnd.nervana"},
				{"request","application/vnd.nervana"},
				{"bkm","application/vnd.nervana"},
				{"kcm","application/vnd.nervana"},
				{"nimn","application/vnd.nimn"},
				{"nitf","application/vnd.nitf"},
				{"nlu","application/vnd.neurolanguage.nlu"},
				{"nds","application/vnd.nintendo.nitro.rom"},
				{"sfc","application/vnd.nintendo.snes.rom"},
				{"smc","application/vnd.nintendo.snes.rom"},
				{"nnd","application/vnd.noblenet-directory"},
				{"nns","application/vnd.noblenet-sealer"},
				{"nnw","application/vnd.noblenet-web"},
				{"ac","application/vnd.nokia.n-gage.ac+xml"},
				{"ngdat","application/vnd.nokia.n-gage.data"},
				{"n-gage","application/vnd.nokia.n-gage.symbian.install"},
				{"rpst","application/vnd.nokia.radio-preset"},
				{"rpss","application/vnd.nokia.radio-presets"},
				{"edm","application/vnd.novadigm.EDM"},
				{"edx","application/vnd.novadigm.EDX"},
				{"ext","application/vnd.novadigm.EXT"},
				{"odc","application/vnd.oasis.opendocument.chart"},
				{"otc","application/vnd.oasis.opendocument.chart-template"},
				{"odb","application/vnd.oasis.opendocument.database"},
				{"odf","application/vnd.oasis.opendocument.formula"},
				{"odg","application/vnd.oasis.opendocument.graphics"},
				{"otg","application/vnd.oasis.opendocument.graphics-template"},
				{"odi","application/vnd.oasis.opendocument.image"},
				{"oti","application/vnd.oasis.opendocument.image-template"},
				{"odp","application/vnd.oasis.opendocument.presentation"},
				{"otp","application/vnd.oasis.opendocument.presentation-template"},
				{"ods","application/vnd.oasis.opendocument.spreadsheet"},
				{"ots","application/vnd.oasis.opendocument.spreadsheet-template"},
				{"odt","application/vnd.oasis.opendocument.text"},
				{"odm","application/vnd.oasis.opendocument.text-master"},
				{"ott","application/vnd.oasis.opendocument.text-template"},
				{"oth","application/vnd.oasis.opendocument.text-web"},
				{"xo","application/vnd.olpc-sugar"},
				{"dd2","application/vnd.oma.dd2+xml"},
				{"tam","application/vnd.onepager"},
				{"tamp","application/vnd.onepagertamp"},
				{"tamx","application/vnd.onepagertamx"},
				{"tat","application/vnd.onepagertat"},
				{"tatp","application/vnd.onepagertatp"},
				{"tatx","application/vnd.onepagertatx"},
				{"obgx","application/vnd.openblox.game+xml"},
				{"obg","application/vnd.openblox.game-binary"},
				{"oeb","application/vnd.openeye.oeb"},
				{"oxt","application/vnd.openofficeorg.extension"},
				{"osm","application/vnd.openstreetmap.data+xml"},
				{"pptx","application/vnd.openxmlformats-officedocument.presentationml.presentation"},
				{"sldx","application/vnd.openxmlformats-officedocument.presentationml.slide"},
				{"ppsx","application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
				{"potx","application/vnd.openxmlformats-officedocument.presentationml.template"},
				{"xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
				{"xltx","application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
				{"docx","application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
				{"dotx","application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
				{"ndc","application/vnd.osa.netdeploy"},
				{"mgp","application/vnd.osgeo.mapguide.package"},
				{"dp","application/vnd.osgi.dp"},
				{"esa","application/vnd.osgi.subsystem"},
				{"oxlicg","application/vnd.oxli.countgraph"},
				{"prc","application/vnd.palm"},
				{"pdb","application/vnd.palm"},
				{"pqa","application/vnd.palm"},
				{"oprc","application/vnd.palm"},
				{"plp","application/vnd.panoply"},
				{"dive","application/vnd.patentdive"},
				{"paw","application/vnd.pawaafile"},
				{"str","application/vnd.pg.format"},
				{"ei6","application/vnd.pg.osasli"},
				{"pil","application/vnd.piaccess.application-licence"},
				{"efif","application/vnd.picsel"},
				{"wg","application/vnd.pmi.widget"},
				{"plf","application/vnd.pocketlearn"},
				{"pbd","application/vnd.powerbuilder6"},
				{"preminet","application/vnd.preminet"},
				{"box","application/vnd.previewsystems.box"},
				{"vbox","application/vnd.previewsystems.box"},
				{"mgz","application/vnd.proteus.magazine"},
				{"psfs","application/vnd.psfs"},
				{"qps","application/vnd.publishare-delta-tree"},
				{"ptid","application/vnd.pvi.ptid1"},
				{"bar","application/vnd.qualcomm.brew-app-res"},
				{"qxd","application/vnd.Quark.QuarkXPress"},
				{"qxt","application/vnd.Quark.QuarkXPress"},
				{"qwd","application/vnd.Quark.QuarkXPress"},
				{"qwt","application/vnd.Quark.QuarkXPress"},
				{"qxl","application/vnd.Quark.QuarkXPress"},
				{"qxb","application/vnd.Quark.QuarkXPress"},
				{"quox","application/vnd.quobject-quoxdocument"},
				{"quiz","application/vnd.quobject-quoxdocument"},
				{"tree","application/vnd.rainstor.data"},
				{"rar","application/vnd.rar"},
				{"bed","application/vnd.realvnc.bed"},
				{"mxl","application/vnd.recordare.musicxml"},
				{"cryptonote","application/vnd.rig.cryptonote"},
				{"link66","application/vnd.route66.link66+xml"},
				{"st","application/vnd.sailingtracker.track"},
				{"SAR","application/vnd.sar"},
				{"scd","application/vnd.scribus"},
				{"sla","application/vnd.scribus"},
				{"slaz","application/vnd.scribus"},
				{"s3df","application/vnd.sealed.3df"},
				{"scsf","application/vnd.sealed.csf"},
				{"sdoc","application/vnd.sealed.doc"},
				{"sdo","application/vnd.sealed.doc"},
				{"s1w","application/vnd.sealed.doc"},
				{"seml","application/vnd.sealed.eml"},
				{"sem","application/vnd.sealed.eml"},
				{"smht","application/vnd.sealed.mht"},
				{"smh","application/vnd.sealed.mht"},
				{"sppt","application/vnd.sealed.ppt"},
				{"s1p","application/vnd.sealed.ppt"},
				{"stif","application/vnd.sealed.tiff"},
				{"sxls","application/vnd.sealed.xls"},
				{"sxl","application/vnd.sealed.xls"},
				{"s1e","application/vnd.sealed.xls"},
				{"stml","application/vnd.sealedmedia.softseal.html"},
				{"s1h","application/vnd.sealedmedia.softseal.html"},
				{"spdf","application/vnd.sealedmedia.softseal.pdf"},
				{"spd","application/vnd.sealedmedia.softseal.pdf"},
				{"s1a","application/vnd.sealedmedia.softseal.pdf"},
				{"see","application/vnd.seemail"},
				{"sema","application/vnd.sema"},
				{"semd","application/vnd.semd"},
				{"semf","application/vnd.semf"},
				{"ssv","application/vnd.shade-save-file"},
				{"ifm","application/vnd.shana.informed.formdata"},
				{"itp","application/vnd.shana.informed.formtemplate"},
				{"iif","application/vnd.shana.informed.interchange"},
				{"ipk","application/vnd.shana.informed.package"},
				{"shp","application/vnd.shp"},
				{"shx","application/vnd.shx"},
				{"sr","application/vnd.sigrok.session"},
				{"twd","application/vnd.SimTech-MindMapper"},
				{"twds","application/vnd.SimTech-MindMapper"},
				{"mmf","application/vnd.smaf"},
				{"notebook","application/vnd.smart.notebook"},
				{"teacher","application/vnd.smart.teacher"},
				{"ptrom","application/vnd.snesdev-page-table"},
				{"pt","application/vnd.snesdev-page-table"},
				{"fo","application/vnd.software602.filler.form+xml"},
				{"zfo","application/vnd.software602.filler.form-xml-zip"},
				{"sdkm","application/vnd.solent.sdkm+xml"},
				{"sdkd","application/vnd.solent.sdkm+xml"},
				{"dxp","application/vnd.spotfire.dxp"},
				{"sfs","application/vnd.spotfire.sfs"},
				{"sqlite","application/vnd.sqlite3"},
				{"sqlite3","application/vnd.sqlite3"},
				{"smzip","application/vnd.stepmania.package"},
				{"sm","application/vnd.stepmania.stepchart"},
				{"wadl","application/vnd.sun.wadl+xml"},
				{"sus","application/vnd.sus-calendar"},
				{"susp","application/vnd.sus-calendar"},
				{"scl","application/vnd.sycle+xml"},
				{"xsm","application/vnd.syncml+xml"},
				{"bdm","application/vnd.syncml.dm+wbxml"},
				{"xdm","application/vnd.syncml.dm+xml"},
				{"ddf","application/vnd.syncml.dmddf+xml"},
				{"tao","application/vnd.tao.intent-module-archive"},
				{"pcap","application/vnd.tcpdump.pcap"},
				{"cap","application/vnd.tcpdump.pcap"},
				{"dmp","application/vnd.tcpdump.pcap"},
				{"qvd","application/vnd.theqvd"},
				{"ppttc","application/vnd.think-cell.ppttc+json"},
				{"vfr","application/vnd.tml"},
				{"viaframe","application/vnd.tml"},
				{"tmo","application/vnd.tmobile-livetv"},
				{"tpt","application/vnd.trid.tpt"},
				{"mxs","application/vnd.triscape.mxs"},
				{"tra","application/vnd.trueapp"},
				{"ufdl","application/vnd.ufdl"},
				{"ufd","application/vnd.ufdl"},
				{"frm","application/vnd.ufdl"},
				{"utz","application/vnd.uiq.theme"},
				{"umj","application/vnd.umajin"},
				{"unityweb","application/vnd.unity"},
				{"uoml","application/vnd.uoml+xml"},
				{"uo","application/vnd.uoml+xml"},
				{"urim","application/vnd.uri-map"},
				{"urimap","application/vnd.uri-map"},
				{"vmt","application/vnd.valve.source.material"},
				{"vcx","application/vnd.vcx"},
				{"mxi","application/vnd.vd-study"},
				{"study-inter","application/vnd.vd-study"},
				{"model-inter","application/vnd.vd-study"},
				{"vwx","application/vnd.vectorworks"},
				{"istc","application/vnd.veryant.thin"},
				{"isws","application/vnd.veryant.thin"},
				{"VES","application/vnd.ves.encrypted"},
				{"vsc","application/vnd.vidsoft.vidconference"},
				{"vsd","application/vnd.visio"},
				{"vst","application/vnd.visio"},
				{"vsw","application/vnd.visio"},
				{"vss","application/vnd.visio"},
				{"vis","application/vnd.visionary"},
				{"vsf","application/vnd.vsf"},
				{"sic","application/vnd.wap.sic"},
				{"slc","application/vnd.wap.slc"},
				{"wbxml","application/vnd.wap.wbxml"},
				{"wmlc","application/vnd.wap.wmlc"},
				{"wmlsc","application/vnd.wap.wmlscriptc"},
				{"wtb","application/vnd.webturbo"},
				{"p2p","application/vnd.wfa.p2p"},
				{"wsc","application/vnd.wfa.wsc"},
				{"wmc","application/vnd.wmc"},
				{"m","application/vnd.wolfram.mathematica.package"},
				{"nbp","application/vnd.wolfram.player"},
				{"wpd","application/vnd.wordperfect"},
				{"wqd","application/vnd.wqd"},
				{"stf","application/vnd.wt.stf"},
				{"wv","application/vnd.wv.csp+wbxml"},
				{"xar","application/vnd.xara"},
				{"xfdl","application/vnd.xfdl"},
				{"xfd","application/vnd.xfdl"},
				{"cpkg","application/vnd.xmpie.cpkg"},
				{"dpkg","application/vnd.xmpie.dpkg"},
				{"ppkg","application/vnd.xmpie.ppkg"},
				{"xlim","application/vnd.xmpie.xlim"},
				{"hvd","application/vnd.yamaha.hv-dic"},
				{"hvs","application/vnd.yamaha.hv-script"},
				{"hvp","application/vnd.yamaha.hv-voice"},
				{"osf","application/vnd.yamaha.openscoreformat"},
				{"saf","application/vnd.yamaha.smaf-audio"},
				{"spf","application/vnd.yamaha.smaf-phrase"},
				{"yme","application/vnd.yaoweme"},
				{"cmp","application/vnd.yellowriver-custom-menu"},
				{"zir","application/vnd.zul"},
				{"zirz","application/vnd.zul"},
				{"zaz","application/vnd.zzazz.deck+xml"},
				{"vxml","application/voicexml+xml"},
				{"vcj","application/voucher-cms+json"},
				{"wif","application/watcherinfo+xml"},
				{"wgt","application/widget"},
				{"wspolicy","application/wspolicy+xml"},
				{"xav","application/xcap-att+xml"},
				{"xca","application/xcap-caps+xml"},
				{"xdf","application/xcap-diff+xml"},
				{"xel","application/xcap-el+xml"},
				{"xer","application/xcap-error+xml"},
				{"xns","application/xcap-ns+xml"},
				{"xhtml","application/xhtml+xml"},
				{"xhtm","application/xhtml+xml"},
				{"xht","application/xhtml+xml"},
				{"xlf","application/xliff+xml"},
				{"dtd","application/xml-dtd"},
				{"xop","application/xop+xml"},
				{"xslt","application/xslt+xml"},
				{"mxml","application/xv+xml"},
				{"xhvml","application/xv+xml"},
				{"xvml","application/xv+xml"},
				{"xvm","application/xv+xml"},
				{"yang","application/yang"},
				{"yin","application/yin+xml"},
				{"zst","application/zstd"},
				{"726","audio/32kadpcm"},
				{"ac3","audio/ac3"},
				{"amr","audio/AMR"},
				{"awb","audio/AMR-WB"},
				{"acn","audio/asc"},
				{"aal","audio/ATRAC-ADVANCED-LOSSLESS"},
				{"atx","audio/ATRAC-X"},
				{"at3","audio/ATRAC3"},
				{"aa3","audio/ATRAC3"},
				{"omg","audio/ATRAC3"},
				{"dls","audio/dls"},
				{"evc","audio/EVRC"},
				{"evb","audio/EVRCB"},
				{"enw","audio/EVRCNW"},
				{"evw","audio/EVRCWB"},
				{"lbc","audio/iLBC"},
				{"l16","audio/L16"},
				{"mhas","audio/mhas"},
				{"mxmf","audio/mobile-xmf"},
				{"m4a","audio/mp4"},
				{"mpga","audio/mpeg"},
				{"mp1","audio/mpeg"},
				{"oga","audio/ogg"},
				{"ogg","audio/ogg"},
				{"spx","audio/ogg"},
				{"sid","audio/prs.sid"},
				{"psid","audio/prs.sid"},
				{"qcp","audio/QCELP"},
				{"smv","audio/SMV"},
				{"sofa","audio/sofa"},
				{"xhe","audio/usac"},
				{"koz","audio/vnd.audiokoz"},
				{"uva","audio/vnd.dece.audio"},
				{"uvva","audio/vnd.dece.audio"},
				{"eol","audio/vnd.digital-winds"},
				{"mlp","audio/vnd.dolby.mlp"},
				{"dts","audio/vnd.dts"},
				{"dtshd","audio/vnd.dts.hd"},
				{"plj","audio/vnd.everad.plj"},
				{"lvp","audio/vnd.lucent.voice"},
				{"pya","audio/vnd.ms-playready.media.pya"},
				{"vbk","audio/vnd.nortel.vbk"},
				{"ecelp4800","audio/vnd.nuera.ecelp4800"},
				{"ecelp7470","audio/vnd.nuera.ecelp7470"},
				{"ecelp9600","audio/vnd.nuera.ecelp9600"},
				{"multitrack","audio/vnd.presonus.multitrack"},
				{"rip","audio/vnd.rip"},
				{"smp3","audio/vnd.sealedmedia.softseal.mpeg"},
				{"smp","audio/vnd.sealedmedia.softseal.mpeg"},
				{"s1m","audio/vnd.sealedmedia.softseal.mpeg"},
				{"ttc","font/collection"},
				{"otf","font/otf"},
				{"ttf","font/ttf"},
				{"woff","font/woff"},
				{"woff2","font/woff2"},
				{"exr","image/aces"},
				{"avci","image/avci"},
				{"avcs","image/avcs"},
				{"avif","image/avif"},
				{"hif","image/avif"},
				{"dib","image/bmp"},
				{"cgm","image/cgm"},
				{"drle","image/dicom-rle"},
				{"emf","image/emf"},
				{"fits","image/fits"},
				{"fit","image/fits"},
				{"fts","image/fits"},
				{"heics","image/heic-sequence"},
				{"heifs","image/heif-sequence"},
				{"hej2","image/hej2k"},
				{"hsj2","image/hsj2"},
				{"jls","image/jls"},
				{"jp2","image/jp2"},
				{"jpg2","image/jp2"},
				{"jph","image/jph"},
				{"jhc","image/jphc"},
				{"jfif","image/jpeg"},
				{"jpm","image/jpm"},
				{"jpgm","image/jpm"},
				{"jpx","image/jpx"},
				{"jpf","image/jpx"},
				{"jxl","image/jxl"},
				{"jxr","image/jxr"},
				{"jxra","image/jxrA"},
				{"jxrs","image/jxrS"},
				{"jxs","image/jxs"},
				{"jxsc","image/jxsc"},
				{"jxsi","image/jxsi"},
				{"jxss","image/jxss"},
				{"ktx","image/ktx"},
				{"ktx2","image/ktx2"},
				{"btif","image/prs.btif"},
				{"btf","image/prs.btif"},
				{"pti","image/prs.pti"},
				{"svgz","image/svg+xml"},
				{"t38","image/t38"},
				{"tfx","image/tiff-fx"},
				{"psd","image/vnd.adobe.photoshop"},
				{"azv","image/vnd.airzip.accelerator.azv"},
				{"uvi","image/vnd.dece.graphic"},
				{"uvvi","image/vnd.dece.graphic"},
				{"uvg","image/vnd.dece.graphic"},
				{"uvvg","image/vnd.dece.graphic"},
				{"djvu","image/vnd.djvu"},
				{"djv","image/vnd.djvu"},
				{"dwg","image/vnd.dwg"},
				{"dxf","image/vnd.dxf"},
				{"fbs","image/vnd.fastbidsheet"},
				{"fpx","image/vnd.fpx"},
				{"fst","image/vnd.fst"},
				{"mmr","image/vnd.fujixerox.edmics-mmr"},
				{"rlc","image/vnd.fujixerox.edmics-rlc"},
				{"pgb","image/vnd.globalgraphics.pgb"},
				{"apng","image/vnd.mozilla.apng"},
				{"mdi","image/vnd.ms-modi"},
				{"b16","image/vnd.pco.b16"},
				{"hdr","image/vnd.radiance"},
				{"rgbe","image/vnd.radiance"},
				{"xyze","image/vnd.radiance"},
				{"spng","image/vnd.sealed.png"},
				{"spn","image/vnd.sealed.png"},
				{"s1n","image/vnd.sealed.png"},
				{"sgif","image/vnd.sealedmedia.softseal.gif"},
				{"sgi","image/vnd.sealedmedia.softseal.gif"},
				{"s1g","image/vnd.sealedmedia.softseal.gif"},
				{"sjpg","image/vnd.sealedmedia.softseal.jpg"},
				{"sjp","image/vnd.sealedmedia.softseal.jpg"},
				{"s1j","image/vnd.sealedmedia.softseal.jpg"},
				{"tap","image/vnd.tencent.tap"},
				{"vtf","image/vnd.valve.source.texture"},
				{"wbmp","image/vnd.wap.wbmp"},
				{"xif","image/vnd.xiff"},
				{"pcx","image/vnd.zbrush.pcx"},
				{"wmf","image/wmf"},
				{"u8msg","message/global"},
				{"u8dsn","message/global-delivery-status"},
				{"u8mdn","message/global-disposition-notification"},
				{"u8hdr","message/global-headers"},
				{"mail","message/rfc822"},
				{"art","message/rfc822"},
				{"glb","model/gltf-binary"},
				{"gltf","model/gltf+json"},
				{"igs","model/iges"},
				{"iges","model/iges"},
				{"msh","model/mesh"},
				{"mesh","model/mesh"},
				{"silo","model/mesh"},
				{"mtl","model/mtl"},
				{"stl","model/stl"},
				{"dae","model/vnd.collada+xml"},
				{"dwf","model/vnd.dwf"},
				{"gdl","model/vnd.gdl"},
				{"gsm","model/vnd.gdl"},
				{"win","model/vnd.gdl"},
				{"dor","model/vnd.gdl"},
				{"lmp","model/vnd.gdl"},
				{"rsm","model/vnd.gdl"},
				{"msm","model/vnd.gdl"},
				{"ism","model/vnd.gdl"},
				{"gtw","model/vnd.gtw"},
				{"moml","model/vnd.moml+xml"},
				{"mts","model/vnd.mts"},
				{"ogex","model/vnd.opengex"},
				{"x_b","model/vnd.parasolid.transmit.binary"},
				{"xmt_bin","model/vnd.parasolid.transmit.binary"},
				{"x_t","model/vnd.parasolid.transmit.text"},
				{"xmt_txt","model/vnd.parasolid.transmit.text"},
				{"pyox","model/vnd.pytha.pyox"},
				{"vds","model/vnd.sap.vds"},
				{"usdz","model/vnd.usdz+zip"},
				{"bsp","model/vnd.valve.source.compiled-map"},
				{"vtu","model/vnd.vtu"},
				{"wrl","model/vrml"},
				{"vrml","model/vrml"},
				{"x3db","model/x3d+xml"},
				{"x3dv","model/x3d-vrml"},
				{"x3dvz","model/x3d-vrml"},
				{"bmed","multipart/vnd.bint.med-plus"},
				{"vpm","multipart/voice-message"},
				{"appcache","text/cache-manifest"},
				{"manifest","text/cache-manifest"},
				{"ics","text/calendar"},
				{"ifb","text/calendar"},
				{"CQL","text/cql"},
				{"csvs","text/csv-schema"},
				{"soa","text/dns"},
				{"zone","text/dns"},
				{"gff3","text/gff3"},
				{"cnd","text/jcr-cnd"},
				{"markdown","text/markdown"},
				{"md","text/markdown"},
				{"miz","text/mizar"},
				{"n3","text/n3"},
				{"asc","text/plain"},
				{"text","text/plain"},
				{"pm","text/plain"},
				{"el","text/plain"},
				{"cc","text/plain"},
				{"hh","text/plain"},
				{"cxx","text/plain"},
				{"hxx","text/plain"},
				{"f90","text/plain"},
				{"conf","text/plain"},
				{"log","text/plain"},
				{"provn","text/provenance-notation"},
				{"rst","text/prs.fallenstein.rst"},
				{"tag","text/prs.lines.tag"},
				{"dsc","text/prs.lines.tag"},
				{"shaclc","text/shaclc"},
				{"shc","text/shaclc"},
				{"spdx","text/spdx"},
				{"ttl","text/turtle"},
				{"uris","text/uri-list"},
				{"uri","text/uri-list"},
				{"vcard","text/vcard"},
				{"abc","text/vnd.abc"},
				{"ascii","text/vnd.ascii-art"},
				{"copyright","text/vnd.debian.copyright"},
				{"dms","text/vnd.DMClientScript"},
				{"sub","text/vnd.dvb.subtitle"},
				{"jtd","text/vnd.esmertec.theme-descriptor"},
				{"flt","text/vnd.ficlab.flt"},
				{"fly","text/vnd.fly"},
				{"flx","text/vnd.fmi.flexstor"},
				{"gv","text/vnd.graphviz"},
				{"hans","text/vnd.hans"},
				{"hgl","text/vnd.hgl"},
				{"3dml","text/vnd.in3d.3dml"},
				{"3dm","text/vnd.in3d.3dml"},
				{"spot","text/vnd.in3d.spot"},
				{"spo","text/vnd.in3d.spot"},
				{"mpf","text/vnd.ms-mediapackage"},
				{"ccc","text/vnd.net2phone.commcenter.command"},
				{"mc2","text/vnd.senx.warpscript"},
				{"uric","text/vnd.si.uricatalogue"},
				{"jad","text/vnd.sun.j2me.app-descriptor"},
				{"sos","text/vnd.sosi"},
				{"ts","text/vnd.trolltech.linguist"},
				{"si","text/vnd.wap.si"},
				{"sl","text/vnd.wap.sl"},
				{"wml","text/vnd.wap.wml"},
				{"wmls","text/vnd.wap.wmlscript"},
				{"vtt","text/vtt"},
				{"xsd","text/xml"},
				{"rng","text/xml"},
				{"ent","text/xml-external-parsed-entity"},
				{"m4s","video/iso.segment"},
				{"mj2","video/mj2"},
				{"mjp2","video/mj2"},
				{"mpg4","video/mp4"},
				{"m4v","video/mp4"},
				{"m2v","video/mpeg"},
				{"ogv","video/ogg"},
				{"uvh","video/vnd.dece.hd"},
				{"uvvh","video/vnd.dece.hd"},
				{"uvm","video/vnd.dece.mobile"},
				{"uvvm","video/vnd.dece.mobile"},
				{"uvu","video/vnd.dece.mp4"},
				{"uvvu","video/vnd.dece.mp4"},
				{"uvp","video/vnd.dece.pd"},
				{"uvvp","video/vnd.dece.pd"},
				{"uvs","video/vnd.dece.sd"},
				{"uvvs","video/vnd.dece.sd"},
				{"uvv","video/vnd.dece.video"},
				{"uvvv","video/vnd.dece.video"},
				{"dvb","video/vnd.dvb.file"},
				{"fvt","video/vnd.fvt"},
				{"mxu","video/vnd.mpegurl"},
				{"m4u","video/vnd.mpegurl"},
				{"pyv","video/vnd.ms-playready.media.pyv"},
				{"nim","video/vnd.nokia.interleaved-multimedia"},
				{"bik","video/vnd.radgamettools.bink"},
				{"bk2","video/vnd.radgamettools.bink"},
				{"smk","video/vnd.radgamettools.smacker"},
				{"smpg","video/vnd.sealed.mpeg1"},
				{"s11","video/vnd.sealed.mpeg1"},
				{"s14","video/vnd.sealed.mpeg4"},
				{"sswf","video/vnd.sealed.swf"},
				{"ssw","video/vnd.sealed.swf"},
				{"smov","video/vnd.sealedmedia.softseal.mov"},
				{"smo","video/vnd.sealedmedia.softseal.mov"},
				{"s1q","video/vnd.sealedmedia.softseal.mov"},
				{"yt","video/vnd.youtube.yt"},
				{"viv","video/vnd.vivo"},
				{"cpt","application/mac-compactpro"},
				{"metalink","application/metalink+xml"},
				{"owx","application/owl+xml"},
				{"rss","application/rss+xml"},
				{"apk","application/vnd.android.package-archive"},
				{"dd","application/vnd.oma.dd+xml"},
				{"dcf","application/vnd.oma.drm.content"},
				{"o4a","application/vnd.oma.drm.dcf"},
				{"o4v","application/vnd.oma.drm.dcf"},
				{"dm","application/vnd.oma.drm.message"},
				{"drc","application/vnd.oma.drm.rights+wbxml"},
				{"dr","application/vnd.oma.drm.rights+xml"},
				{"sxc","application/vnd.sun.xml.calc"},
				{"stc","application/vnd.sun.xml.calc.template"},
				{"sxd","application/vnd.sun.xml.draw"},
				{"std","application/vnd.sun.xml.draw.template"},
				{"sxi","application/vnd.sun.xml.impress"},
				{"sti","application/vnd.sun.xml.impress.template"},
				{"sxm","application/vnd.sun.xml.math"},
				{"sxw","application/vnd.sun.xml.writer"},
				{"sxg","application/vnd.sun.xml.writer.global"},
				{"stw","application/vnd.sun.xml.writer.template"},
				{"sis","application/vnd.symbian.install"},
				{"mms","application/vnd.wap.mms-message"},
				{"anx","application/x-annodex"},
				{"torrent","application/x-bittorrent"},
				{"bz2","application/x-bzip2"},
				{"vcd","application/x-cdlink"},
				{"crx","application/x-chrome-extension"},
				{"dcr","application/x-director"},
				{"dir","application/x-director"},
				{"dxr","application/x-director"},
				{"spl","application/x-futuresplash"},
				{"jar","application/x-java-archive"},
				{"jnlp","application/x-java-jnlp-file"},
				{"pack","application/x-java-pack200"},
				{"kil","application/x-killustrator"},
				{"rpm","application/x-rpm"},
				{"sit","application/x-stuffit"},
				{"1","application/x-troff-man"},
				{"2","application/x-troff-man"},
				{"3","application/x-troff-man"},
				{"4","application/x-troff-man"},
				{"5","application/x-troff-man"},
				{"6","application/x-troff-man"},
				{"7","application/x-troff-man"},
				{"8","application/x-troff-man"},
				{"xpi","application/x-xpinstall"},
				{"xspf","application/x-xspf+xml"},
				{"xz","application/x-xz"},
				{"mid","audio/midi"},
				{"midi","audio/midi"},
				{"kar","audio/midi"},
				{"axa","audio/x-annodex"},
				{"flac","audio/x-flac"},
				{"mka","audio/x-matroska"},
				{"mod","audio/x-mod"},
				{"ult","audio/x-mod"},
				{"uni","audio/x-mod"},
				{"m15","audio/x-mod"},
				{"mtm","audio/x-mod"},
				{"669","audio/x-mod"},
				{"med","audio/x-mod"},
				{"wax","audio/x-ms-wax"},
				{"wma","audio/x-ms-wma"},
				{"rm","audio/x-pn-realaudio"},
				{"s3m","audio/x-s3m"},
				{"stm","audio/x-stm"},
				{"xyz","chemical/x-xyz"},
				{"webp","image/webp"},
				{"tga","image/x-targa"},
				{"sandboxed","text/html-sandboxed"},
				{"pod","text/x-pod"},
				{"axv","video/x-annodex"},
				{"flv","video/x-flv"},
				{"fxm","video/x-javafx"},
				{"mkv","video/x-matroska"},
				{"mk3d","video/x-matroska-3d"},
				{"asx","video/x-ms-asf"},
				{"wm","video/x-ms-wm"},
				{"wmv","video/x-ms-wmv"},
				{"wmx","video/x-ms-wmx"},
				{"wvx","video/x-ms-wvx"},
				{"ice","x-conference/x-cooltalk"},
				{"sisx","x-epoc/x-sisx-app"}
			};



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



};// namespace xsystem

#endif