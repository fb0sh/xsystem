#pragma once
#ifndef __XSYSTEM__
#define __XSYSTEM__

// windows ok!
#if _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
#pragma comment (lib, "ws2_32.lib") 

// linux ok!
#else 
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#define SOCKET int
#endif

#include <string>
using std::string;
using std::stoll;

#include <iostream>
using std::cout;
using std::endl;

#include <map>
using std::map;
using std::pair;

namespace xsystem {

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
		};

		class Socket {
		public:
			SOCKET fd;
			Address address;

		public:
			static string domain2ip(string domain) {
				char ip[16];
			#if _WIN32
				HOSTENT *host = gethostbyname(domain.c_str());
				strcpy(ip, inet_ntoa(*(struct in_addr *)*host->h_addr_list));
			#else
				struct hostent *host = gethostbyname(domain.c_str());
				strcpy(ip, inet_ntoa(*((struct in_addr *)host->h_addr)));
			#endif
				return string(ip);
			}

			static int Init() {
			#if _WIN32
				WSADATA wsData;
				WORD wsVersion = MAKEWORD(2, 2);
				return WSAStartup(wsVersion, &wsData);
			#else
				return 0;
			#endif
			}

			static int Exit() {
			#if _WIN32
				return WSACleanup();
			#else
				return 0;
			#endif
			}

			int Bind(string host, unsigned int port) {
				this->address.host = host;
				this->address.port = port;

				this->address.addr.sin_port = htons(port);
			#if _WIN32
				this->address.addr.sin_addr.S_un.S_addr = inet_addr(host.c_str());
			#else
				this->address.addr.sin_addr.s_addr = inet_addr(host.c_str());
			#endif
				return bind(this->fd, (struct sockaddr *)(&this->address.addr), sizeof(this->address.addr));
			}

			int Connect(string host, unsigned int port) {
				struct sockaddr_in target;
				target.sin_family = this->address.addr.sin_family;
				target.sin_port = htons(port);
			#if _WIN32
				target.sin_addr.S_un.S_addr = inet_addr(host.c_str());
			#else
				target.sin_addr.s_addr = inet_addr(host.c_str());
			#endif
				return connect(this->fd, (const struct sockaddr *)(&target), sizeof(target));
			}

			int Listen(int backlog) {
				return listen(this->fd, backlog);
			}

			int Send(const char *buf, int len, int flags) {
				return send(this->fd, buf, len, flags);
			}

			int Recv(char *buf, int len, int flags) {
				return recv(this->fd, buf, len, flags);
			}

			Socket Accept() {
				Socket client;
				int c_size = sizeof(struct sockaddr);
			#if _WIN32
				client.fd = accept(this->fd, (struct sockaddr *)(&client.address.addr), &c_size);
			#else
				client.fd = accept(this->fd, (struct sockaddr *)(&client.address.addr), (socklen_t *)&c_size);
			#endif
				client.address.host = inet_ntoa(client.address.addr.sin_addr);
				client.address.port = ntohs(client.address.addr.sin_port);
				return client;
			}

			int Close() {
			#if _WIN32
				return closesocket(this->fd);
			#else
				return close(this->fd);
			#endif
			}

			int SetSockOpt(int level, int optname, const char *optval, int optlen) {
				return setsockopt(this->fd, level, optname, optval, optlen);
			}

			int GetSockOpt(int level, int optname, char *optval, int *optlen) {
			#if _WIN32
				return getsockopt(this->fd, level, optname, optval, optlen);
			#else
				return getsockopt(this->fd, level, optname, optval, (socklen_t *)optlen);
			#endif
			}

			Socket(int protofamily, int type, int protocol) {
				this->fd = socket(protofamily, type, protocol);
				this->address.addr.sin_family = protofamily;
			}

			Socket() {}

			~Socket() {}
		};

		namespace http {

			const string HTTP_DELIM = "\r\n";
			const string HTTP_VERSION = "HTTP/1.1";

			static int HttpInit() {
				return Socket::Init();
			}

			static int HttpExit() {
				return Socket::Exit();
			}

			enum HTTP_METHOD {
				GET,
				POST
			};

			class Response {
			public:
				string status_code;
				string status;
				string url;
				string text;
				char *data;
				map<string, string> headers;

			public:
				Response() {}

				Response(string url): url(url) {}

				~Response() {
					free(this->data);
				}

			};

			class Request {
			public:
				string base;// http://www.baidu.com
				string domain;
				string ip;
				string body;
				unsigned int port = 80;
				map<string, string> headers = {
					{"User-Agent", "Mozilla / 5.0 (Windows NT 10.0; Win64; x64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 53.0.2785.143 Safari / 537.36"},
					{"Accept","*/*"},
					{"Accept-Language","zh-CN,zh;q = 0.8;*"}
				};

			public:
				Response Get(string path = "/") {// /getip/id=3
					return this->FuckHandleHttpRequest(GET, path);
				}
				Response Post(string path = "/") {
					return this->FuckHandleHttpRequest(POST, path);
				}
			private:
				Response FuckHandleHttpRequest(HTTP_METHOD method, string path) {
					Response response(this->base + path);
					// http packet construction
					string http_packet;
					if(method == GET) {
						http_packet = "GET ";
					} else if(method == POST) {
						http_packet = "POST ";
					}

					http_packet += path + " " + HTTP_VERSION + HTTP_DELIM;
					for(pair<string, string> item : this->headers) {
						http_packet += item.first + ": " + item.second + HTTP_DELIM;
					}

					http_packet += HTTP_DELIM;
					if(method == POST) http_packet += this->body;

					Socket client(AF_INET, SOCK_STREAM, 0);
					client.Connect(this->ip, this->port);

					// first line
					char c;
					while(client.Recv(&c, 1, 0) && c != ' ');// HTTP/1.1
					while(client.Recv(&c, 1, 0) && c != ' ') response.status_code += c;
					while(client.Recv(&c, 1, 0) && c != '\r') response.status += c;
					// others
					int flag = 1;
					while(flag) {
						string first, second;
						while(int len = client.Recv(&c, 1, 0)) {
							if(c == '\n') {
								client.Recv(&c, 1, 0);
								if(c == '\r') {
									client.Recv(&c, 1, 0);
									if(c == '\n') {
										flag = 0;
										break;
									}
								}
							}// check if down to body
							if(c != ':') {
								first += c;
							} else break;
						}

						while(client.Recv(&c, 1, 0) && c != '\r') {
							second += c;
						}

						response.headers.insert(pair<string, string>(first, second));
					}

					if(response.headers.count("Content-Length")) {
						long long int size = stoll(response.headers["Content-Length"]);
						response.data = new char(size);
						memset(response.data, '\0', size);
					}

					char buffer[1024] = { '\0' };
					while(int size = client.Recv(buffer, 1024, 0)) {
						strncpy(response.data, buffer, size);
					}

					client.Close();
					return response;
				}

			public:
				Request(string base):base(base) {
					if(this->base.length() > 7) {
						if(this->base.at(4) == 's' || this->base.at(4) == 'S') port = 443;
						int index = 0;
						while(this->base.at(index) != ':') index++;
						this->domain = this->base.substr(index + 3, this->base.length());// : split
						this->ip = Socket::domain2ip(this->domain);
					}
				}
				Request() {}
				~Request() {}
			};
		};
	};
};





#endif