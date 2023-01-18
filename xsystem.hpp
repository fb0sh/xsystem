#pragma once
#ifndef __XSYSTEM__
#define __XSYSTEM__

// windows ok!
#if _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
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
using std::stoull;
using std::stoul;

#include <iostream>
using std::cout;
using std::endl;

#include <map>
using std::map;
using std::pair;

#include <memory>
using std::shared_ptr;

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

			int Send(const char *buf, size_t len, int flags) {
				return send(this->fd, buf, (int)len, flags);
			}

			int Recv(char *buf, size_t len, int flags) {
				return recv(this->fd, buf, (int)len, flags);
			}

			shared_ptr<Socket> Accept() {
				shared_ptr<Socket> client(new Socket);
				int c_size = sizeof(struct sockaddr);
			#if _WIN32
				client->fd = accept(this->fd, (struct sockaddr *)(&client->address.addr), &c_size);
			#else
				client->fd = accept(this->fd, (struct sockaddr *)(&client.address.addr), (socklen_t *)&c_size);
			#endif
				client->address.host = inet_ntoa(client->address.addr.sin_addr);
				client->address.port = ntohs(client->address.addr.sin_port);
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

			Socket() {
				this->fd = -1;
			}

			~Socket() {
				this->Close();
			}
		};

		namespace http {

			const string HTTP_DELIM = "\r\n";
			const string HTTP_VERSION = "HTTP/1.1";
			const string HTTP_USERAGENT = "xsystem-request/0";

			static int HttpInit() {
				return Socket::Init();
			}

			static int HttpExit() {
				return Socket::Exit();
			}

			enum HTTP_METHOD {
				GET,
				POST,
				CONNECT
			};

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

			};

			class Request {
			public:
				string base;// http://www.baidu.com
				string domain;
				string ip;
				string body;
				unsigned int port = 80;
				map<string, string> headers;
				shared_ptr<Socket> client;
			private:
				int proxy = 0;
				string proxy_url;
				int keep_connection = 0; // client exist

			public:
				string GetProxy() {
					return this->proxy_url;
				}
				int UnsetProxy() {
					Request temp(this->base);
					this->ip = temp.ip;
					this->port = temp.port;
					this->domain = temp.domain;
					return (this->proxy = 0);
				}
				shared_ptr<Response> Get(string path = "/") {// /getip/id=3
					return this->PrepareHttpRequest(path, GET);
				}

				shared_ptr<Response> Post(string path = "/") {
					return this->PrepareHttpRequest(path, POST);
				}
				// proxy
				shared_ptr<Response> Connect(string proxy_url) {
					this->proxy_url = proxy_url;
					Request temp(proxy_url);
					shared_ptr<Socket> client(new Socket(AF_INET, SOCK_STREAM, 0));
					client->Connect(Socket::domain2ip(temp.ip), temp.port);
					this->ip = temp.ip;
					this->port = temp.port;
					this->domain = temp.domain;
					this->client = client;
					this->keep_connection = 1;
					shared_ptr<Response> response = this->FuckHandleHttpRequest(this->client, "/", CONNECT);
					//cout << response->all << endl;// getall
					return response;
				}

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
				}

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

					client->Send(http_packet.c_str(), http_packet.length(), 0);

					// first line
					char c;
					while(client->Recv(&c, 1, 0) && c != ' ') {
						response->all += c;
					}; response->all += ' ';// HTTP/1.1
					while(client->Recv(&c, 1, 0) && c != ' ') {
						response->all += c;
						response->status_code += c;
					}; response->all += ' ';
					while(client->Recv(&c, 1, 0) && c != '\r') {
						response->all += c;
						response->status += c;
					}
					// others
					int flag = 1; // 
					while(flag) {
						string first, second;
						while(int len = client->Recv(&c, 1, 0)) {
							response->all += c;
							if(c == '\n') {
								client->Recv(&c, 1, 0);
								response->all += c;
								if(c == '\r') {
									client->Recv(&c, 1, 0);
									response->all += c;
									if(c == '\n') {
										flag = 0;
										goto HTTP_CONTENT;
									}
								}
							}// check if down to body
							if(c != ':') {
								first += c;
							} else break;
						}

						client->Recv(&c, 1, 0);// Space
						response->all += c;
						while(client->Recv(&c, 1, 0) && c != '\r') {
							response->all += c;
							second += c;
						}

						response->headers.insert(pair<string, string>(first, second));
					}

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
					while(int size = client->Recv(buffer, 1024, 0)) {
						response->all += buffer;
						strncpy(response->data, buffer, size);
						if(size > 1024) response->data[total] = '\0';
						total += size;
					}

					response->text = string(response->data);

					return response;
				}

			public:
				Request(string base):base(base) {
					if(this->base.length() > 7) {
						if(this->base.at(4) == 's' || this->base.at(4) == 'S') port = 443;
						size_t index = 0;
						while(this->base.at(index) != ':') index++;
						this->domain = this->base.substr((size_t)(index + 3), this->base.length());// : split
						if(size_t t = this->domain.find(':')) {
							this->ip = Socket::domain2ip(this->domain.substr(0, t));
							//if(size_t s =this->ip.)
							string port = this->domain.substr(t + 1, this->domain.length());
							if(port != this->ip) this->port = stoul(port);
						}
					}
				}

				Request() {}

				~Request() {}
			};
		};
	};
};

#endif