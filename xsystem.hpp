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
#define SOCKET int
#endif
#include <string>
using std::string;



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
				client.address.port = ntohs(client.address.addr.sin_port);
				client.address.host = inet_ntoa(client.address.addr.sin_addr);
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
		public:
			Socket(int protofamily, int type, int protocol) {
				this->fd = socket(protofamily, type, protocol);
				this->address.addr.sin_family = protofamily;
			}
			Socket() {}
			~Socket() {}
		};

	};
};





#endif