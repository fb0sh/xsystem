#define SSL_ENABLE 1
#include "../xsystem.hpp"
using xsystem::net::Socket;
#include <iostream>
using std::cout;
using std::endl;

int main() {
	Socket::Init();

	Socket s(AF_INET, SOCK_STREAM, 0);
	s.Bind("192.168.0.103", 80);
	s.Listen(5);

	auto c = s.SSL_Accept();

	char buf[1024] = "Hello!";
	c->SSL_Send(buf, 1024);
	c->SSL_Recv(buf, 1024);
	cout << buf << endl;

	Socket::Exit();
	return 0;
}
