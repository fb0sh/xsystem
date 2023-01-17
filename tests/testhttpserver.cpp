#include "../xsystem.hpp"
using namespace xsystem::net;
#include <iostream>
using std::cout;
using std::endl;

int main() {
	Socket::Init();
	Socket s(AF_INET, SOCK_STREAM, 0);
	s.Bind("192.168.0.103", 80);
	s.Listen(5);
	auto c = s.Accept();

	char buf[1024];
	while(c.Recv(buf,1024,0)) {
		cout << buf << endl;
	}

	char htx[87] = "HTTP/1.1 200 Ok\r\nServer: TestServer\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n123";
	c.Send(htx, 87, 0);
	c.Close();
	s.Close();
	Socket::Exit();
	return 0;
}