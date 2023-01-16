#include "../xsystem.hpp"
using namespace xsystem::net::http;

#include <iostream>
using std::cout;
using std::endl;


int main() {
	HttpInit();
	Request req("http://www.baidu.com");
	cout << req.domain << endl;
	cout << req.port << endl;
	cout << req.ip << endl;

	HttpExit();
	return 0;
}