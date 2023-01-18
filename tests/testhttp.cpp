#include "../xsystem.hpp"
using namespace xsystem::net::http;

#include <iostream>
using std::cout;
using std::endl;


int main() {
	HttpInit();
	Request req("http://192.168.0.103:80");
	cout << req.domain << endl;
	cout << req.port << endl;
	cout << req.ip << endl;
	req.headers["Connection"] = "keep-alive";

	auto r = req.Get();
	cout << r->status_code << endl
		 << r->status << endl
		 << r->headers["Server"] << endl
		 << r->headers["Content-Length"] << endl
		 << r->data << endl
		 << r->text << endl;
	HttpExit();
	return 0;
}