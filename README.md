# xsystem

**xsystem** is a simple, yet elegant, cross-system c++ library.

xsystem include net http crypt etc. You can use it to build what you want extremely easily.

## Installing xsystem

xsystem is available on Github: https://github.com/freetbash/xsystem

```console
git clone https://github.com/freetbash/xsystem.git
and just include "xsystem.hpp"
```
## Usage
```cpp
// The SSL_ENABLE should be placed in the front fo "includes"
#define SSL_ENABLE 1 // 0
#include "xsystem.hpp"
```
## net socket
---
### server
```cpp
#include "../xsystem.hpp"
using xsystem::net::Socket;
#include <iostream>
using std::cout;
using std::endl;

int main(){
  Socket::Init();
  
  Socket s(AF_INET, SOCK_STREAM, 0);
  s.Bind("192.168.0.103", 80);
  s.Listen(5);
  
  auto c = s.Accept();
  
  char buf[1024]="Hello!";
  c->Send(buf,1024,0);
  c->Recv(buf,1024,0);
  cout << buf << endl;
  
  Socket::Exit();
  return 0;
}

```
### client
```cpp
#include "../xsystem.hpp"
using xsystem::net::Socket;
#include <iostream>
using std::cout;
using std::endl;

int main(){
  Socket::Init();
  
  Socket c(AF_INET, SOCK_STREAM, 0);
  c.Connect("192.168.0.103", 3147);
  
  char buf[1024]="Hello!";
  c.Send(buf,1024,0);
  c.Recv(buf,1024,0);
  cout << buf << endl;

  Socket::Exit();
  return 0;
}

```
### ssl server
---
```cpp
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

```
### ssl client
---
```cpp
#define SSL_ENABLE 1
#include "../xsystem.hpp"
using xsystem::net::Socket;
#include <iostream>
using std::cout;
using std::endl;

int main(){
  Socket::Init();
  
  Socket c(AF_INET, SOCK_STREAM, 0);
  c.SSL_Connect("192.168.0.103", 3147);
  
  char buf[1024]="Hello!";
  c.SSL_Send(buf,1024);
  c.SSL_Recv(buf,1024);
  cout << buf << endl;

  Socket::Exit();
  return 0;
}

```
## net http
---
```cpp
#include "../xsystem.hpp"
using namespace xsystem::net::http;

#include <iostream>
using std::cout;
using std::endl;


int main() {
	HttpInit();
	Request req("https://www.baidu.com");
	cout << req.domain << endl;
	cout << req.port << endl;
	cout << req.ip << endl;

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
```
## crypt
---
```cpp
#include "../xsystem.hpp"
using xsystem::crypt::Base64;
using xsystem::crypt::hash::sha256;
using xsystem::crypt::hash::Md5;

#include <iostream>
using std::cout;
using std::endl;

int main() {
	string text = "FreetBash";
	// base64
	string result = Base64::Encode((unsigned char *)(text.c_str()), text.length());
	cout << result << endl;
	int outlen;
	result = Base64::Decode(result.c_str(), result.size(), &outlen);
	cout << result << endl;
	// sha256
	result = sha256((unsigned char *)text.c_str(), text.size());
	cout << result<< endl;
	// md5
	result = Md5::Encode((unsigned char *)text.c_str(), text.size());
	cout << result << endl;
	// md5 file
	result = Md5::FileEncode("server.exe");
	cout << result << endl;
}
```
## At the end

Hope you can fork this repo to assist it.

##### freet-bash@qq.com 
