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
