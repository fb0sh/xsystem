#include "../xsystem.hpp"
using xsystem::net::Socket;
#include <iostream>
using std::cin,std::cout;

int main(){
  Socket::Init();
  
  Socket c(AF_INET, SOCK_STREAM, 0);
  c.Connect("192.168.0.14", 3147);
  
  char buf[1024]="Hello!";
  c.Send(buf,1024,0);
  c.Recv(buf,1024,0);
  cout << buf << endl;
  
  c.Close();
  Socket::Exit();
  return 0;
}
