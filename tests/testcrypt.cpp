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