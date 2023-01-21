#include "../xsystem.hpp"
using namespace xsystem::os;

#include <iostream>
using std::cout;
using std::endl;

int main() {
	// SYSTEM_PATH_DELIM
	cout << "SYSTEM_PATH_DELIM" << endl;
	cout << SYSTEM_PATH_DELIM << endl;

	// TEST GETENV
	cout << GetEnv("PAsTH") << endl;

	// GetCwd
	string cwd = GetCwd();
	cout << cwd << endl;

	// Chdir
	int ret = Chdir("..");// fuck
	cout << GetCwd() << endl;
	ret = Chdir(cwd);

	// FileExist
	cout << FileExist("testproxyhttp.exe") << endl;
	cout << FileExist("freet.bash") << endl;

	// DirExist
	cout << DirExist("..") << endl;
	cout << DirExist("asd") << endl;
	cout << "-------------------" << endl;
	// Mkdir
	cout << Mkdir("asd") << endl;
	cout << DirExist("asd") << endl;
	cout << Rmdir("asd") << endl;
	cout << DirExist("asd") << endl;
	// Rmove
	cout << FileExist("test111111.txt") << endl;
	cout << Remove("test111111.txt") << endl;

	// ListDir

	for(auto c : ListDir(".") ){
		cout << c << endl;
	}


	return 0;
}