#include <iostream>
using namespace std; 

class hello {
public:
	int x;
	int y;
	int xe(int y){
		return y + 5;
	}
};

int main(){
	hello* g = new hello();
	g->y = 9;
	cout << g->xe(5) << endl;
}