#include <stdio.h>

int main() {
	setvbuf(stdout, 0, 2, 0);

	for (size_t i = 0; i < 100000; ++i) {
		putchar('A');
	}


	return 0;
}
