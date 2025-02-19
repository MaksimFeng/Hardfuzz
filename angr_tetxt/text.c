#include <stdio.h>

int main() {
    int a = 1;          // Def of a
    int b = 2;          // Def of b
    if (a > 0) {        // Use of a
        b = a + 3;      // Def of b, uses a
    } else {
        b = a - 1;      // Def of b, uses a
    }
    int c = b * 2;      // Def of c, uses b
    printf("%d\n", c);  // Use of c
    return 0;
}