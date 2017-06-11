#include <stdlib.h>
#include <stdio.h>


int main() {
    int *tmp;

    printf("Running...\n");
    scanf("%p", &tmp);

    for(int *it = tmp; it < tmp + 1024; it++) {
        printf("%p: %d\n", it, *it);
    }
    printf("%p: %d\n", tmp, *tmp);
    scanf("%p", &tmp);
}