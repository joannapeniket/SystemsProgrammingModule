/* Given a declaration of 

    int a[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10} 
    
Write a program fragment which computes the sum of all elements of the array with even index */

#include <stdio.h>

int main() {

    int a[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    int sum = 0;
    for (int i = 0; i < 10; i += 2) {
        sum = sum + a[i];
    }

    printf("Sum = %d\n", sum);
    return 0;  
}

