/* Write a program to copy its input to its output, replacing each string of one or more blanks by a single blank */

#include <stdio.h>

int main() 
{
    int c, prev = 0;

    while ((c = getchar()) != EOF) {
        if (c == ' ') {
            if (prev != ' ') {
                putchar(c); /* only print a blank in output if previous character was NOT a blank */
            }
        } else {
                putchar(c); /* always print characters that aren't blankb */
            }
        prev = c; /* store this character for check in the next iteration */
    }

    return 0;
}