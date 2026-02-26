#include <stdio.h>

#define IN  1  /* inside a word */
#define OUT 0  /* outside a word */

/* count lines, words, and characters in input */
int main()
{
    int c, state;
    
    state = OUT;
    while ((c = getchar()) != EOF) {
        if (c == ' ' || c == '\n' || c == '\t') {
            if (state == IN) /* end of word */
                putchar('\n');
            state = OUT;
        }
        else { /* any other character */
            state = IN;
            putchar(c); /* print the character */
        }
    }
}