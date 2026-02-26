/* Write a program to print a histogram of the lengths of words in its input. It is easy to draw the histogram with the bars horizontal; a vertical orientation is more challenging */

#include <stdio.h>

#define IN  1  /* inside a word */
#define OUT 0  /* outside a word */
#define MAX_LENGTH 20

int main() {
    
    int word_lengths[MAX_LENGTH] = {0}; // word_lengths = name of the array, [MAX_LENGTH] = size of the array (how many elements), {0} = initialize all elements to 0 
    int current_length = 0;
    int state = OUT;
    int c;

    while ((c = getchar()) != EOF) {
        if (c == ' ' || c == '\n' || c == '\t') {
            if (state == IN) { // word has just ended 
                ++word_lengths[current_length]; // increment the number of words of the current length
                current_length = 0; // reset current_length counter
            }
            state = OUT; 
        }
        else { // any character that isnt ' ', \t, \n
            if (state == OUT) { // start of a new word
                state = IN; 
            }
            ++current_length; //increase current-length counter by 1
        }
    }
    if (state == IN) {
        ++word_lengths[current_length];
    }
    
    printf("Word Length Histogram\n");
    printf("\n");

    int i = 1;
    while (i < MAX_LENGTH) {
        if (word_lengths[i] > 0) {
            printf("Word Length %2d | ", i);
            int j = 0;
            while (j < word_lengths[i]) {
                printf("*");
                j++;
            }
            printf("\n");
        }
        i++;
    }
    return 0;
}
