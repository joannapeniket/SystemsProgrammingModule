/* Write a program to print a histogram of the frequencies of different characters in its input */

#include <stdio.h>

#define FIRST_CHAR ' ' // ASCII 32
#define LAST_CHAR '~' // ASCII 126
#define NUM_CHARS (LAST_CHAR - FIRST_CHAR + 1) // // 126 - 32 + 1 = 95 (Why + 1? Because we're counting inclusively: from 32 TO 126 including both endpoints.) This is the number of printable ASCII characters.

int main() {

    int char_freq[NUM_CHARS] = {0}; // creates array called char_freq with 95 slots
    int c; // stores the most recent character read from the input as an input so that we can check for equivalence with EOF 
    
    while ((c = getchar() ) != EOF) {
        // only count printable characters
        if (c >= FIRST_CHAR &&  c <= LAST_CHAR) { //checks whether 
            ++char_freq[c - FIRST_CHAR]; //place printable character value stored as c in the array, c - FIRST_CHAR calculates where in the array to place c using the corresponding numeric value
        }
    }

    printf("Character Frequency Table\n");
    printf("\n");

    for (int i = 0; i < NUM_CHARS; i++) {  //iterate through the NUM_CHARS range (95 values) from 0 to 94 because i is the index not the actual values (32 to 126)
        if (char_freq[i] > 0) {  // skip over any characters that have not appeared in the input
            char ch = FIRST_CHAR + i;  // declare variable ch as 32 plus the current position in the array (essentially converts the position in the array back to the relevant ASCII character)
            printf("%c | ", ch);  // format specifier %c interprets ASCII values as their corresponding characters and prints them if they appear at least once in the input
            for (int j = 0; j < char_freq[i]; j++) {  // iterates from 0 to the value at index i in char_freq
                printf("*");  // prints '*' for each occurence of char_freq[i] in the input
            }
            printf("\n");  // move to the next line to print the next occuring character
        }
    }
    return 0;
}