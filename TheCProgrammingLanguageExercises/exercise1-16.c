/* Revise the main routine of the longest-line program so it will correctly print the length of arbitrarily long input lines, and as much as possible of the text */

/* The buffer is there as allocated storage for the actual text (what fits), but we report the complete length by continuing to count characters we dont have room to store */

/* int getline(char s[], int lim)
{
    int c, i;  // 
    
    for (i=0; i<lim-1 && (c=getchar())!=EOF && c!='\n'; ++i). //main loop stops when any of these is true: i<lim-1 (buffer is full - saves spaces for \n and \0), (c=getchar())!=EOF (reached end of file), c!='\n' found newline (end of line)
        s[i] = c;  // for each iteration - read a character and store it in s[i]
    if (c == '\n') {  // if we stopped because of newline, store it in the array (preserves the newline character)
        s[i] = c;
        ++i;
    }
    s[i] = '\0';  // add null terminator to make it a proper string
    return i;  // return the length (number of characters stored)

Note that a single call of getline() counts the characters on a SINGLE line, to count the characters on the next line, you need to call get line again.
} */

#include <stdio.h> 

int get_line(char s[], int lim)  // lim is the maximum size of the array s[]
{
    int c, i, j; 
    
    for (i=0; i<lim-1 && (c=getchar())!=EOF && c!='\n'; ++i)  // (c=getchar())!=EOF calls getchar() to read one character, assigns it to c and compares it to EOF
        s[i] = c;  

    if (c == '\n') {  // if newline character wound WITHIN BUFER
        s[i] = c;
        ++i;
    }
    s[i] = '\0'; 

    j = i;
    if (c != '\n' && c != EOF) {
        while((c=getchar()) != EOF && c != '\n')  // (c=getchar())!=EOF calls getchar() to read one character, assigns it to c and compares it to EOF
            ++j; 
        if (c == '\n')
            ++j;
    }

    return j;  // return the true length of the line - not what we just stored
} 

int main() {
    char line[100];
    get_line(line, 100);
}