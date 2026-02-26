/* Write a program to remove trailing blanks and tabs from each line of the input a line at a time */

/* use getchar to make c the next character in the input, if c  is a blank or tab character followed by a new line character, remove it. track c and prev. if \n, check prev and if prev == tab or blank, delete preve from the array and move to the next line of the input*/

#include <stdio.h>
#define MAXLINE 1000

int get_line(char line[], int lim);
int remove_trailing (char s[]);

int get_line(char line[], int lim) { //get_line function from exercise1-17
    int c, i;

    for (i=0; i<lim && (c=getchar())!=EOF && c!='\n'; i++)  // (c=getchar())!=EOF calls getchar() to read one character, assigns it to c and compares it to EOF
        line[i] = c;

        if (c == '\n') {
            line[i] = c;
            ++i;
        }

        line[i] = '\0';
        return i;  //this value is assigned to len in main

}

int main() {

    char line[MAXLINE];

    while (get_line(line, MAXLINE) > 0 )  // if the input line is not blank
        if (remove_trailing(line) > 0)  // if the line is not blank after removal
            printf("%s", line); 
    return 0;
}

int remove_trailing (char s[]) {

    int i;

    i = 0;
    while (s[i] != '\n') 
        i++;
    i--;
    while (i > 0 && (s[i] == ' ' || s[i] == '\t')) 
        i--;

    if (i > 0) {
        i++;
        s[i] = '\n';
        i++;
        s[i] = '\0';
        return i;
        }
    return 0;  // returns the length of the line after trailing blank and tab removal

}