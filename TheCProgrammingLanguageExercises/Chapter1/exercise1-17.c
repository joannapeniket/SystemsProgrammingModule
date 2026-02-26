/* Write a program to print all input lines that are longer than 80 lines */

#include <stdio.h>
#define MAXLINE 1000 
#define LONGLINE 80

int get_line(char s[], int lim);

int main() {
    int len;
    char line[MAXLINE];  //line is the variable that stores the actual input line - it cannot be longer than the MAXLINE constant

    while ((len = get_line(line, MAXLINE)) > 0) {  //len the actual size of the input line
        if (len > LONGLINE) {  //if the length of the input line is longer than 80
        printf("Text: %s", line);
        }
    }
    return 0;
}

int get_line(char s[], int lim) {
    int c, i;

    for (i=0; i<lim && (c=getchar())!=EOF && c!='\n'; i++)  // (c=getchar())!=EOF calls getchar() to read one character, assigns it to c and compares it to EOF
        s[i] = c;

        if (c == '\n') {
            s[i] = c;
            ++i;
        }

        s[i] = '\0';
        return i;  //this value is assigned to len in main

}

