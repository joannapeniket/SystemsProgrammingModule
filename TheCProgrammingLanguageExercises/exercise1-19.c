/* Write a function reverse(s) that reserves the character string s. Use it to write a program that reverses its input a line at a time */

#include <stdio.h>
#define MAXLINE 1000

int get_line(char s[], int lim);
void reverse(char s[]);

int main() {

    char line[MAXLINE];  // create array called line to store input

    while (get_line(line, MAXLINE) > 0) {  //if input line is not blank
        reverse(line);
        printf("%s", line);
    }
    return 0;
}

void reverse(char s[]) 
{

    int i, j;
    char temp;

    i = 0;
    while (s[i] != '\0') 
        i++;

    i--;
    if (i >= 0 && s[i] == '\n') 
        i--;
    
    j = 0;
    while (j < i) {
            temp = s[j];
            s[j] = s[i];
            s[i] = temp;
            i--;
            j++;
        }
}

int get_line(char s[], int lim) {
    int c, i;

    for (i=0; i<lim-1 && (c=getchar())!=EOF && c!='\n'; i++)  // (c=getchar())!=EOF calls getchar() to read one character, assigns it to c and compares it to EOF
        s[i] = c;

        if (c == '\n') {
            s[i] = c;
            ++i;
        }

        s[i] = '\0';
        return i;  //this value is assigned to len in main
    }