/* Exercise 1.4 - Write a programto print the corresponding Celsius to Fahrenheit table */

#include <stdio.h>

int main()
{
    float fahr, celsius;
    int lower, upper, step;

    lower = 0;
    upper = 300;
    step = 20;

    printf("Conversion Chart (Celsius -> Fahrenheit)\n");
    celsius = lower;
    while (celsius <= upper) {
        fahr = (9.0/5.0) * celsius + 32.0;
        printf("%3.0f %6.1f\n" ,celsius, fahr);
        celsius = celsius + step;
    }
}