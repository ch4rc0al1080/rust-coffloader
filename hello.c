#include<stdio.h>
void test(int,int);

int main()
{
    int a=1,b=2,c=3,d=4;
    char e='5',f='6';
    char g[]="7777777777";
    a+b;
    c+d;
    test(a,b);
    return 0;
}

void test(int a,int b)
{
    int c=a+b;
    int d=c++;
    int e=c+d;
    char f[]="999999999";
}