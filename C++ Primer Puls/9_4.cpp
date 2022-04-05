#include<iostream>
#include<cstring>
using namespace std;
template<typename T>//定义模板函数，返回最大值
T max_5(T a[],int n)
{
    T max=a[0];
   for(int i=1;i<n;i++){
       max=max>a[i]?max:a[i];
   }
   return max;
}
template<>char *max_5(char *a[],int n)//定义具体化函数，返回最长字符的地址
{ 
    char *p=a[0];
    for(int i=1;i<n;i++){
        p=strlen(p)>strlen(a[i])?p:a[i];
    }
    char *max=p;
    return max;
}
int main(){
    int a[6]={3,6,17,9,0,7};
    double b[4]={1.3,6.5,3.4,8.1};
    int x=max_5(a,6);
    cout<<x<<endl;
    double y=max_5(b,4);
    cout<<y<<endl;
    char *p[4]={"asd","sret","srtgjgs","dd"};
    char *z=max_5(p,4);
    cout<<&z<<endl;
    return 0;
}
