int romanToInt(char * s){
    int i,n=strlen(s);
    int a[n];
    for(i=0;i<n;i++)
    {
        switch (*(s+i))
        {
            case 'I': a[i]=1;
            break;
            case 'V': a[i]=5;
            break;
            case 'X': a[i]=10;
            break;
            case 'L': a[i]=50;
            break;
            case 'C': a[i]=100;
            break;
            case 'D': a[i]=500;
            break;
            case 'M': a[i]=1000;
            break;
        }
    }
    int sum=0;
    for(i=0;i<n-1;i++){
        if(a[i]<a[i+1])
        {
            sum+=a[i+1]-a[i];
            a[i+1]=0;
            i++;
        }
        else
        sum+=a[i];
    }
    if(a[n-1])
    sum+=a[n-1];
   
    return sum;
}
