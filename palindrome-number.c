bool isPalindrome(int x){
    if(x<0)
    return false;
    if(x==0)
    return true;
    int i,n=0,m=x;
    while(m>0){
        m=m/10;
        n++;
    }
    int a[n];
    m=x;
    for(i=0;i<n;i++){
        a[i]=m%10;
        m=m/10;
    }
    for(i=0;i<=n/2-1;i++)
    {
        if(a[i]!=a[n-1-i])
        return false;
    }
    return true;

}
