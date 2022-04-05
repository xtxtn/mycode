int* twoSum(int* nums, int numsSize, int target, int* returnSize){
    int i,j,a;
    int *ret;
    for(i=0;i<numsSize;i++){
        a=target-nums[i];
        for(j=i+1;j<numsSize;j++){
            if(a==nums[j])
            {
                ret = malloc(sizeof(int) * 2);
                ret[0] = i, ret[1] = j;
                *returnSize = 2;
                return ret;
            }
        }
    }
    ret=NULL;
    *returnSize=0;
    return ret;
}
