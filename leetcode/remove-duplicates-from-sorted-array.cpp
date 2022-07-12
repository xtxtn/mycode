//26. 删除有序数组中的重复项
class Solution {
public:
    int removeDuplicates(vector<int>& nums) {
        int end = nums.size();
        for (int i = 1 , m = 0; i < nums.size() ; i ++){
            if ( nums[m] == nums[i]){
                end --;
            }
            else{
                nums[m+1] = nums[i];
                m ++;
            }
        }
        return end;
    }
};
