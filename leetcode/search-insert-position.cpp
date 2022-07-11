class Solution {
public:
    int searchInsert(vector<int>& nums, int target) {
        int left = 0 , right = nums.size()-1 , middle;
        while (left <= right)
        {
            middle = (left + right) / 2;
            if (nums[middle] > target){
                right = middle - 1;
            }
            else if(nums[middle] < target){
                left = middle + 1;
            }
            else
                return middle;
        }
        return left ;
    }
};
/*
class Solution {
public:
    int searchInsert(vector<int>& nums, int target) {
        int left = 0 , right = nums.size()  , middle;
        while (left < right)
        {
            middle = (left + right) / 2;
            if (nums[middle] > target){
                right = middle ;
            }
            else if(nums[middle] < target){
                left = middle + 1;
            }
            else
                return middle;
        }
        return left ;
    }
};*/
