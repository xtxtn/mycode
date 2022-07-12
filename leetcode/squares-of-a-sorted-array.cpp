//977.有序数组的平方
class Solution {
public:
    vector<int> sortedSquares(vector<int>& nums) {
        
        for (int i = 0 ; i < nums.size() ; i ++){
            nums[i] = nums[i] * nums[i];
        }
        sort(nums.begin() , nums.end());
        return nums;
        /*
        双指针
        vector<int> obj(nums.size(),0);
        int left = 0 ,right = nums.size() - 1 ,end = nums.size() - 1;
        while (left <= right){
            if (nums[left] * nums[left] >= nums[right] * nums[right]){
                obj[end] = nums[left] * nums [left];
                left ++;
                end --;
            }
            else{
                obj[end] = nums[right] * nums [right];
                right --;
                end --;
            }
        }
        return obj;
        */
    }
};
