//34.在排序数组中查找元素的第一个和最后一个位置
class Solution {
public:
    vector<int> searchRange(vector<int>& nums, int target) {
        int left = 0 , right = nums.size() - 1;     //定义双指针
        while (left <= right){
            if (nums[left] != target){              //找到左边界
                left ++;
            } 
            if (nums[right] != target && right != 0){  //找到右边界
                right --;
            }
            if (nums[right] == target && nums[left] == target) //双指针重合时退出循环
                break;
        }
        vector<int> obj;
        if (left <= right)
            obj = {left , right};
        else
            obj = {-1 ,-1};
        return obj;
    }
};
