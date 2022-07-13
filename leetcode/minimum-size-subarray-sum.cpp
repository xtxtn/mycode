//209.长度最小的字符串子数组
class Solution {
public:
    int minSubArrayLen(int target, vector<int>& nums) {
        int i = 0, j = 0 ,length = 0;
        int result = INT32_MAX;
        int sum = 0;
        for ( ; j < nums.size() ;j ++){
            sum += nums[j];                 // j左移，窗口变大
            while (sum >= target ){
                length = j - i + 1;         
                result = length < result ? length : result;
                sum -= nums[i++];           // i左移，窗口变小
            }
        }
        return result = result < INT32_MAX ? result : 0;
    }
};
