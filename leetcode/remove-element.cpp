//27. 移除元素
class Solution {
public:
    int removeElement(vector<int>& nums, int val) {
        int end = nums.size();
        for (int i = 0; i < end ; i++){

            if ( nums[i] == val){
                end --;
                for (int j = i; j < end; j++){
                    nums[j] = nums[j+1];
                }
                i --;
            }
        }
        return end;
    }
};
