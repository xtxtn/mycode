//904.水果成篮
class Solution {
public:
    int totalFruit(vector<int>& fruits) {
        int m = -1, n = -1, i = 0 , j = 0 ,t;
        int length = 0 ,result = 0;
        //m = fruits[j++];
        while (1){
            m = fruits[i];                              //找到第一种水果
            while ( m == fruits[j] || n == fruits[j]){  //找到第二种水果
                if (j == fruits.size() - 1)
                    break;
                j ++;
            }
            n = fruits[j];
            t = j;   //记录第二种水果                        
            while ( m == fruits[j] || n == fruits[j] ){ //找到第三种水果时停止
                if (j == fruits.size() - 1)
                    break;
                j ++;
            }
            if ( m == fruits[j] || n == fruits[j])      //判断是否到达边界
                length = j - i + 1;
            else
                length = j - i;
            result = result > length ? result :length;
            if (j == fruits.size() - 1)                //跳出循环
            break;           
            i = t;                                     //初始化水果
            j = t;
        }
        return result;
    }
};
