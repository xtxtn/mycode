//904.水果成篮
class Solution {
public:
    int totalFruit(vector<int>& fruits) {
        int m = -1, n = -1, i = 0 , j = 0 ,t;
        int length = 0 ,result = 0;
        //m = fruits[j++];
        while (1){
            m = fruits[i];
            while ( m == fruits[j] || n == fruits[j]){
                if (j == fruits.size() - 1)
                    break;
                j ++;
            }
            n = fruits[j];
            t = j;
            while ( m == fruits[j] || n == fruits[j] ){
                if (j == fruits.size() - 1)
                    break;
                j ++;
            }
            if ( m == fruits[j] || n == fruits[j])
                length = j - i + 1;
            else
                length = j - i;
            result = result > length ? result :length;
            if (j == fruits.size() - 1) 
            break;           
            i = t;
            j = t;
        }
        return result;
    }
};
