//59.螺旋矩阵
class Solution {
public:
    vector<vector<int>> generateMatrix(int n) {
        vector<vector<int>> obj(n , vector<int>(n,0));
        int m = 1 ,i = 0 , j = 0;
        while ( m <= n *n){
            while (m <= n*n){
                obj[i][j] = m;
                m ++;
                j ++;
                if ( j == n || obj[i][j] != 0){
                    j --;
                    i ++;
                    break;
                }
            }
            while (m <= n*n){
                obj[i][j] = m;
                m ++;
                i ++;
                if (i == n  || obj[i][j] != 0){
                    i --;
                    j --;
                    break;
                }       
            }
            while (m <= n*n){
                obj[i][j] = m;
                m ++;
                j --;
                if (j == -1 || obj[i][j] != 0){
                    j ++;
                    i --;
                    break;
                } 
            }
            while (m <= n*n){
                obj[i][j] = m;
                m ++;
                i --;
                if (i == -1 || obj[i][j] != 0){
                    i ++;
                    j ++;
                    break;
                }
                    
            }
        }
        return obj;
        
    }
};
