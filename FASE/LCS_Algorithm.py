import numpy as np

def lcs(a, b):
    lcs_matrix = np.zeros((len(a) +1, len(b) +1), dtype=np.int64)
    for i,r in enumerate(a):
        for j,c in enumerate(b):
            if r==c:
                lcs_matrix[i+1,j+1] = lcs_matrix[i,j]+1
            else:
                lcs_matrix[i+1,j+1] = max(lcs_matrix[i,j+1], lcs_matrix[i+1,j])
    Len_LCS = lcs_matrix[-1,-1]
    LCS = []
    LCS_index =[]

    # initial max
    LCS_list = lcs_matrix [:,len(b)]
    index = np.argmax(LCS_list)
    LCS.append(a[index-1])
    LCS_index.append(index-1)
    max_value = np.max(LCS_list)
    if max_value > 1:
      for j in range (len(b)-1,0,-1):
        LCS_list = lcs_matrix [:,j]
        s_value = max_value-1
        max_value = s_value
        index_w = np.where(LCS_list == s_value)
        index = index_w[0][0]
        LCS.append(a[index-1])
        LCS_index.append(index-1)
        if s_value == 1:
          break

    # Data는 common seqeunce
    return lcs_matrix, list(reversed(LCS)), list(reversed(LCS_index))