import numpy as np
from LCS_Algorithm import lcs


def update_lcs_index (index, LCS_index ):
  # when an SF is inserted in front of the common seqeuence,
  for j in range (0, len(LCS_index)):
    if index <= LCS_index[j]:
      LCS_index[j] = LCS_index[j]+1
  return LCS_index

def update_mapping (insertIndex, Y, i, t, N):
  # find mapping_result <i>
  if Y[i][t] == -1:
    for i_sfc in range (0,N):
      SFCmap = Y[i_sfc][:]
      for i_sf, map_index in enumerate(SFCmap):
        if map_index >= insertIndex:
          Y[i_sfc][i_sf] = map_index+1
    Y[i][t] = insertIndex

  return Y

def RR (X, SFs, Resource_Map):
  i = 0
  for i_SF, SF in enumerate(X):
    i=i+Resource_Map[SFs.index(SF)]
  return i

def fase (SFlists, SFCs, SFs, Resource_Map, switch_resources,N):

    TheReqeustedSFCs = SFCs [0:N]
    SortedSFCs = TheReqeustedSFCs.argsort()[::-1]
    X = []
    Y = [[-1 for j in range(len(SFlists[i]))] for i in range(N)]

    # Part 1: without re-circulation and redundancy
    for i in range(0, N):
        SF_list = []
        SFlist = SFlists[SortedSFCs[i]]
        for t in range(0, len(SFlist)):
            SF_list.append(SFlist[t])
        if i == 0:
            X = SF_list
            Y[SortedSFCs[i]][:] = list(range(len(SFlist)))

        else:
            _, LCS, LCS_index = lcs(X, SF_list)
            for t in range(SF_list.index(LCS[0]), -1, -1):  # Insert noexsited SFs in front of LCS
                if SF_list[t] not in X:
                    X.insert(0, SF_list[t])
                    LCS_index = update_lcs_index(0, LCS_index)
                    Y = update_mapping(0, Y, SortedSFCs[i], SF_list.index(SF_list[t]), N)

            for t in range(1, len(LCS)):  # Insert noexsited SFs in middle of LCS
                insertIndex = LCS_index[t - 1] + 1
                for k in range(SF_list.index(LCS[t]), SF_list.index(LCS[t - 1])):
                    if SF_list[k] not in X:
                        X.insert(insertIndex, SF_list[k])
                        LCS_index = update_lcs_index(insertIndex, LCS_index)
                        Y = update_mapping(insertIndex, Y, SortedSFCs[i], SF_list.index(SF_list[k]), N)

            for t in range(SF_list.index(LCS[-1]) + 1, len(SF_list)):  # Insert noexsited SFs in back of LCS
                if SF_list[t] not in X:
                    insertIndex = len(X) + t
                    X.insert(insertIndex, SF_list[t])
                    Y = update_mapping(insertIndex, Y, SortedSFCs[i], SF_list.index(SF_list[t]), N)

    # Part 2: without re-circulation and with redundancy
    for i in range(1, N):
        SF_list = []
        SFlist = SFlists[SortedSFCs[i]]
        for t in range(0, len(SFlist)):
            SF_list.append(SFlist[t])

        current, LCS, LCS_index = lcs(X, SF_list)
        for t in range(0, SF_list.index(LCS[0])):
            if RR(X, SFs, Resource_Map) + Resource_Map[SFs.index(SF_list[t])] > switch_resources:
                break
            else:
                insertIndex = t
                X.insert(insertIndex, SF_list[t])
                LCS_index = update_lcs_index(insertIndex, LCS_index)
                Y = update_mapping(insertIndex, Y, SortedSFCs[i], SF_list.index(SF_list[t]), N)

        previous_index = SF_list.index(LCS[0])  # Between the LCS
        for t in range(SF_list.index(LCS[0]), SF_list.index(LCS[-1]) + 1):
            if SF_list[t] in LCS:
                previous_index = LCS_index[LCS.index(SF_list[t])]
                Y[SortedSFCs[i]][t] = previous_index

            if SF_list[t] not in LCS:
                if RR(X, SFs, Resource_Map) + Resource_Map[SFs.index(SF_list[t])] > switch_resources:
                    break
                else:
                    insertIndex = previous_index + 1
                    X.insert(insertIndex, SF_list[t])
                    LCS_index = update_lcs_index(insertIndex, LCS_index)
                    Y = update_mapping(insertIndex, Y, SortedSFCs[i], SF_list.index(SF_list[t]), N)
                    previous_index = insertIndex

        for t in range(SF_list.index(LCS[-1]) + 1, len(SF_list)):
            if RR(X, SFs, Resource_Map) + Resource_Map[SFs.index(SF_list[t])] > switch_resources:
                break
            else:
                insertIndex = len(X) + t
                X.insert(insertIndex, SF_list[t])
                Y = update_mapping(insertIndex, Y, SortedSFCs[i], SF_list.index(SF_list[t]), N)

    # Part 2: Recirculation mapping
    for i in range(0, N):
        previousSFMapping = 0
        for t in range(0, len(SFlists[i])):
            if Y[i][t] != -1:
                previousSFMapping = Y[i][t]
            if Y[i][t] == -1:
                for k in range(previousSFMapping, len(X)):
                    if SFlists[i][t] == X[k]:
                        Y[i][t] = k
                        break
                if Y[i][t] == -1:
                    for k in range(0, previousSFMapping):
                        if SFlists[i][t] == X[k]:
                            Y[i][t] = k
                            break

    return X, Y, RR(X, SFs, Resource_Map)
