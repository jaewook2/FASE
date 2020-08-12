import numpy as np
from FASE_Algorithm import fase


SFlists = (('FW', 'NAT', 'L3', 'LB'), ('LB', 'FW'), ('NAT', 'L2', 'LB', 'L3', 'FW'), ('LB','NAT'))
SFCs = np.array([1, 2, 3, 4]) # set incoming rate
SFs= ['LB', 'NAT', 'FW', 'L3', 'L2']
Resource_Map = [3,2,1,1,1]
N=4
switch_resources = 11

X,Y, Resource = fase(SFlists, SFCs, SFs, Resource_Map, switch_resources,N)

def _CalculateRecirculation (Y,N):
    numberOfRecirculation = 0
    for i_sfc in range (N):
        previousMapping = 0
        for i_sf in range (len(Y[i_sfc][:])):
            if previousMapping > Y[i_sfc][i_sf]:
                numberOfRecirculation = numberOfRecirculation+1
            previousMapping = Y[i_sfc][i_sf]

    return numberOfRecirculation

numberOfRecirculation = _CalculateRecirculation (Y,N)

print("The number of requested SFCs is", N, "SFCs.")
for i in range (N):
    print ("The processing order of SFC",i,"is" ,SFlists[i][:])

print ("The available stages in switch are", switch_resources, "stages")
print("The embedding order is determined as", X, "and the required resources to embed SFs are", Resource, "stages")
#print("The mapping result between SFCs and the embedded SFs is determined as follow", Y)
for i in range (N):
    print ("Th SFs (",SFlists[i][:],") in SFC",i, "is mapped to",Y[i][:],"th embedded SFs" )
print("The number of re-circulations to support SFCs under X and Y is", numberOfRecirculation)