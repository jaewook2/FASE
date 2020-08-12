import numpy as np
from FASE_Algorithm import fase

#Set the needed data (i.e., the requested SFCs, the number of requested SFCs, the incoming rate, SF types in the requested SFCs, the required resource to embed each SF, and available resource in switch)
#The reqeusted SFCs list 
SFlists = (('FW', 'NAT', 'L3', 'LB'), ('LB', 'FW'), ('NAT', 'L2', 'LB', 'L3', 'FW'), ('LB','NAT'))
# The number of requested SFCs 
N=4
# The incoming rate of requested SFC
SFCs = np.array([1, 2, 3, 4]) 
# The SF types in the requested SFCs
SFs= ['LB', 'NAT', 'FW', 'L3', 'L2']
# The required stages to embed SFs 
Resource_Map = [3,2,1,1,1]
# The available resource in switch
switch_resources = 11

# Deteremine the embedding order, X and mapping result,Y by FASE algorithm 
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

# Show the determined embedding order and mapping result
print("The number of requested SFCs is", N, "SFCs.")
for i in range (N):
    print ("The processing order of SFC",i,"is" ,SFlists[i][:])

print ("The available stages in switch are", switch_resources, "stages")
print("The embedding order is determined as", X, "and the required resources to embed SFs are", Resource, "stages")
#print("The mapping result between SFCs and the embedded SFs is determined as follow", Y)
for i in range (N):
    print ("Th SFs (",SFlists[i][:],") in SFC",i, "is mapped to",Y[i][:],"th embedded SFs" )
print("The number of re-circulations to support SFCs under X and Y is", numberOfRecirculation)
