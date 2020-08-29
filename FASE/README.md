# FASE Algorithm

According to the simulation environment, the system parameter is set at 'FASE_main.py'
The variables that need to be set are as follows
  - 'SFlists' variable represents the SF list in each SFC. 
  - 'N' and switch_resources variables represent the number of requested SFCs and the available resource in the switch, respectively.
  - 'SFCs' variable represents the incoming rates of SFCs
  - 'SFs' and 'Resource_Map' variables represent the SF types in the requested SFCs and the required stages to embed each SF, respectively.
  
X, Y, Resource variables represent the embedding order, mapping result, and the required number of stages to embed SFs according to X. 
From the CalculateRecirculation (Y, N) function, the required number of re-circulations to support the requested SFCs can be calculated  
