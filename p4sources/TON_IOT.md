# Notes on the ToN-IoT p4 implementation

## Programs and clusters
We have 4 clusters producing outputs as defined in the following table :
| Cluster ID | Output classes IDs |
|-|-|
|CL0|1,(2)|
|CL1|1,2,3,(4)|
|CL2|1,(2)|
|CL3|1,2,(3)|

The sequencing process has given the following order : `CL1 -> CL3 -> CL2 -> CL0`

### Tofino implementation
In the tofino implementation we have :
- The class in parenthesis respresent an unknown class for the model
- For models downstream the classes are offset by the number of classes in
    the previous models. This mean in practice we have :
    | Cluster ID | Output classes IDs |
    |-|-|
    |CL0|7,(8)|
    |CL1|1,2,3,(4)|
    |CL2|6,(7)|
    |CL3|4,5,(6)|

### Bmv2 implementation
In the Bmv2 implementation :
- We represent an unknown class for a model with the constant UKNOWN\_CLASS which coincide in every model
- As in the tofino implementation we offset the classes of downstream switches.
    Combining this with what is stated above we have :
    | Cluster ID | Output classes IDs |
    |-|-|
    |CL0|7,(0)|
    |CL1|1,2,3,(0)|
    |CL2|6,(0)|
    |CL3|4,5,(0)|

