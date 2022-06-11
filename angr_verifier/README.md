# Verification of the code using angr
This folder contains the code that was used to verify the modified Fortanix EDP entry code.
The source code of the Guardian paper was used as the basis of this verifier, but serious extensions and modifications have been done.

## Instructions to run the code
This code can be run by using the following commands.
A sample binary (containing a binary built with the latest entry code), called 'app', has been included to be able to run the analyses mentioned below.
### Simple analysis
This will check that the entry and exit assembly code blocks meet some security and correctness requirements
```
python3 main.py -p <insert_path_here> 
```

### Full analysis
This will try to run the whole entry code, but excluded the entry() function.
It adds additional checks compared to the code above.
Most importantly for the purpose of this thesis, it will allow the user to verify the "exit states".
```
python3 main.py -f True -p <insert_path_here> 
```

However, it is often more useful to run the code using IPython.
This way the resulting states can be analysed.
An example of some possible analyses is given below:

```
%run "main.py" -f True -p <insert_path_here> 

# See all functions that have been called to get to this specific state
# By changing the index, other states can be checked.
guard.simgr.exited[0].enclave.print_trace()  

# See an overview of the contents of the register at this specific state
# By changing the index, other states can be checked.
guard.angr_project.print_out_register_values(guard.simgr.exited[0])  

# Note: if there are "active" / "violated" / "killed" states, then the user should change "exited" to the keyword that's mentioned at the end of the analysis.
```
