Things you'll need

*	make and gcc (from cygwin and/or linux) 
*	eid_root_key (root key, obtained from flatz's dumper)
*	eid 		 (eEID, renamed to eid, no extension)
*	sectors		 (hdd image, starting from sector 0, no extension)
* 	to place eid_root_key and sectors on data
*	to place eid on eid
* 	to leave the syscon folder as is

How to (EID/HDD/SYSCON)

1. Compile the program
2. Run the apropriate option 
by selecting the correspondent number

for HDD:

if you DO NOT have VFLASH then please 
comment out the code under line 39 and 79 (decrypt or encrypt)
and compile the program again