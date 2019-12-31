This  repo is for CPU sharing test privately, so we don't update them to acrn-unit-test github repo. Binary and script is under each directory. 
note:if you need not modify the test case code, you can use the binary cpu_sharing_p1.flat directly.
if need change  source file and rebuild:
step:1.The source file for cpu sharing is under acrn-unit-test/ directory,pls replace them (up to now only io.c cstart64.S cpu_sharing_p1.c)with your acrn-unit-test master code.(https://github.com/projectacrn/acrn-unit-test/)
2.pls refer:https://wiki.ith.intel.com/display/OTCCWPQA/%5BHypervisor%5D+How+to+run+ACRN-UNIT-TEST
*******************
Test Step
1.boot your device with SOS only( do not boot other UOS)
2.upload binary and script to SOS(cpu_sharing_p1.flat, vm1.sh pt_launch_vm2.sh pt_launch_vm3.sh)
3.ssh to SOS, and run ./vm1.sh cpu_sharing_p1.flat 
./pt_launch_vm2.sh cpu_sharing_p1.flat
./pt_launch_vm3.sh cpu_sharing_p1.flat

the test result will display on your screen.

