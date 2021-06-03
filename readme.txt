******************
ACRN Unit Tool
******************
This repo is for CPU sharing new feature test only, and it depends on acrn-unit-test github repo. We put the related binary and script under each directory. 

If you need not modify the test case code, please use the binary cpu_sharing_p1.flat directly.

If you need change source file and rebuild, steps as following:
1.The source file for cpu sharing is under acrn-unit-test/ directory,pls replace them (up to now only io.c cstart64.S cpu_sharing_p1.c regdump.h)with your acrn-unit-test master code.(https://github.com/projectacrn/acrn-unit-test/)
2.About compiling, pls refer to the wiki:https://wiki.ith.intel.com/display/OTCCWPQA/%5BHypervisor%5D+How+to+run+ACRN-UNIT-TEST

*******************
ACRN HV
*******************
To display test log in each VM screen, we need align COM port with acrn-unit-tool.
e.g.
for acrn-unit-tool, "static int serial_iobase = 0x2f8;" is in io.c
Then we need invalid COM2 in HV XML:
<legacy_vuart id="1">
       <type>VUART_LEGACY_PIO</type>
       <base>INVALID_COM_BASE</base>
       <irq>COM2_IRQ</irq>
       <target_vm_id>0</target_vm_id>
       <target_uart_id>1</target_uart_id>
</legacy_vuart>

*******************
Test Steps:
*******************
1.Confirm your test configuration, and figure out which guest VMs share the same cores? We only need test these guest VMs.
  e.g. In industry scenario, we only need test YaaG and WaaG.
2.Boot ACRN and SOS only.
3.Upload CPU sharing binary and script to SOS(cpu_sharing_p1.flat, yaag.sh waag.sh)
4.SSH to SOS, and run the following commands concurrently. 
./yaag.sh cpu_sharing_p1.flat 
./waag.sh cpu_sharing_p1.flat
5.Check the test result on each VM screen.

