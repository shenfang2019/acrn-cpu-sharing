#include "processor.h"
#include "libcflat.h"
#include "vm.h"
#include "alloc_page.h"
#include "smp.h"
#include "desc.h"
#include "isr.h"
#include "apic.h"
#include "alloc.h"
#include "x86/asm/io.h"
//#include "vmx.h"
#include "regdump.h"

/**/
/********************************************/
/*          timer calibration  */
/********************************************/
uint64_t tsc_hz;
uint64_t apic_timer_hz;
uint64_t cpu_hz;
uint64_t bus_hz;

static void tsc_calibrate(void)
{
	u32 eax_denominator, ebx_numerator, ecx_crystal_hz, reserved;
	u32 eax_base_mhz = 0, ebx_max_mhz = 0, ecx_bus_mhz = 0, edx;

	__asm volatile("cpuid"
				   : "=a"(eax_denominator), "=b"(ebx_numerator), "=c"(ecx_crystal_hz), "=d"(reserved)
				   : "0" (0x15), "2" (0)
				   : "memory");

	printf("crystal_hz:%u\n\r", ecx_crystal_hz);

	if (ecx_crystal_hz != 0) {
		tsc_hz = ((uint64_t) ecx_crystal_hz *
				  ebx_numerator) / eax_denominator;
		apic_timer_hz = ecx_crystal_hz;
	} else {

		__asm volatile("cpuid"
					   : "=a"(eax_base_mhz), "=b"(ebx_max_mhz), "=c"(ecx_bus_mhz), "=d"(edx)
					   : "0" (0x16), "2" (0)
					   : "memory");

		tsc_hz = (uint64_t) eax_base_mhz * 1000000U;
		apic_timer_hz = tsc_hz * eax_denominator / ebx_numerator;
	}

	cpu_hz = eax_base_mhz * 1000000U;
	bus_hz = ecx_bus_mhz * 1000000U;
	printf("apic_timer_hz: %lu\n", apic_timer_hz);
	printf("tsc_hz: %lu\n", tsc_hz);
	printf("cpu_hz: %lu\n", cpu_hz);
	printf("bus_hz: %lu\n", bus_hz);

	/* apic_timer_hz: 23863636; 16C 2154H
	 * tsc_hz: 2100000000
	 * cpu_hz: 2100000000
	 * bus_hz: 100000000

	 */
}

#define TSC_DEADLINE_TIMER_VECTOR 0xef
bool volatile tdt_isr_flag = false;
volatile u64 start_dtimer_cnt = 0;
volatile u64 process_dtimer_cnt = 0;
static void tsc_deadline_timer_isr(isr_regs_t *regs)
{
	tdt_isr_flag = true;
	process_dtimer_cnt++;
	eoi();
}

/*simple sleep for xxx ns*/
static void sleep_ns(u64 ns)
{
#define TSC_TICKS_PER_NS (tsc_hz / 1000000000)
	u64 tsc;

	tsc = rdtsc();
	while (1) {
		asm volatile("pause");
		if ((tsc + ns * TSC_TICKS_PER_NS) < rdtsc()) {
			break;
		}
	}
}
//#define HV_X64_MSR_TIME_REF_COUNT	0x40000020U
//#define HV_X64_MSR_REFERENCE_TSC	0x40000021U
//#define HV_X64_MSR_TSC_FREQUENCY	0x40000022U

static bool start_dtimer(u64 ticks_interval)
{
	u64 tsc;
	bool ret = true;

	start_dtimer_cnt++;
	tsc = rdmsr(MSR_IA32_TSC);
	tsc += ticks_interval;
//	ticks1 = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
	wrmsr(MSR_IA32_TSCDEADLINE, tsc);
	return ret;
}

static int enable_tsc_deadline_timer(void)
{
	u32 lvtt;

	if (cpuid(1).c & (1 << 24)) {
		lvtt = APIC_LVT_TIMER_TSCDEADLINE | TSC_DEADLINE_TIMER_VECTOR;
		apic_write(APIC_LVTT, lvtt);
		return 1;
	} else {
		return 0;
	}
}
static bool init_rtsc_dtimer(void)
{
	if (enable_tsc_deadline_timer()) {
		handle_irq(TSC_DEADLINE_TIMER_VECTOR, tsc_deadline_timer_isr);
		irq_enable();
		return true;
	}
	return false;
}

#define RTC_INDEX_REG  0x70
#define RTC_TARGET_REG 0x71

#define SECOND_INDEX       0x0
#define SECOND_ALARM_INDEX 0x1
#define MINUTE_INDEX       0x2
#define MINUTE_ALARM_INDEX 0x3
#define HOUR_INDEX         0x4
#define HOUR_ALARM_INDEX   0x5
#define DAY_OF_WEEK_INDEX  0x6
#define DAY_OF_MONTH_INDEX 0x7
#define MONTH_INDEX        0x8
#define YEAR_INDEX         0x9
#define A_INDEX            0xA
#define B_INDEX            0xB
#define C_INDEX            0xC

#define B_DEFAULT_VALUE 0x6

static void pio_test()
{
#if 1
	u8 reg8_value, reg8_value_prev;
	reg8_value = inb(RTC_INDEX_REG);

	outb(YEAR_INDEX, RTC_INDEX_REG);
	reg8_value = inb(RTC_TARGET_REG);

	outb(YEAR_INDEX, 0x72);
	reg8_value = inb(0x73);
	reg8_value_prev = reg8_value;//make GCC Happy

	outb(B_INDEX, RTC_INDEX_REG);
	reg8_value_prev = inb(RTC_TARGET_REG);
	outb(0xFF, RTC_TARGET_REG);
	reg8_value = inb(RTC_TARGET_REG);

	reg8_value = reg8_value_prev;//make GCC Happy
	//printf("tdt_isr=%d cnt=%lx\n\r",tdt_isr,process_dtimer_cnt);
#endif
}
#if 1
/*
*
*0:sucessfully
*other: error code:
*/
#define TEST_OK 0x0u
#define FPU_TEST_FAILED 0x1u
#define MMX_TEST_FAILED 0x2u
#define SSE_TEST_FAILED 0x3u
#define AVX_TEST_FAILED 0x4u
#define GP_INS_TEST_FAILED 0x5u
#define EXCEPTION_GP_FAILED 0x6u
#define EXCEPTION_UD_FAILED 0x7u
#define XSAVE_AREA_CHECK_FAILED 0x8u
#define TEST_FAILED	0xfu
int test_gp_ins()
{
	int ret = TEST_OK;
	unsigned long rax;
	const unsigned long in_rax = 0x1234567890abcdeful;

	asm("nop\n\t" : "=a" (rax) : "0" (in_rax));
	if (rax != in_rax) {
		ret = GP_INS_TEST_FAILED;
	}
	return ret;
}
int test_fpu()
{
	float f32fp = 1.01f;
	float f_st2 = 2.02f;
	float f_test_result = 0.0f;
	int	ret = TEST_OK;
	ulong cr0 = read_cr0();

	write_cr0(cr0 & ~0xe); /*MP, EM, TS */

	asm volatile("fninit");
	asm volatile("FWAIT");
	asm volatile("fld %0" : : "m"(f32fp) : "memory");
	asm volatile("fld %0" : : "m"(f_st2) : "memory");
	asm volatile("fadd %%st(1), %%st(0)" : : :);
	asm volatile("fst %0" : "=m"(f_test_result):  : "memory");

	if (f_test_result != (f32fp + f_st2)) {
		ret = FPU_TEST_FAILED;
	}

	//write cr0 back
	write_cr0(cr0);
	return ret;
}


int  test_mmx_mov(void)
{
	/*
	 * Initialize FPU without checking for pending unmasked
	 * floating-point exceptions.
	 */
	//asm volatile("fninit");
	u64 u64_data = 0x0102030405060708ULL;
	u64 test_result;
	asm volatile("movq %0, %%mm0" : : "m"(u64_data) : "memory");
	asm volatile("movq %%mm0, %0" : "=m"(test_result):  : "memory");

	if (test_result != u64_data) {
		report("CPU sharing MMX movq test failed", 0);
		return MMX_TEST_FAILED;
	}

	u32 u32_test_result = 0;
	u32 u32_data = 0x01020304UL;
	asm volatile("movd %0, %%mm1" : : "m"(u32_data) : "memory");
	asm volatile("movd %%mm1, %0" : "=m"(u32_test_result): : "memory");
	if (u32_test_result != u32_data) {
		report("CPU sharing MMX movd test", 0);
		return MMX_TEST_FAILED;
	}
	return 0;
}

int test_mmx_add(void)
{
	u64 u64_data = 0x0101010101010101ULL;
	u64 test_result = 0;

	asm volatile("movq %0, %%mm2" : : "m"(u64_data) : "memory");
	asm volatile("paddq %0, %%mm2" : : "m"(u64_data): "memory");
	asm volatile("movq %%mm2, %0" : "=m"(test_result):  : "memory");

	if (test_result != u64_data + u64_data) {
		report("CPU sharing MMX add test", 0);
		return MMX_TEST_FAILED;
	}

	return TEST_OK;
}

int   test_mmx_compare(void)
{
	u64 u64_data1 = 0x0101010101010101ULL;
	u64 u64_data2 = 0x0201010102010101ULL;
	u64 test_result = 0x11;
	int ret = TEST_OK;

	asm volatile("movq %0, %%mm3" : : "m"(u64_data1) : "memory");
	/* Compare packed doublewords in mm/m64 andmm for equality */
	asm volatile("pcmpeqd %0, %%mm3" : : "m"(u64_data2): "memory");
	asm volatile("movq %%mm3, %0" : "=m"(test_result):  : "memory");
	if (test_result != 0) {
		ret = MMX_TEST_FAILED;
	}

	u64_data2 = u64_data1;
	asm volatile("movq %0, %%mm3" : : "m"(u64_data1) : "memory");
	/* Compare packed doublewords in mm/m64 andmm for equality */
	asm volatile("pcmpeqd %0, %%mm3" : : "m"(u64_data2): "memory");
	asm volatile("movq %%mm3, %0" : "=m"(test_result):  : "memory");
	if (test_result != 0xffffffffffffffffULL) {
		ret = MMX_TEST_FAILED;
	}

	if (ret != TEST_OK) {
		report("CPU sharing MMX compare test", 0);
	}

	return ret;

}

int test_mmx()
{
	ulong cr0 = read_cr0();

	write_cr0(cr0 & ~0xe); /*MP, EM, TS */
	asm volatile("emms");
	if ((test_mmx_mov() != TEST_OK)		\
		|| (test_mmx_add() != TEST_OK)	\
		|| (test_mmx_compare() != TEST_OK)) {
		write_cr0(cr0);
		return MMX_TEST_FAILED;
	}
#if 0
	v = 0x0102030405060708ULL;
	asm("movq %1, %0" : "=m"(*mem) : "y"(v));
	report("movq (mmx, read)", v == *mem);
	*mem = 0x8070605040302010ull;
	asm("movq %1, %0" : "=y"(v) : "m"(*mem));
	report("movq (mmx, write)", v == *mem);
#endif
	//recover cr0
	write_cr0(cr0);
	return TEST_OK;
}
#if 0
int test_avx()
{

}
int test_avx2()
{

}
#endif
#endif



#if 0
struct invept_desc {
	uint64_t eptp;
	uint64_t res;
};

/*
*
*SDM 30.3 INVETP
*
*
*/

/* If the INVEPT type is 1, the logical processor invalidates all mappings associated
with bits 51:12 of the EPT pointer (EPTP) specified in the INVEPT descriptor. It may invalidate other mappings
as well.
	If the INVEPT type is 2, the logical processor invalidates mappings associated with all
EPTPs

127 <----->			64 	 |	63 	<--->		0
Reserved (must be zero)  |	EPT pointer (EPTP)

*/
u64 *vmxon_region;
void make_gcc_happy()
{

	vmx_on();
	vmx_off();
}
void invalid_ept(void)
{
	struct invept_desc desc = {0};
	u64 type = 2U;
	asm volatile("invept %0, %1\n" :
				 : "m" (desc), "r" (type)
				 : "memory");
}

void update_eoi()
{
	vmcs_write(EOI_EXIT_BITMAP3, 0x0);
}
#endif
/*
*
*
*TC_CPU_sharing_rr_scheduler_001
*run "hlt" and "pause" instruction
*/
#define mem_size (4*1024)
#define TICKS_PER_SEC 	tsc_hz
#define TICKS_PER_MS	tsc_hz/1000
void cpu_sharing_test001(int *p, u64 ticks)
{
	bool test_end = false;

	printf("start TC_CPU_sharing_rr_scheduler_001:run hlt and pause instruction\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);

	start_dtimer(ticks);//pls do not end this case untile this timer experi
	while (1) {
		for (int i = 0; i < mem_size / 4; i++) {
			*(p + i) = i;
			asm volatile("hlt");
			asm volatile ("pause");
			asm volatile("WBINVD");
			sleep_ns(100);
			if (tdt_isr_flag) {
				test_end = true;
				tdt_isr_flag = false;
				break;
			}
		}

		if (test_end) {
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_001\n\r", 1);
}

/*
*TC_CPU_sharing_rr_scheduler_002
*emulate virtual interrupt
*/
static volatile int ipi_count = 0;

static void self_ipi_isr(isr_regs_t *regs)
{
	ipi_count = 1;
	eoi();
}
static int test_self_ipi(void)
{
	int ret = TEST_OK;

	//apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED | 0xf1,
	//		   0);

	/*send ipi to apic_id=0 of cpu*/
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_FIXED | 0xf1 | 0, 0);
	asm volatile ("nop");
	asm volatile ("nop");

	if (ipi_count == 0) {
		ret = TEST_FAILED;
	}

	ipi_count = 0;
	return ret;
}
void cpu_sharing_test002(u64 ticks)
{
	bool ret = true;

	printf("start TC_CPU_sharing_rr_scheduler_002:emulate virtual interrupt\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);

	handle_irq(0xf1, self_ipi_isr);
	irq_enable();
	start_dtimer(ticks);

	while (1) {
		if (test_self_ipi() != TEST_OK) {
			ret = false;
		}

		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
		sleep_ns(1000);
	}
	report("TC_CPU_sharing_rr_scheduler_002\n\r", ret);
}
/*
*
*
*TC_CPU_sharing_rr_scheduler_003	trigger exception
*
*
*/
static int test_ud2()
{
	asm volatile(ASM_TRY("1f")
				 "ud2 \n\t"
				 "1:" :);
	return exception_vector();
}

static int test_gp()
{
#if 0
	/*write cr4 to gernate #GP,this will cause vmexit.When TSC timer interrupt,sometimes,
	in Interrupt handler, To send EOI will occur #GP
	*/
	unsigned long tmp;

	asm volatile("mov $0xffffffff, %0 \n\t"
				 ASM_TRY("1f")
				 "mov %0, %%cr4\n\t"
				 "1:"
				 : "=a"(tmp));
	return exception_vector();
#else
	ulong *addr = (ulong*)0xfe000000006000u;
	asm volatile(ASM_TRY("1f")
				 "adc  $0x32, %0 \n\t"
				 "1:"::"m"(*addr));
	return exception_vector();
#endif
}

int exception_test()
{
	int r = TEST_OK;

	if (test_gp() != GP_VECTOR) {
		r = EXCEPTION_GP_FAILED;
	}

	if (test_ud2() != UD_VECTOR) {
		r = EXCEPTION_UD_FAILED;
	}
	return r;
}

void cpu_sharing_test003(int *p, u64 ticks)
{
	bool test_end = false;
	int ret, err = 0;
	bool result = true;

	printf("start TC_CPU_sharing_rr_scheduler_003: trigger exception\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);
	start_dtimer(ticks);

	while (1) {
		for (int i = 0; i < mem_size / 4; i++) {
			*(p + i) = i;
			ret = exception_test();
			if (ret != TEST_OK) {
				err = ret;
				result = false;
			}
			sleep_ns(100);
			if (tdt_isr_flag) {
				test_end = true;
				tdt_isr_flag = false;
				break;
			}
		}

		if (test_end) {
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_003 %d\n\r", result, err);
}
/*
*
*
*TC_CPU_sharing_rr_scheduler_004:send SIPI to AP from BP
*
*This case need two cpu to test.
*when system bootup,the BSP cpu will send SIPI to APs to start them.
*So, in Multiple CPUs System, if other APs startup normally, this case has been tested
*/
void cpu_sharing_test004(int *p, u64 ticks)
{


	report("TC_CPU_sharing_rr_scheduler_004\n\r", 1);
}

/*
*
*TC_CPU_sharing_rr_scheduler_005	write/read PIO per 2ms
*
*/
void cpu_sharing_test005( u64 ticks)
{

	printf("start TC_CPU_sharing_rr_scheduler_005:write/read PIO per 2ms\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);

	start_dtimer(ticks);
	while (1) {
		pio_test();
		sleep_ns(2 * 1000);
		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_005\n\r", 1);
}

/*
*
*TC_CPU_sharing_rr_scheduler_006	write/read PIO per 100ms
*
*/
void cpu_sharing_test006(u64 ticks)
{

	printf("start TC_CPU_sharing_rr_scheduler_006:write/read PIO per 100ms\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);

	start_dtimer(ticks);
	while (1) {
		pio_test();
		sleep_ns(100 * 1000);
		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_006 \n\r", 1);
}

typedef unsigned __attribute__((vector_size(32))) avx256;
typedef union {
	avx256 avx;
	float avx_m[8];
	u32 avx_u[8];
} avx_union;
/*
*
*1: supported
*0:not support
*/
static inline bool check_avx_supported()
{
	//CPUID.(EAX=01H,ECX=0):ECX[bit 28]
	return (cpuid_indexed(1, 0).c & (1 << 28));

}
/*
*
*
*/
bool test_avx_vsqrtpd(void)
{
//	avx_union m256;
	//float tmp = 45.67;
	__attribute__ ((aligned(64))) avx_union avx_temp, avx_temp1, avx_temp2, avx_result;

	avx_temp.avx_m[0] = 1111.11;
	avx_temp.avx_m[1] = 2222.22;
	avx_temp.avx_m[2] = 3333.33;
	avx_temp.avx_m[3] = 4444.44;
	avx_temp.avx_m[4] = 5555.55;
	avx_temp.avx_m[5] = 6666.66;
	avx_temp.avx_m[6] = 7777.77;
	avx_temp.avx_m[7] = 8888.88;

	avx_temp1.avx_m[0] = 1789.29;//square root is 42.3
	avx_temp1.avx_m[1] = 600.25;//24.5^2
	avx_temp2.avx_m[0] = 42.3;
	avx_temp2.avx_m[1] = 24.5;
	avx_temp1.avx_m[2] = avx_temp2.avx_m[2] = 0.0;
	avx_temp1.avx_m[3] = avx_temp2.avx_m[3] = 0.0;
	avx_temp1.avx_m[4] = avx_temp2.avx_m[4] = 0.0;
	avx_temp1.avx_m[5] = avx_temp2.avx_m[5] = 0.0;
	avx_temp1.avx_m[6] = avx_temp2.avx_m[6] = 0.0;
	avx_temp1.avx_m[7] = avx_temp2.avx_m[7] = 0.0;
	//u32 val = 0xffff;
	//u32 reg_val;

	//asm volatile("stmxcsr %0" : "=m"(reg_val));
	//printf("reg_val:%x\n\r",reg_val);
	//asm volatile("ldmxcsr %0" : : "m"(val));
	/*vsqrtpd:get Square Roots value of first OP to ymm1 register*/
	asm volatile(
		"vmovaps %[avx_temp], %%ymm1 \n\t"
		"vsqrtps %[avx_temp1], %%ymm2 \n\t"
		"vcmpps $0,%[avx_temp2], %%ymm2, %%ymm3 \n\t"
		"vmovaps %%ymm3, %[result] \n\t"
		:[result]"=m"(avx_result)
		:[avx_temp]"m"(avx_temp), [avx_temp1]"m"(avx_temp1), [avx_temp2]"m"(avx_temp2)
		:"memory");

	for (int i = 0; i < 8; i++) {
		if (avx_result.avx_u[i] != 0xffffffffU) {
			//printf("0x%x", avx_result.avx_u[i]);
			return false;
		}
	}

	return true;
}
bool test_avx_vaddps()
{
	__attribute__ ((aligned(64))) avx_union avx_temp, avx_temp1, avx_temp2, avx_result;

	avx_temp.avx_m[0] = 1111.11;
	avx_temp.avx_m[1] = 2222.22;
	avx_temp.avx_m[2] = 3333.33;
	avx_temp.avx_m[3] = 4444.44;
	avx_temp.avx_m[4] = 5555.55;
	avx_temp.avx_m[5] = 6666.66;
	avx_temp.avx_m[6] = 7777.77;
	avx_temp.avx_m[7] = 8888.88;

	avx_temp1.avx_m[0] = 1234.56;
	avx_temp1.avx_m[1] = avx_temp1.avx_m[2] = avx_temp1.avx_m[3] = 0.0;
	avx_temp1.avx_m[4] = avx_temp1.avx_m[5] = avx_temp1.avx_m[6] = 0.0;
	avx_temp1.avx_m[7] = 0.0;

	avx_temp2.avx_m[0] = 2345.67; //avx_temp2 = avx_temp + avx_temp1
	avx_temp2.avx_m[1] = 2222.22;
	avx_temp2.avx_m[2] = 3333.33;
	avx_temp2.avx_m[3] = 4444.44;
	avx_temp2.avx_m[4] = 5555.55;
	avx_temp2.avx_m[5] = 6666.66;
	avx_temp2.avx_m[6] = 7777.77;
	avx_temp2.avx_m[7] = 8888.88;

	asm volatile (
		"vmovaps %1, %%ymm2 \n\t"
		"vaddps %2, %%ymm2, %%ymm1 \n\t"
		"vcmpps $0, %3, %%ymm1, %%ymm3 \n\t"
		"vmovaps %%ymm3, %0"
		:"=m"(avx_result)
		:"m"(avx_temp), "m"(avx_temp1), "m"(avx_temp2)
		:"memory");

	for (int i = 0; i < 8; i++) {
		if (avx_result.avx_u[i] != 0xffffffffU) {
			return false;
		}
	}

	return true;
}
int test_avx()
{
	int error_code = 0;

	if (test_avx_vsqrtpd() != true) {
		error_code = 1;
		goto TEST_AVX_FAILED;
	}

	if (test_avx_vaddps() != true) {
		error_code = 2;
		goto TEST_AVX_FAILED;
	}

	//if (avx
	return TEST_OK;

TEST_AVX_FAILED:
	printf("CPU Sharing  in test_avx() error code:%d", error_code);
	return AVX_TEST_FAILED;
}
/*
*
*TC_CPU_sharing_rr_scheduler_007	execute AVX instructions
*
*/
void cpu_sharing_test007(u64 ticks)
{
	bool ret = true;
	ulong cr4;

	printf("start TC_CPU_sharing_rr_scheduler_007:execute AVX instructions\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);
	cr4 = read_cr4();
	write_cr4(cr4 | (1 << 18)); /* osxsave */
	if (!check_avx_supported()) {
		report_skip("Not support avx instruction,cpu_sharing_test008");
		write_cr4(cr4);
		return;
	}

	start_dtimer(ticks);
	while (1) {
		if (test_avx() != TEST_OK) {
			ret = false;
		}
		sleep_ns(1000);
		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}

	write_cr4(cr4);
	report("TC_CPU_sharing_rr_scheduler_007\n\r", ret);
}
typedef unsigned __attribute__((vector_size(16))) sse128;
typedef union {
	sse128 sse;
	unsigned u[4];
} sse_union;
static bool sseeq(sse_union *v1, sse_union *v2)
{
	bool ok = true;
	int i;

	for (i = 0; i < 4; ++i) {
		ok &= v1->u[i] == v2->u[i];
	}

	return ok;
}
__attribute__((target("sse"))) int test_sse(sse_union *mem)
{
	sse_union v;
	int error_code;

	write_cr0(read_cr0() & ~6); /* EM, TS */
	write_cr4(read_cr4() | 0x200); /* OSFXSR */
	v.u[0] = 1;
	v.u[1] = 2;
	v.u[2] = 3;
	v.u[3] = 4;
	asm("movdqu %1, %0" : "=m"(*mem) : "x"(v.sse));
	if (sseeq(&v, mem) != true) {
		error_code = 1;
		goto TEST_SSE_FAILED;
	}
	mem->u[0] = 5;
	mem->u[1] = 6;
	mem->u[2] = 7;
	mem->u[3] = 8;
	asm("movdqu %1, %0" : "=x"(v.sse) : "m"(*mem));
	if (sseeq(mem, &v) != true) {
		error_code = 2;
		goto TEST_SSE_FAILED;
	}

	v.u[0] = 1;
	v.u[1] = 2;
	v.u[2] = 3;
	v.u[3] = 4;
	asm("movaps %1, %0" : "=m"(*mem) : "x"(v.sse));
	if (sseeq(mem, &v) != true) {
		error_code = 3;
		goto TEST_SSE_FAILED;
	}
	mem->u[0] = 5;
	mem->u[1] = 6;
	mem->u[2] = 7;
	mem->u[3] = 8;
	asm("movaps %1, %0" : "=x"(v.sse) : "m"(*mem));
	if (sseeq(mem, &v) != true) {
		error_code = 4;
		goto TEST_SSE_FAILED;
	}

	v.u[0] = 1;
	v.u[1] = 2;
	v.u[2] = 3;
	v.u[3] = 4;
	asm("movapd %1, %0" : "=m"(*mem) : "x"(v.sse));
	if (sseeq(mem, &v) != true) {
		error_code = 5;
		goto TEST_SSE_FAILED;
	}
	mem->u[0] = 5;
	mem->u[1] = 6;
	mem->u[2] = 7;
	mem->u[3] = 8;
	asm("movapd %1, %0" : "=x"(v.sse) : "m"(*mem));
	if (sseeq(mem, &v) != true) {
		error_code = 6;
		goto TEST_SSE_FAILED;
	}

	return TEST_OK;

TEST_SSE_FAILED:
	printf("CPU Sharing  in test_sse() error code:%d", error_code);
	return SSE_TEST_FAILED;
}

/*
*
*
*TC_CPU_sharing_rr_scheduler_008	execute SSE instructions
*Assume Platform support SSE instructions by default,we needn't check.
*/
void cpu_sharing_test008(u64 ticks)
{
	bool ret = true;
	sse_union *mem;

	printf("start TC_CPU_sharing_rr_scheduler_008:excute SSE instruction\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);

	mem = (sse_union *)malloc(sizeof(sse_union));
	if (mem == NULL) {

		report_skip("no enough mem,cpu_sharing_test008 ");
		return;
	}

	start_dtimer(ticks);
	while (1) {
		if (test_sse(mem) != 0) {
			ret = false;
		}

		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}
	free(mem);
	report("TC_CPU_sharing_rr_scheduler_008\n\r", ret);
}

/*
*
*TC_CPU_sharing_rr_scheduler_009	execute MMX instructions
*
*/
void cpu_sharing_test009(u64 ticks)
{
	bool ret = true;

	printf("start TC_CPU_sharing_rr_scheduler_009:execute MMX instructions\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);

	start_dtimer(ticks);
	while (1) {
		if (test_mmx() != TEST_OK) {
			ret = false;
		}

		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_009\n\r", ret);
}
/*
*
*TC_CPU_sharing_rr_scheduler_010	execute FPU instructions
*
*/
void cpu_sharing_test010(u64 ticks)
{
	bool ret = true;

	printf("start TC_CPU_sharing_rr_scheduler_010:execute FPU instructions\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);

	start_dtimer(ticks);
	while (1) {
		if (test_fpu() != TEST_OK) {
			ret = false;
		}

		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_010\n\r", ret);
}
/*
*
*TC_CPU_sharing_rr_scheduler_011	execute GP instructions(general purpose instructions)
*
*/
void cpu_sharing_test011(u64 ticks)
{
	bool ret = true;

	printf("start TC_CPU_sharing_rr_scheduler_011:execute general instructions\n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);

	start_dtimer(ticks);
	while (1) {
		if (test_gp_ins() != TEST_OK) {
			ret = false;
		}

		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_011\n\r", ret);
}

static int xsave_setbv(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;
#if 0
	asm volatile(ASM_TRY("1f")
				 "xsetbv\n\t" /* xsetbv */
				 "1:"
				 : : "a" (eax), "d" (edx), "c" (index));
	return exception_vector();
#else
	asm volatile("xsetbv\n" /* xsetbv */
				 : : "a" (eax), "d" (edx), "c" (index));
	return 0;
#endif
}
static int xsave_getbv(u32 index, u64 *result)
{
	u32 eax, edx;

	asm volatile("xgetbv\n" /* xgetbv */
				 : "=a" (eax), "=d" (edx)
				 : "c" (index));
	*result = eax + ((u64)edx << 32);
	return 0;
}


static int xsave_instruction(u64 *xsave_addr, u64 xcr0)
{
	u32 eax = xcr0;
	u32 edx = xcr0 >> 32;

#if 0
	asm volatile(ASM_TRY("1f")
				 "xsave %[addr]\n\t"
				 "1:"
				 : : [addr]"m"(xsave_array), "a"(eax), "d"(edx)
				 : "memory");
	return exception_vector();
#else
	asm volatile(
		"xsave %[addr]\n"
		: : [addr]"m"(*xsave_addr), "a"(eax), "d"(edx)
		: "memory");
	return 0;
#endif
}
static u64 get_supported_xcr0(void)
{
	struct cpuid r;
	r = cpuid_indexed(0xd, 0);
	return r.a + ((u64)r.d << 32);
}

/*------------------------------------------------------*
*   dump xsave reg to ptr
*   TURE:sucess
*   FALSE:failed
*-------------------------------------------------------*/
bool xsave_reg_dump(void *ptr)
{
//    void *mem;
	uintptr_t p_align;
//	void *fpu_sse,*ymm_ptr,*bnd_ptr;
//    xsave_dump_t * xsave_reg;
	size_t alignment;
	u64 supported_xcr0;
	u64 xcr0, cr4;

	assert(ptr);
	cr4 = read_cr4();
	/*enable xsave feature set by set cr4.18*/
	write_cr4(cr4 | (1 << 18)); /* osxsave */
	supported_xcr0 = get_supported_xcr0();
	/*enable all xsave bitmap 0x3--we support until now!!
	MPX component is hidden,so we add it ?
	*/
	xsave_getbv(0, &xcr0);

	//printf("support xcr0:%lx xcr0:%lx\n\r",supported_xcr0,xcr0);

	xsave_setbv(0, supported_xcr0);

	/*allocate 2K memory to save xsave feature*/
//    mem = malloc(1 << 11);
//    assert(mem);
//    memset(mem, 0, (1 << 11));
	/*mem base address must be 64 bytes aligned to excute "xsave". vol1 13.4 in SDM*/
	alignment = 64;
	p_align = (uintptr_t) ptr;
	p_align = ALIGN(p_align, alignment);
	if (xsave_instruction((void*)p_align, supported_xcr0) != 0) {
		/*set origin xcr0 back*/
		//xsave_setbv(0, xcr0);
		write_cr4(cr4);
		return false;
	}
#if 0
	/*copy to dump buffer*/
	xsave_reg = (xsave_dump_t *)ptr;
	xsave = (xsave_area_t*)p_align;
	fpu_sse = (void*) xsave;
	memcpy((void*) & (xsave_reg->fpu_sse), fpu_sse, sizeof(fpu_sse_t));
	ymm_ptr = (void*) &xsave->ymm[0];
	memcpy((void*) & (xsave_reg->ymm), ymm_ptr, sizeof(xsave_avx_t));
	bnd_ptr = (void*) &xsave->bndregs;
	memcpy((void*) & (xsave_reg->bndregs), bnd_ptr, \
		   sizeof(xsave_bndreg_t) + sizeof(xsave_bndcsr_t));
	free(mem);
#endif
	/*set origin xcr0 back*/
	//xsave_setbv(0, xcr0);
	write_cr4(cr4);
	return true;
}


int check_xsave_area()
{
	int ret = TEST_OK;
	xsave_area_t *xsave_ptr1, *xsave_ptr2;
	/*
	*dump xsave register
	*/
	xsave_ptr1 = (xsave_area_t *)malloc(sizeof(xsave_area_t));
	assert(xsave_ptr1);
	memset(xsave_ptr1, 0x0, sizeof(xsave_area_t));
	if (xsave_reg_dump((void*)xsave_ptr1) != true) {
		printf("xsave_reg_dump::xsave_reg_dump return err\n\r");
		ret = XSAVE_AREA_CHECK_FAILED;
	}

	/*sleep a while time to check xsave later*/
	sleep_ns(1000);

	xsave_ptr2 = (xsave_area_t *)malloc(sizeof(xsave_area_t));
	assert(xsave_ptr2);
	memset(xsave_ptr2, 0x0, sizeof(xsave_area_t));
	if (xsave_reg_dump((void*)xsave_ptr2) != true) {
		printf("xsave_reg_dump::xsave_reg_dump return err\n\r");
		ret = XSAVE_AREA_CHECK_FAILED;
	}
	if (memcmp(xsave_ptr1, xsave_ptr2, sizeof(xsave_area_t)) != 0) {
		ret = XSAVE_AREA_CHECK_FAILED;
	}

	free(xsave_ptr1);
	free(xsave_ptr2);

	return ret;
}
/*
*
*TC_CPU_sharing_rr_scheduler_012	check  xSave area during vcpu scheduling
*
*/
void cpu_sharing_test012(u64 ticks)
{
	bool ret = true;

	printf("start TC_CPU_sharing_rr_scheduler_012:check xSave area \n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);
#if 0
	/*
	*dump xsave register
	*/
	xsave_ptr1 = (xsave_dump_t *)malloc(sizeof(xsave_dump_t));
	assert(xsave_ptr1);
	memset(xsave_ptr1, 0x0, sizeof(xsave_dump_t));
	ret = xsave_reg_dump((void*)xsave_ptr1);
	if (ret != true) {
		printf("xsave_reg_dump::xsave_reg_dump return err\n\r");
		return -1;
	}
#endif
	start_dtimer(ticks);
	while (1) {
		if (check_xsave_area() != TEST_OK) {
			ret = false;
		}

		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_012\n\r", ret);
}
/*
*
*TC_CPU_sharing_rr_scheduler_013	matrix of instructions and schduler trigger
*
*/
void cpu_sharing_test013(u64 ticks)
{
	bool ret = true;

	printf("start TC_CPU_sharing_rr_scheduler_013:matrix of instructions and schduler trigger \n\r");
	printf("This case will take %lu minutes,pls wait ... ...\n\r", ticks / TICKS_PER_SEC / 60);
#if 0
	/*
	*dump xsave register
	*/
	xsave_ptr1 = (xsave_dump_t *)malloc(sizeof(xsave_dump_t));
	assert(xsave_ptr1);
	memset(xsave_ptr1, 0x0, sizeof(xsave_dump_t));
	ret = xsave_reg_dump((void*)xsave_ptr1);
	if (ret != true) {
		printf("xsave_reg_dump::xsave_reg_dump return err\n\r");
		return -1;
	}
#endif
	start_dtimer(ticks);
	while (1) {
		asm volatile("hlt");
		asm volatile ("pause");
		asm volatile("WBINVD");

		if (test_self_ipi() != TEST_OK) {
			printf("test_self_ipi failed in cpu_sharing_test013 \n\r");
			ret = false;
		}

		if (exception_test() != TEST_OK) {
			printf("exception test failed in cpu_sharing_test013 \n\r");
			ret = false;
		}

		pio_test();

		sse_union mem;
		if (test_sse(&mem) != TEST_OK) {
			printf("sse test failed in cpu_sharing_test013 \n\r");
			ret = false;
		}

		if (test_mmx() != TEST_OK) {
			printf("mmx test failed in cpu_sharing_test013 \n\r");
			ret = false;
		}

		if (test_fpu() != TEST_OK) {
			printf("fpu test failed in cpu_sharing_test013 \n\r");
			ret = false;
		}

		if (test_gp_ins() != TEST_OK) {
			printf("gp instruction test failed in cpu_sharing_test013 \n\r");
			ret = false;
		}

		if (check_xsave_area() != TEST_OK) {
			printf("xave area checking failed in test\n\r");
			ret = false;
		}

		if (tdt_isr_flag) {
			tdt_isr_flag = false;
			break;
		}
	}
	report("TC_CPU_sharing_rr_scheduler_013\n\r", ret);
}

void main()
{
	int *p;
	u64 ticks;
//	u64 print_cnt = 0;
//	u64 rflags;

	setup_vm();
	setup_idt();
	tsc_calibrate();
	if (init_rtsc_dtimer() != true) {
		printf("not support tsc deadline timer\n\r");
		return;
	}

	ticks = TICKS_PER_SEC * 120;
	p = (int *)malloc(mem_size);
#if 0
	cpu_sharing_test003(p, ticks);
	//cpu_sharing_test007(ticks);
#else
	cpu_sharing_test001(p, ticks);
	cpu_sharing_test002(ticks);
	cpu_sharing_test003(p, ticks);
	//report_skip("TC_CPU_sharing_rr_scheduler_003: trigger exception");
	cpu_sharing_test004(p, ticks);
	cpu_sharing_test005(ticks);
	cpu_sharing_test006(ticks);
	cpu_sharing_test007(ticks);
	cpu_sharing_test008(ticks);
	cpu_sharing_test009(ticks);
	cpu_sharing_test010(ticks);
	cpu_sharing_test011(ticks);
	cpu_sharing_test012(ticks);
	report_summary();
#endif
	free(p);

#if 0
	while (1) {
		for (int i = 0; i < mem_size / 4; i++) {
			*(p + i) = i;
			asm volatile("hlt");
			asm volatile ("pause");
			asm volatile("WBINVD");
			sleep_ns(100);
			if (tdt_isr_flag) {
				pio_test();
			}
		}

	}

	if (tdt_isr) {
		start_dtimer(ticks);

		tdt_isr = false;
		if (process_dtimer_cnt % 200 == 0) {
			if (print_cnt % 16 == 0) {
				printf("\n\r");
			}
			print_cnt ++;
			printf("%lx ", print_cnt);
		}
		pio_test();
	}
#endif
#if 0
	asm volatile("pushf\n\t"
				 "pop %0\n\t"
				 :"=m"(rflags)::"memory");
	printf("rflags:%lx", rflags);
	//invalid_ept();
	//update_eoi();
#endif

}


