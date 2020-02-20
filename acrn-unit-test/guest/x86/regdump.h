//#include "libcflat.h"
//#include "msrdump.h"
#ifndef _REG_DUMP_H_
#define _REG_DUMP_H_
#include "msr.h"
//#include "alloc.h"
//#include "desc.h"
//#include "processor.h"
#if 0
#define X86_CR4_OSXSAVE					(1<<18)
#define XCR0_MASK       0x00000000
#define XCR_XFEATURE_ILLEGAL_MASK       0x00000010
#define CPUID_1_ECX_XSAVE	    		(1 << 26)
#define CPUID_1_ECX_OSXSAVE	    		(1 << 27)

#define STATE_X87_BIT			0
#define STATE_SSE_BIT			1
#define STATE_AVX_BIT			2
#define STATE_MPX_BNDREGS_BIT		3
#define STATE_MPX_BNDCSR_BIT		4
#define STATE_AVX_512_OPMASK		5
#define STATE_AVX_512_Hi16_ZMM_BIT	7
#define STATE_PT_BIT			8
#define STATE_PKRU_BIT			9
#define STATE_HDC_BIT			13

#define STATE_X87		(1 << STATE_X87_BIT)
#define STATE_SSE		(1 << STATE_SSE_BIT)
#define STATE_AVX		(1 << STATE_AVX_BIT)
#define STATE_MPX_BNDREGS	(1 << STATE_MPX_BNDREGS_BIT)
#define STATE_MPX_BNDCSR	(1 << STATE_MPX_BNDCSR_BIT)
#define STATE_AVX_512		(0b111 << STATE_AVX_512_OPMASK)
#define STATE_PT		(1 << STATE_PT_BIT)
#define STATE_PKRU		(1 << STATE_PKRU_BIT)
#define STATE_HDC		(1 << STATE_HDC_BIT)
#endif
#define XSAVE_REGDUMP_OFFSET (1 << 10)//xsave reg begin from 1k offset of base address
#define MSR_REGDUMP_OFFSET (3 << 10)   //msr reg begin from 3k offset of base address  

typedef struct gen_reg_dump{
	u64 rax, rbx, rcx, rdx;
	u64 rsi, rdi, rsp, rbp;
	u64 rip, rflags;
#ifdef __x86_64__
	u64 r8, r9, r10, r11;
	u64 r12, r13, r14, r15;
#endif
    u64 cr0,cr1,cr2,cr3,cr4,cr8;
}gen_reg_dump_t;

typedef unsigned __attribute__((vector_size(16))) fpu_st;
typedef unsigned __attribute__((vector_size(16))) sse_xmm;
typedef unsigned __attribute__((vector_size(16))) avx_ymm;
typedef unsigned __attribute__((vector_size(16))) bnd_reg;

/*legacy area for fpu&sse.416 bytes totally*/
typedef struct fpu_sse_struct {
    u16 fcw;
    u16 fsw;
    u8  ftw;
    u8  reserved;
    u16 fpop;
    u64 fpip;
    u64 fpdp;
    u32 mxcsr;
    u32 mxcsr_mask;
    fpu_st fpregs[8];
    sse_xmm xmm_regs[16];
} __attribute__((packed)) fpu_sse_t;

/*64bytes xsave header*/
typedef struct xsave_header_struct {
    u64 xstate_bv;
    u64 xcomp_bv;
    u64 reserved[6];
}xsave_header_t;

/* Ext. save area 2: AVX State 256bytes*/
typedef struct xsave_avx_struct {
    avx_ymm avx_ymm[16];
} xsave_avx_t;

/* Ext. save area 3: BNDREG 64bytes*/
typedef struct xsave_bndreg_struct {
    bnd_reg bnd_regs[4];
} xsave_bndreg_t;

/* Ext. save area 4: BNDCSR 16bytes*/
typedef struct xsave_bndcsr_struct {
    u64 cfg_reg_u;
    u64 status_reg;
} xsave_bndcsr_t;


/* we only support x87&sse&avx&mpx for XSAVE feature set now!!
   1040 bytes totally
*/
typedef struct xsave_area_struct {
    u8 fpu_sse[512];
    struct xsave_header_struct xsave_hdr;//64
    /*extended area*/
    u8 ymm[256];
    u8 lwp[128];/*this is a gap,i don't know what it should be until now....*/
    struct xsave_bndreg_struct bndregs;//64 bytes
    struct xsave_bndcsr_struct bndcsr;//16 bytes/*by cpuid.0d.04 return eax--0x40 this is 64 bytes */
} __attribute__((packed)) xsave_area_t;

/* xsave_dump_struct:752 bytes totally*/
typedef struct xsave_dump_struct{
    struct fpu_sse_struct fpu_sse;// 416 bytes
    struct xsave_avx_struct ymm;// 256 bytes
    struct xsave_bndreg_struct bndregs;//64 bytes
    struct xsave_bndcsr_struct bndcsr;//16 bytes
}xsave_dump_t;//
typedef struct msr_dump_info{
    u32 index;
    u32 valid;
    const char * name;
}msr_dump_info_t;
typedef enum msr_all_name{
    MSR_IA32_SYSENTER_CS_NAME = 0u,
    MSR_IA32_SYSENTER_ESP_NAME,
    MSR_MTRRfix4K_D8000_NAME,
    MSR_MTRRdefType_NAME,
    MSR_DUMP_NAME_MAX
} MSR_ALL_NAME_E;

#define  MSR_INDEX_LIST_ALL {MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, \
                MSR_MTRRfix4K_D8000, MSR_MTRRdefType}


bool xsave_reg_dump(void *ptr);
bool compare_all(void *ptr1,void *ptr2);
bool dump_all(void *ptr,size_t size);
void dump_free( void *ptr);

/*-------------------------------------------------*
*Genaral register dump 
*
*
*--------------------------------------------------*/
static inline void gen_reg_dump(void * ptr)
{
    gen_reg_dump_t * reg_dump;
    u64 ip;
    
    /*dump rip & rflags firstly or, we does not need dump rip ?*/
#ifdef __x86_64__
    asm volatile ("lea (%%rip),%0\n"
                    :"=g"(ip)::"memory");
#endif
#ifdef __i386__
        asm volatile ("lea (%%eip),%0\n"
                        :"=g"(ip)::"memory");
#endif
    reg_dump = (gen_reg_dump_t*)ptr;
    reg_dump->rflags = read_rflags();
    
    asm volatile ("mov %%" R "ax," "%0" :"=m"(reg_dump->rax)::"memory");
    asm volatile ("mov %%" R "bx," "%0" :"=m"(reg_dump->rbx)::"memory");
    asm volatile ("mov %%" R "cx," "%0" :"=m"(reg_dump->rcx)::"memory");
    asm volatile ("mov %%" R "dx," "%0" :"=m"(reg_dump->rdx)::"memory");
    asm volatile ("mov %%" R "si," "%0" :"=m"(reg_dump->rsi)::"memory");
    asm volatile ("mov %%" R "di," "%0" :"=m"(reg_dump->rdi)::"memory");
    asm volatile ("mov %%" R "sp," "%0" :"=m"(reg_dump->rsp)::"memory");
    asm volatile ("mov %%" R "bp," "%0" :"=m"(reg_dump->rbp)::"memory");
#ifdef __x86_64__
    asm volatile ("mov %%r8, %0" :"=m"(reg_dump->r8)::"memory");
    asm volatile ("mov %%r9, %0" :"=m"(reg_dump->r9)::"memory");
    asm volatile ("mov %%r10," "%0" :"=m"(reg_dump->r10)::"memory");
    asm volatile ("mov %%r11," "%0" :"=m"(reg_dump->r11)::"memory");
    asm volatile ("mov %%r12," "%0" :"=m"(reg_dump->r12)::"memory");
    asm volatile ("mov %%r13," "%0" :"=m"(reg_dump->r13)::"memory");
    asm volatile ("mov %%r14," "%0" :"=m"(reg_dump->r14)::"memory");
    asm volatile ("mov %%r15," "%0" :"=m"(reg_dump->r15)::"memory");
#endif
    asm volatile ("mov %%cr0,%%" R "ax \n" 
                  "mov %%" R "ax," "%0"
                  :"=m"(reg_dump->cr0)::"memory");
   // asm volatile ("mov %%cr1,%%" R "ax \n" /*read cr1 will occur error*/
   //               "mov %%" R "ax," "%0"
   //               :"=m"(reg_dump->cr1)::"memory");
    asm volatile ("mov %%cr2,%%" R "ax \n" 
                  "mov %%" R "ax," "%0"
                  :"=m"(reg_dump->cr2)::"memory");
    asm volatile ("mov %%cr3,%%" R "ax \n" 
                  "mov %%" R "ax," "%0"
                  :"=m"(reg_dump->cr3)::"memory");
    asm volatile ("mov %%cr4,%%" R "ax \n" 
                  "mov %%" R "ax," "%0"
                  :"=m"(reg_dump->cr4)::"memory");
    asm volatile ("mov %%cr8,%%" R "ax \n" 
                  "mov %%" R "ax," "%0"
                  :"=m"(reg_dump->cr8)::"memory");
    reg_dump->rip = ip - 6;
    
}

#endif
