/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#define UK_DEBUG

#include "uk/asm/sev.h"
#include "kvm-x86/serial_console.h"
#include "uk/arch/lcpu.h"
#include "uk/arch/paging.h"
#include "uk/asm/sev-ghcb.h"
#include "uk/asm/svm.h"
#include "uk/bitops.h"
#include "uk/isr/string.h"
#include "uk/plat/bootstrap.h"
#include "uk/plat/io.h"
#include "uk/plat/paging.h"
#include <x86/cpu.h>
#include "x86/desc.h"
#include "x86/traps.h"
#include <stdio.h>
#include <uk/sev.h>
#include <errno.h>
#include <uk/essentials.h>
#include <uk/assert.h>
#include <uk/print.h>
#include <uk/page.h>

#include <kvm/efi.h>
#include <uk/plat/common/bootinfo.h>

#include <kvm-x86/traps.h>

#include <uk/event.h>

#include "decoder.h"

/* Boot GDT and IDT to setup the early VC handler */
static __align(8) struct seg_desc32 boot_cpu_gdt64[GDT_NUM_ENTRIES];
static struct seg_gate_desc64 sev_boot_idt[IDT_NUM_ENTRIES] __align(8);
static struct desc_table_ptr64 boot_idtptr;
static struct ghcb ghcb_page __align(__PAGE_SIZE);

static struct uk_efi_cc_blob_tbl *cc_blob_tbl;
static struct svsm_caa *svsm_caa_gpa;
int svsm_present = 0;

static inline int uk_sev_svsm_present()
{
#ifdef CONFIG_X86_AMD64_FEAT_SEV_ES
	return svsm_present;
#else
	return 0;
#endif
}

/* Debug printing is only available after GHCB is initialized. */
int ghcb_initialized = 1;

static inline void uk_sev_ghcb_wrmsrl(__u64 value)
{
	wrmsrl(SEV_ES_MSR_GHCB, value);
}
static inline __u64 uk_sev_ghcb_rdmsrl()
{
	return rdmsrl(SEV_ES_MSR_GHCB);
}

static inline __u64 uk_sev_ghcb_msr_invoke(__u64 value)
{
	uk_sev_ghcb_wrmsrl(value);
	vmgexit();
	return uk_sev_ghcb_rdmsrl();
}

int uk_sev_ghcb_initialized(void) {
#ifdef CONFIG_X86_AMD64_FEAT_SEV_ES
	return ghcb_initialized;
#else
	return 1;
#endif
}
void uk_sev_terminate(int set, int reason)
{
	uk_sev_ghcb_wrmsrl(SEV_GHCB_MSR_TERM_REQ_VAL(set, reason));
	vmgexit();
}

int uk_sev_ghcb_vmm_call(struct ghcb *ghcb, __u64 exitcode, __u64 exitinfo1,
			 __u64 exitinfo2)
{
	GHCB_SAVE_AREA_SET_FIELD(ghcb, sw_exitcode, exitcode);
	GHCB_SAVE_AREA_SET_FIELD(ghcb, sw_exitinfo1, exitinfo1);
	GHCB_SAVE_AREA_SET_FIELD(ghcb, sw_exitinfo2, exitinfo2);
	ghcb->ghcb_usage = SEV_GHCB_USAGE_DEFAULT;

	/* TODO: Negotiate ghcb protocol version */
	/* ghcb->protocol_version = 1; */
	uk_sev_ghcb_wrmsrl(ukplat_virt_to_phys(ghcb));
	vmgexit();

	/* TODO: Verify VMM return */
	return 0;
};

static inline int _uk_sev_ghcb_cpuid_reg(int reg_idx, int fn, __u32 *reg)
{
	__u64 val, code;

	val = uk_sev_ghcb_msr_invoke(SEV_GHCB_MSR_CPUID_REQ_VAL(reg_idx, fn));
	code = SEV_GHCB_MSR_RESP_CODE(val);
	if (code != SEV_GHCB_MSR_CPUID_RESP) {
		return -1;
	}

	*reg = (val >> 32);
	return 0;
}

static inline int uk_sev_ghcb_cpuid(__u32 fn, __unused __u32 sub_fn, __u32 *eax,
				    __u32 *ebx, __u32 *ecx, __u32 *edx)
{
	int rc;

	rc = _uk_sev_ghcb_cpuid_reg(SEV_GHCB_MSR_CPUID_REQ_RAX, fn, eax);
	rc = rc ? rc
		: _uk_sev_ghcb_cpuid_reg(SEV_GHCB_MSR_CPUID_REQ_RBX, fn, ebx);
	rc = rc ? rc
		: _uk_sev_ghcb_cpuid_reg(SEV_GHCB_MSR_CPUID_REQ_RCX, fn, ecx);
	rc = rc ? rc
		: _uk_sev_ghcb_cpuid_reg(SEV_GHCB_MSR_CPUID_REQ_RDX, fn, edx);
	return rc;
}

#define COM1 0x3f8
#define COM1_DATA (COM1 + 0)
#define COM1_STATUS (COM1 + 5)
#define MAX_SEV_PRINT_LEN 512

/*
 * Emulation of serial print, so that #VC is not triggered.
 */
// #define SERIAL_PRINTF 1
static void uk_sev_serial_printf(struct ghcb *ghcb, const char* fmt, ...){
#if SERIAL_PRINTF
	if (!ghcb_initialized)
		return;

	char buf[MAX_SEV_PRINT_LEN];
	unsigned long orig_rax, orig_rdx, orig_rax_valid, orig_rdx_valid;

	va_list ap;
	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	__u64 exitinfo1 = 0;
	exitinfo1 |= UK_SEV_IOIO_TYPE_OUT;
	exitinfo1 |= UK_SEV_IOIO_TYPE_OUT;
	exitinfo1 |= UK_SEV_IOIO_SEG(UK_SEV_IOIO_SEG_DS);
	exitinfo1 |= UK_SEV_IOIO_PORT(COM1_DATA);
	exitinfo1 |= UK_SEV_IOIO_SZ8;
	exitinfo1 |= UK_SEV_IOIO_A16;

	/* Backup rax and rdx if they are set previously */
	orig_rax_valid = GHCB_SAVE_AREA_GET_VALID(ghcb, rax);
	orig_rdx_valid = GHCB_SAVE_AREA_GET_VALID(ghcb, rdx);

	if (orig_rax_valid)
		orig_rax = ghcb->save_area.rax;
	if (orig_rdx_valid)
		orig_rdx = ghcb->save_area.rdx;

	for (int i = 0; i < MAX_SEV_PRINT_LEN; i++) {
		if (buf[i] == '\0')
			break;
		if (buf[i] == '\n') {
			GHCB_SAVE_AREA_SET_FIELD(ghcb, rax,
						 '\r' & (UK_BIT(8) - 1));
			uk_sev_ghcb_vmm_call(ghcb, SVM_VMEXIT_IOIO, exitinfo1,
					     0);
		}

		GHCB_SAVE_AREA_SET_FIELD(ghcb, rax, buf[i] & (UK_BIT(8) - 1));
		uk_sev_ghcb_vmm_call(ghcb, SVM_VMEXIT_IOIO, exitinfo1, 0);
	}

	/* Restore rax and rdx */
	if (orig_rax_valid)
		GHCB_SAVE_AREA_SET_FIELD(ghcb, rax, orig_rax);
	if (orig_rdx_valid)
		GHCB_SAVE_AREA_SET_FIELD(ghcb, rdx, orig_rdx);
#endif

}

int do_vmm_comm_exception_no_ghcb(struct __regs *regs,
				   unsigned long error_code)
{
	__u32 fn = regs->rax;
	if (error_code == SVM_VMEXIT_CPUID) {
		__u32 eax, ebx = 0, ecx, edx;
		int rc;
		rc = uk_sev_ghcb_cpuid(fn, 0, &eax, &ebx, &ecx, &edx);

		if (unlikely(rc)) {
			return rc;
		}

		regs->rax = eax;
		regs->rbx = ebx;
		regs->rcx = ecx;
		regs->rdx = edx;

		/* Advance RIP by 2 bytes (CPUID opcode) */
		regs->rip += 2;
		return 0;
	}

	uk_sev_terminate(1, error_code);
	/* Other error code are not supported */
	return -ENOTSUP;
}

int uk_sev_set_pages_state(__vaddr_t vstart, __paddr_t pstart, unsigned long num_pages,
			   int page_state)
{
	static int counter_shared = 0;
	static int counter_private = 0;
	static int counter_call = 0;

	vstart = PAGE_ALIGN_DOWN(vstart);
	pstart = PAGE_ALIGN_DOWN(pstart);

	for (unsigned long i = 0; i < num_pages; i++){
		int rc;
		__u64 val;
		__paddr_t paddr = pstart + i * PAGE_SIZE;
		__paddr_t vaddr = vstart + i * PAGE_SIZE;

		uk_pr_debug("uk_sev_set_pages_state: uk_sev_ghcb_initialized: %d\n", uk_sev_ghcb_initialized());
		// TODO: When kernel running in VMPL1 (a.k.a, SVSM is present), PVALIDATE inst. should
		// only be invoked by SVSM running at VMPL0 (refer to doc No. 24594, page 426)
		if (page_state == SEV_GHCB_MSR_SNP_PSC_PG_SHARED) {
			counter_shared++;

			/* Un-validate page to make it shared */
			if (svsm_present)
			{
				// MEMO: According to https://lkml.org/lkml/2024/1/26/1092,
				// When an SVSM is present, use the SVSM_CORE_PVALIDATE call to perform
				// memory validation instead of issuing the PVALIDATE instruction directly.
				uk_pr_info("[count: %d] Pvalidating vaddr 0x%lx paddr 0x%lx shared by SVSM\n", 
					counter_shared, vaddr, paddr);
				rc = uk_sev_svsm_core_pvalidate_msr(vaddr, PVALIDATE_PAGE_SIZE_4K, 0);
			}
			else
			{
				uk_pr_info("[count: %d] Pvalidating vaddr 0x%lx paddr 0x%lx shared by instruction\n", 
					counter_shared, vaddr, paddr);
				rc = pvalidate(vaddr, PVALIDATE_PAGE_SIZE_4K, 0);
			}

			if (unlikely(rc))
			{
				uk_pr_warn("pvalidate failed, error code: %d.\n", rc);
				return rc;
			}
			//while (1);
		}

		/* 
		 * MEMO: This GHCB MSR invoke is given parameters
		 * GHCBInfo: 0x014 Page State Change Request
		 * GHCBData:
		 * 	 GHCBData[55:52] – Page operation `page_state`  
		 *	 GHCBData[51:12] – Guest physical frame number `paddr >> PAGE_SHIFT`
		 * to change the page state to `page_state`.
		 */
		uk_pr_info("Requesting PSC\n");
		counter_call++;
		uk_pr_info("[count: %d] Requesting PSC\n", counter_call);
		val = uk_sev_ghcb_msr_invoke(SEV_GHCB_MSR_SNP_PSC_REQ_VAL(
		    page_state, paddr >> PAGE_SHIFT));

		if (SEV_GHCB_MSR_RESP_CODE(val) != SEV_GHCB_MSR_SNP_PSC_RESP)
			return -1;

		if (SEV_GHCB_MSR_SNP_PSC_RESP_VAL(val)) {
			uk_pr_warn("PSC request failed, error code: 0x%lx.\n",
				   val);
			return -1;
		}

		if (page_state == SEV_GHCB_MSR_SNP_PSC_PG_PRIVATE) {
			counter_private++;
			uk_pr_info("[count: %d] Pvalidating vaddr 0x%lx paddr 0x%lx private\n", 
				counter_private, vaddr, paddr);
			
			if (svsm_present)
			{
				// MEMO: According to https://lkml.org/lkml/2024/1/26/1092,
				// When an SVSM is present, use the SVSM_CORE_PVALIDATE call to perform
				// memory validation instead of issuing the PVALIDATE instruction directly.
				rc = uk_sev_svsm_core_pvalidate_msr(vaddr, PVALIDATE_PAGE_SIZE_4K, 1);
			}
			else
			{
				rc = pvalidate(vaddr, PVALIDATE_PAGE_SIZE_4K, 1);
			}

			if (unlikely(rc))
			{
				uk_pr_warn("pvalidate failed, error code: %d.\n", rc);
				return rc;
			}
		}
	}

	return 0;
}


int uk_sev_set_memory_private(__vaddr_t addr, unsigned long num_pages)
{
	UK_ASSERT(PAGE_ALIGNED(addr));
	unsigned long prot;
	int rc;

	uk_pr_info("Setting 0x%lx, %lu pages to private\n", addr, num_pages);
	prot = PAGE_ATTR_PROT_RW | PAGE_ATTR_ENCRYPT;
	rc = ukplat_page_set_attr(ukplat_pt_get_active(), addr, num_pages, prot, 0);

	if (unlikely(rc))
		return rc;

#ifdef CONFIG_X86_AMD64_FEAT_SEV_SNP
	rc = uk_sev_set_pages_state(addr, ukplat_virt_to_phys((void*)addr), num_pages,
	 			    SEV_GHCB_MSR_SNP_PSC_PG_PRIVATE);
	if (unlikely(rc))
		return rc;
#endif

	memset((void *)addr, 0, num_pages * PAGE_SIZE);
	return 0;
}

int uk_sev_set_memory_shared(__vaddr_t addr, unsigned long num_pages)
{
	UK_ASSERT(PAGE_ALIGNED(addr));

	unsigned long prot;
	int rc;

	uk_pr_info("Setting 0x%lx, %lu pages to shared\n", addr, num_pages);

	/* Clearing memory before sharing the page. This also makes sure the PTE
	 * is present */
	memset((void *)addr, 0, num_pages * PAGE_SIZE);

#ifdef CONFIG_X86_AMD64_FEAT_SEV_SNP
	rc = uk_sev_set_pages_state(addr, ukplat_virt_to_phys((void *)addr),
				    num_pages, SEV_GHCB_MSR_SNP_PSC_PG_SHARED);
	if (unlikely(rc))
		return rc;
#endif

	prot = PAGE_ATTR_PROT_RW;
	rc = ukplat_page_set_attr(ukplat_pt_get_active(), addr, num_pages, prot,
				  0);

	if (unlikely(rc))
		return rc;

	return 0;
}

static inline int _uk_sev_ghcb_gpa_register(__paddr_t paddr)
{
	__u64 pfn, val;

	pfn = paddr >> __PAGE_SHIFT;
	val = uk_sev_ghcb_msr_invoke(SEV_GHCB_MSR_REG_GPA_REQ_VAL(pfn));

	if (SEV_GHCB_MSR_RESP_CODE(val) != SEV_GHCB_MSR_REG_GPA_RESP
	    && SEV_GHCB_MSR_REG_GPA_RESP_PFN(val) != pfn))
		return -1;

	return 0;
}

/* TODO: GHCB should be setup per-cpu */
int uk_sev_setup_ghcb(void)
{
#ifdef CONFIG_X86_AMD64_FEAT_SEV_ES
	int rc;
	__paddr_t ghcb_paddr;

	// while (1);
	rc = uk_sev_set_memory_shared((__vaddr_t)&ghcb_page,
				      sizeof(struct ghcb) / __PAGE_SIZE);

	if (unlikely(rc))
		return rc;

	// while (1);
	memset(&ghcb_page, 0, sizeof(struct ghcb));

	ghcb_paddr = ukplat_virt_to_phys(&ghcb_page);

	rc = _uk_sev_ghcb_gpa_register(ghcb_paddr);
	if (unlikely(rc))
		return rc;

	/* Fixup the idt with the VC handler that uses the GHCB  */
	traps_table_ghcb_vc_handler_init();

	ghcb_initialized = 1;

	/* An instruction decoder is needed to handle I/O-related #VC */
	rc = uk_sev_decoder_init();

	if (unlikely(rc)) {
		UK_CRASH("Fail initializing instruction decoder\n");
		return -1;
	}
#endif /* CONFIG_X86_AMD64_FEAT_SEV_ES */
	uk_pr_debug(" GHCB Virtual Address: 0x%016lx\n", (__u64)&ghcb_page);
	uk_pr_debug("GHCB Physical Address: 0x%016lx\n", (__u64)ukplat_virt_to_phys(&ghcb_page));

	return 0;
}

static void uk_sev_boot_gdt_init(void)
{
	volatile struct desc_table_ptr64 gdtptr; /* needs to be volatile so
						  * setting its values is not
						  * optimized out
						  */

	boot_cpu_gdt64[GDT_DESC_CODE].raw = GDT_DESC_CODE64_VAL;
	boot_cpu_gdt64[GDT_DESC_DATA].raw = GDT_DESC_DATA64_VAL;

	gdtptr.limit = sizeof(boot_cpu_gdt64) - 1;
	gdtptr.base = (__u64)&boot_cpu_gdt64;
	__asm__ goto(
	    /* Load the global descriptor table */
	    "lgdt	%0\n"

	    /* Perform a far return to enable the new CS */
	    "leaq	%l[jump_to_new_cs](%%rip), %%rax\n"

	    "pushq	%1\n"
	    "pushq	%%rax\n"
	    "lretq\n"
	    :
	    : "m"(gdtptr), "i"(GDT_DESC_OFFSET(GDT_DESC_CODE))
	    : "rax", "memory"
	    : jump_to_new_cs);
jump_to_new_cs:
	__asm__ __volatile__(
	    /* Update remaining segment registers */
	    "movl	%0, %%es\n"
	    "movl	%0, %%ss\n"
	    "movl	%0, %%ds\n"

	    /* Initialize fs and gs to 0 */
	    "movl	%1, %%fs\n"
	    "movl	%1, %%gs\n"
	    :
	    : "r"(GDT_DESC_OFFSET(GDT_DESC_DATA)), "r"(0));
	return;
}

static void uk_sev_boot_idt_fillgate(unsigned int num, void *fun,
				     unsigned int ist)
{
	struct seg_gate_desc64 *desc = &sev_boot_idt[num];

	/*
	 * All gates are interrupt gates, all handlers run with interrupts off.
	 */
	desc->offset_hi = (__u64)fun >> 16;
	desc->offset_lo = (__u64)fun & 0xffff;
	desc->selector = IDT_DESC_OFFSET(IDT_DESC_CODE);
	desc->ist = ist;
	desc->type = IDT_DESC_TYPE_INTR;
	desc->dpl = IDT_DESC_DPL_KERNEL;
	desc->p = 1;
}

static void uk_sev_boot_idt_init(void)
{
	__asm__ __volatile__("lidt %0" ::"m"(boot_idtptr));
}

static void uk_sev_boot_traps_table_init(void)
{
	uk_sev_boot_idt_fillgate(TRAP_vmm_comm_exception,
				 &ASM_TRAP_SYM(vmm_comm_exception_no_ghcb), 0);
	boot_idtptr.limit = sizeof(sev_boot_idt) - 1;
	boot_idtptr.base = (__u64)&sev_boot_idt;
}

static inline int
uk_sev_ioio_exitinfo1_init(struct uk_sev_decoded_inst *instruction,
			   struct __regs *regs, __u64 *exitinfo1)
{
	/* Encode the instruction type */
	switch (instruction->opcode) {
	/* INS */
	case 0x6c:
	case 0x6d:
		*exitinfo1 |= UK_SEV_IOIO_TYPE_IN;
		*exitinfo1 |= UK_SEV_IOIO_STR;
		*exitinfo1 |= UK_SEV_IOIO_SEG(UK_SEV_IOIO_SEG_ES);
		*exitinfo1 |= UK_SEV_IOIO_PORT(regs->rdx);
		break;

	/* OUTS */
	case 0x6e:
	case 0x6f:
		*exitinfo1 |= UK_SEV_IOIO_TYPE_OUT;
		*exitinfo1 |= UK_SEV_IOIO_STR;
		*exitinfo1 |= UK_SEV_IOIO_SEG(UK_SEV_IOIO_SEG_DS);
		*exitinfo1 |= UK_SEV_IOIO_PORT(regs->rdx);
		break;
	/* IN imm */
	case 0xe4:
	case 0xe5:
		*exitinfo1 |= UK_SEV_IOIO_TYPE_IN;
		*exitinfo1 |= UK_SEV_IOIO_PORT((__u8)instruction->immediate);
		break;
	/* OUT imm */
	case 0xe6:
	case 0xe7:
		*exitinfo1 |= UK_SEV_IOIO_TYPE_OUT;
		*exitinfo1 |= UK_SEV_IOIO_PORT((__u8)instruction->immediate);
		break;
	/* IN reg */
	case 0xec:
	case 0xed:
		*exitinfo1 |= UK_SEV_IOIO_TYPE_IN;
		*exitinfo1 |= UK_SEV_IOIO_SEG(UK_SEV_IOIO_SEG_ES);
		*exitinfo1 |= UK_SEV_IOIO_PORT(regs->rdx);
		break;
	/* OUT reg */
	case 0xee:
	case 0xef:
		*exitinfo1 |= UK_SEV_IOIO_TYPE_OUT;
		*exitinfo1 |= UK_SEV_IOIO_SEG(UK_SEV_IOIO_SEG_DS);
		*exitinfo1 |= UK_SEV_IOIO_PORT(regs->rdx);
		break;
	default:
		return -1;
	}

	/* Encode the operand size */
	switch (instruction->operand_width) {
	case 8:
		*exitinfo1 |= UK_SEV_IOIO_SZ8;
		break;
	case 16:
		*exitinfo1 |= UK_SEV_IOIO_SZ16;
		break;
	case 32:
		*exitinfo1 |= UK_SEV_IOIO_SZ32;
		break;
	default:
		return -1;
	}

	/* Encode the address size */
	switch (instruction->address_width) {
	case 16:
		*exitinfo1 |= UK_SEV_IOIO_A16;
		break;
	case 32:
		*exitinfo1 |= UK_SEV_IOIO_A32;
		break;
	case 64:
		*exitinfo1 |= UK_SEV_IOIO_A64;
		break;
	default:
		return -1;
	}

	/* Encode rep prefix */
	if (instruction->has_rep) {
		*exitinfo1 |= UK_SEV_IOIO_REP;
	}
	return 0;
}

static int uk_sev_handle_ioio_exitinfo1(struct uk_sev_decoded_inst *instruction,
					struct __regs *regs, struct ghcb *ghcb,
					__u64 exitinfo1)
{
	__u64 exitinfo2 = 0;
	if (exitinfo1 & UK_SEV_IOIO_STR) {

		/* We only handle reg and imm-based IO for now */
		return -ENOTSUP;
	} else { /* Non-string IN/OUT */
		__u8 addr_bits;
		if (exitinfo1 & UK_SEV_IOIO_A16)
			addr_bits = 16;
		else if (exitinfo1 & UK_SEV_IOIO_A32)
			addr_bits = 32;
		else
			addr_bits = 64;

		if (!(exitinfo1 & UK_SEV_IOIO_TYPE_IN)) {
			GHCB_SAVE_AREA_SET_FIELD(
			    ghcb, rax, regs->rax & (UK_BIT(addr_bits) - 1));
		}
		uk_sev_ghcb_vmm_call(ghcb, SVM_VMEXIT_IOIO, exitinfo1,
				     exitinfo2);

		if (exitinfo1 & UK_SEV_IOIO_TYPE_IN) {
			regs->rax =
			    (ghcb->save_area.rax & (UK_BIT(addr_bits) - 1));
		}
	}
	return 0;
}

static int uk_sev_handle_ioio(struct __regs *regs, struct ghcb *ghcb)
{
	struct uk_sev_decoded_inst instruction;
	__u64 exitinfo1 = 0;
	int rc;
	rc = uk_sev_decode_inst(regs->rip, &instruction);
	if (unlikely(rc)) {
		UK_CRASH("Failed decoding instruction\n");
	}

	rc = uk_sev_ioio_exitinfo1_init(&instruction, regs, &exitinfo1);
	if (unlikely(rc)) {
		UK_CRASH("Failed building exitinfo1\n");
	}

	rc = uk_sev_handle_ioio_exitinfo1(&instruction, regs, ghcb, exitinfo1);
	if (unlikely(rc)) {
		UK_CRASH("Failed handling exitinfo1\n");
	}

	/* Now skip over the emulated instruction */
	regs->rip += instruction.length;
	return 0;
}

static int uk_sev_do_mmio(struct ghcb *ghcb,int is_read){

}
static int uk_sev_handle_mmio_inst(struct __regs *regs, struct ghcb *ghcb,
				   struct uk_sev_decoded_inst *instruction)
{
	unsigned long *reg_ref, *mem_ref;
	__u64 disp = 0;
	int rc, sz;
	int is_read = 0;

	char buffer[512];
	memset_isr(buffer, 0, 512);
	uk_sev_pr_instruction(instruction, buffer, 512);
	uk_sev_serial_printf(ghcb, "Handling MMIO %s\n", buffer);
	uk_sev_serial_printf(ghcb, "opcode: 0x%x\n", instruction->opcode);


	/* uk_sev_pr_instruction(instruction); */
	/* uk_pr_info("Opcode: 0x%" __PRIx64 "\n", instruction->opcode); */

	__u64 exitcode, exitinfo1, exitinfo2;
	__paddr_t ghcb_phys, shared_buffer;
	switch (instruction->opcode) {
	/* MOV r, r/m: MMIO write reg to memory */
	case 0x88:
	case 0x89:
		rc = uk_sev_inst_get_reg_operand(instruction, regs, &reg_ref);
		if (rc)
			UK_CRASH("Failed getting reg operand\n");

		rc = uk_sev_inst_get_mem_reg_operand(instruction, regs,
						     &mem_ref);

		rc = uk_sev_inst_get_displacement(instruction, &disp);
		sz = instruction->operand_width / 8;


		exitcode = SVM_VMGEXIT_MMIO_WRITE;
		exitinfo1 = (__u64)ukplat_virt_to_phys((void *)*mem_ref) + disp;
		exitinfo2 = sz;

		/* shared_buffer = ukplat_virt_to_phys(ghcb->shared_buffer); */
		ghcb_phys = ukplat_virt_to_phys(ghcb);
		shared_buffer =
		    ghcb_phys + __offsetof(struct ghcb, shared_buffer);
		uk_sev_serial_printf(ghcb, "shared buffer: 0x%lx\n", shared_buffer);
		uk_sev_serial_printf(ghcb, "exit_reason: 0x%lx\n", exitcode);
		uk_sev_serial_printf(ghcb, "ghcb: 0x%lx\n", ghcb_phys);


		/* shared_buffer = */
		/*     ghcb_phys + __offsetof(struct ghcb, shared_buffer); */

		memcpy_isr(ghcb->shared_buffer, reg_ref, sz);
		uk_sev_serial_printf(
		    ghcb, "Requesting write: %d size, value %x to 0x%lx\n", exitinfo2,
		    *reg_ref, exitinfo1);

		GHCB_SAVE_AREA_SET_FIELD(ghcb, sw_scratch, shared_buffer);

		uk_sev_ghcb_vmm_call(ghcb, exitcode, exitinfo1, exitinfo2);
		break;

	/* MOV r/m, r: MMIO read memory to reg */
	case 0x8a:
	case 0x8b:
		is_read = 1;
		rc = uk_sev_inst_get_reg_operand(instruction, regs, &reg_ref);
		if (rc)
			UK_CRASH("Failed getting reg operand\n");

		rc = uk_sev_inst_get_mem_reg_operand(instruction, regs,
						     &mem_ref);

		rc = uk_sev_inst_get_displacement(instruction, &disp);
		sz = instruction->operand_width / 8;

		exitcode = SVM_VMGEXIT_MMIO_READ;
		exitinfo1 = (__u64)ukplat_virt_to_phys((void *)*mem_ref) + disp;
		exitinfo2 = sz;
		ghcb_phys = ukplat_virt_to_phys(ghcb);
		shared_buffer =
		    ghcb_phys + __offsetof(struct ghcb, shared_buffer);
		uk_sev_serial_printf(ghcb, "shared buffer: 0x%lx\n", shared_buffer);

		/* shared_buffer = ukplat_virt_to_phys(ghcb->shared_buffer); */
		GHCB_SAVE_AREA_SET_FIELD(ghcb, sw_scratch, shared_buffer);

		uk_sev_ghcb_vmm_call(ghcb, exitcode, exitinfo1, exitinfo2);

		uk_sev_serial_printf(ghcb,
				     "Requesting read: %d size, to 0x%lx\n",
				     exitinfo2, exitinfo1);

		uk_sev_serial_printf(ghcb, "Read result: 0x%lx\n",
				     *(unsigned long *)ghcb->shared_buffer);

		memcpy_isr(reg_ref, ghcb->shared_buffer, sz);
		break;

	default:
		uk_sev_terminate(9,9);
		return -ENOTSUP;
	}

	return 0;
}

static int uk_sev_handle_mmio(struct __regs *regs, struct ghcb *ghcb)
{
	struct uk_sev_decoded_inst instruction;
	int rc;

	rc = uk_sev_decode_inst(regs->rip, &instruction);
	if (unlikely(rc))
		return rc;

	rc = uk_sev_handle_mmio_inst(regs, ghcb, &instruction);
	if (unlikely(rc))
		return rc;

	regs->rip += instruction.length;
	return 0;
}

static int uk_sev_handle_msr(struct __regs *regs, struct ghcb *ghcb)
{
	__u64 exitcode, exitinfo1;
	int rc;
	struct uk_sev_decoded_inst instruction;

	rc = uk_sev_decode_inst(regs->rip, &instruction);
	if (unlikely(rc)) {
		return rc;
	}

	switch (instruction.opcode) {
	case 0x30: /* WRMSR opcode */
		exitinfo1 = 1;
		break;
	case 0x32: /* RDMSR opcode */
		exitinfo1 = 0;
		break;
	default:
		return -ENOTSUP;
	}

	exitcode = SVM_VMEXIT_MSR;
	GHCB_SAVE_AREA_SET_FIELD(ghcb, rcx, regs->rcx);

	if (exitinfo1) {
		GHCB_SAVE_AREA_SET_FIELD(ghcb, rax, regs->rax);
		GHCB_SAVE_AREA_SET_FIELD(ghcb, rdx, regs->rdx);
	}

	rc = uk_sev_ghcb_vmm_call(ghcb, exitcode, exitinfo1, 0);
	if (unlikely(rc))
		return rc;

	if (!exitinfo1) {
		regs->rax = ghcb->save_area.rax;
		regs->rdx = ghcb->save_area.rdx;
	}
	regs->rip += instruction.length;

	return 0;
}

static int uk_sev_handle_vc(void *data)
{
	struct ukarch_trap_ctx *ctx = (struct ukarch_trap_ctx *)data;

	int exit_code = ctx->error_code;
	struct ghcb *ghcb = &ghcb_page;

	int rc = 0;
	switch (exit_code) {
	case SVM_VMEXIT_CPUID:
		/* Reuse the no GHCB handler for now */
		do_vmm_comm_exception_no_ghcb(ctx->regs, exit_code);
		break;
	case SVM_VMEXIT_IOIO:
		rc = uk_sev_handle_ioio(ctx->regs, ghcb);
		break;
	case SVM_VMEXIT_NPF:
		rc = uk_sev_handle_mmio(ctx->regs, ghcb);
		break;
	case SVM_VMEXIT_MSR:
		rc = uk_sev_handle_msr(ctx->regs, ghcb);
		break;
	default:
		uk_sev_terminate(2, exit_code);
		return UK_EVENT_NOT_HANDLED;
	}

	if (unlikely(rc)) {
		uk_sev_terminate(3, rc);
		UK_CRASH("Failed handling #VC , ec = %d\n", exit_code);
		return UK_EVENT_NOT_HANDLED;
	}

	return UK_EVENT_HANDLED;
}

int uk_sev_mem_encrypt_init(void)
{
	__u32 eax, ebx, ecx, edx;
	__u32 encryption_bit;

	ukarch_x86_cpuid(0x8000001f, 0, &eax, &ebx, &ecx, &edx);
	encryption_bit = ebx & X86_AMD64_CPUID_EBX_MEM_ENCRYPTION_MASK;

	if (unlikely(encryption_bit != CONFIG_LIBUKSEV_PTE_MEM_ENCRYPT_BIT)) {
		UK_CRASH("Invalid encryption bit configuration, please set "
			 "it to %d in the config.\n",
			 encryption_bit);
	}

	return 0;
};

int uk_sev_cpu_features_check(void){
	__u32 eax, ebx, ecx, edx;

	ukarch_x86_cpuid(0x8000001f, 0, &eax, &ebx, &ecx, &edx);
	if (unlikely(!(eax & X86_AMD64_CPUID_EAX_SEV_ENABLED))) {
		uk_pr_crit("%s not supported.\n", "AMD SEV");
		return -ENOTSUP;
	}

#ifdef CONFIG_X86_AMD64_FEAT_SEV_ES
	if (unlikely(!(eax & X86_AMD64_CPUID_EAX_SEV_ES_ENABLED))) {
		uk_pr_crit("%s not supported.\n", "AMD SEV-ES");
		return -ENOTSUP;
	}
#endif /* CONFIG_X86_AMD64_FEAT_SEV_ES */

#ifdef CONFIG_X86_AMD64_FEAT_SEV_SNP
	if (unlikely(!(eax & X86_AMD64_CPUID_EAX_SEV_SNP_ENABLED))) {
		uk_pr_crit("%s not supported.\n", "AMD SEV-SNP");
		return -ENOTSUP;
	}
#endif /* CONFIG_X86_AMD64_FEAT_SEV_SNP */
	return 0;
}



int uk_sev_early_vc_handler_init(void)
{
	uk_sev_boot_traps_table_init();
	uk_sev_boot_gdt_init();
	uk_sev_boot_idt_init();
	ghcb_initialized = 0;
	return 0;
}



UK_EVENT_HANDLER(UKARCH_TRAP_VC, uk_sev_handle_vc);

int uk_sev_svsm_discover(__u64 efi_st)
{
	struct uk_efi_cfg_tbl *ct;
	struct uk_efi_sys_tbl *uk_efi_st;
	struct snp_secrets_page_layout *snp_sp;
	__u64 i;
	//__u32 fms_cpuid;

	uk_efi_st = (struct uk_efi_sys_tbl*)efi_st;
	uk_pr_debug("Finding uk_efi_st->configuration_table for ccblob...\n");
	for (i = 0; i < uk_efi_st->number_of_table_entries; i++) {
		ct = &uk_efi_st->configuration_table[i];

		if (!memcmp(&ct->vendor_guid,
			    UK_EFI_CC_BLOB_GUID,
			    sizeof(ct->vendor_guid))) {
			
			uk_pr_debug("Found UK_EFI_CC_BLOB_GUID in configuration_table[%ld].\n", i);
			cc_blob_tbl = ct->vendor_table;
			uk_pr_debug("                        Magic:\t0x%08x (Should be: 0x%08x)\n", cc_blob_tbl->magic, CC_BLOB_SEV_HDR_MAGIC);
			uk_pr_debug("                      Version:\t0x%08x (%d)\n", cc_blob_tbl->version, cc_blob_tbl->version);
			uk_pr_debug("Secrets Page Physical Address:\t0x%016lx\n", cc_blob_tbl->secrets_phys);
			uk_pr_debug("          Secrets Page Length:\t0x%08x (%d)\n", cc_blob_tbl->secrets_len, cc_blob_tbl->secrets_len);
			uk_pr_debug("       CPUID Physical Address:\t0x%016lx\n", cc_blob_tbl->cpuid_phys);
			uk_pr_debug("                 CPUID Length:\t0x%08x (%d)\n", cc_blob_tbl->cpuid_len, cc_blob_tbl->cpuid_len);
			break;
		}
	}

	snp_sp = (struct snp_secrets_page_layout *)cc_blob_tbl->secrets_phys;
	uk_pr_debug("Contents in Secrets Page starting from 0x%016lx:\n", (__u64)snp_sp);
	uk_pr_debug("Version: 0x%08x (%d)\n", snp_sp->version, snp_sp->version);
	uk_pr_debug(" IMI_EN: 0x%02x (%d)\n", snp_sp->imien, snp_sp->imien);
	uk_pr_debug("    FMS: 0x%08x\n", snp_sp->fms);
	//uk_sev_cpuid_get_fms();
	uk_pr_debug("Contents in SVSM field:\n");
	uk_pr_debug("       SVSM Base: 0x%016lx\n", snp_sp->svsm_base);
	uk_pr_debug("       SVSM Size: 0x%016lx\n", snp_sp->svsm_size);
	uk_pr_debug("        SVSM CAA: 0x%016lx\n", snp_sp->svsm_caa);
	uk_pr_debug("SVSM Max Version: 0x%08x (%d)\n", snp_sp->svsm_max_version, snp_sp->svsm_max_version);
	uk_pr_debug(" SVSM Guest VMPL: 0x%02x (%d)\n", snp_sp->svsm_guest_vmpl, snp_sp->svsm_guest_vmpl);

	if (snp_sp->svsm_size > 0)
	{
		svsm_caa_gpa = (struct svsm_caa *)snp_sp->svsm_caa;
		svsm_caa_gpa->call_pending = 0;
		svsm_present = 1;
		//uk_pr_debug("SVSM Present: 0x%01x\n", uk_sev_svsm_present());

		uk_pr_debug("Contents in CAA area starting from 0x%016lx:\n", (__u64)svsm_caa_gpa);
		uk_pr_debug(" Call Pending: 0x%02x\n", svsm_caa_gpa->call_pending);
		uk_pr_debug("Mem Available: 0x%02x\n", svsm_caa_gpa->mem_available);
	}
	else
	{
		uk_pr_info("No SVSM module found.\n");
	}

	uk_pr_debug("GHCB information:\n");
	uk_pr_debug("GHCB Address: 0x%016lx\n", (__u64)&ghcb_page);
	uk_pr_debug("   GHCB Size: 0x%016lx (%ld)\n", sizeof(ghcb_page), sizeof(ghcb_page));

	return 0;
}

int uk_sev_write_caa_pending(__u8 val)
{
	svsm_caa_gpa->call_pending = val;

	return 0;
}

#define VMGEXIT_INST "rep; vmmcall;\n\t"

int __svsm_msr_protocol(__u64 function, __u64 rcx, __u64 rdx, __u64 r8, __u64 r9)
{
	volatile __u64 msr_original, msr_new, msr_resp, msr_value;
	volatile __u64 _rax, _rcx, _rdx, _r8, _r9;
	volatile __u8 pending;
	volatile __u64 reta = 0xffffffff, retc = 0xffffffff;

	uk_debug_beacon();
	_rax = function;
	_rcx = rcx;
	_rdx = rdx;
	_r8 = r8;
	_r9 = r9;

	/* 
	 * GHCB Run at VMPL Request/Response
	 * VMPL = 0
	 */
	msr_original = uk_sev_ghcb_rdmsrl();
	msr_value = 0x16;
	uk_sev_ghcb_wrmsrl(msr_value);
	msr_new = uk_sev_ghcb_rdmsrl();

	uk_pr_debug("Now calling SVSM core protocol %d\n", _rax);
	uk_pr_debug(" msr_original: 0x%016lx\n", msr_original);
	uk_pr_debug("      msr_new: 0x%016lx\n", msr_new);
	uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", (__u64)svsm_caa_gpa);
	uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);
	uk_pr_debug("          rax: 0x%016lx\n", _rax);
	uk_pr_debug("          rcx: 0x%016lx\n", _rcx);

	asm volatile("mov %4, %%r8\n\t"
		     "mov %5, %%r9\n\t"
		     "movb $1, %7\n\t"
		     VMGEXIT_INST
		     : "=a" (reta), "=c" (retc)
		     : "a" (_rax), "c" (_rcx), "d" (_rdx), "r" (_r8), "r" (_r9), "m" (svsm_caa_gpa->call_pending)
		     : "r8", "r9");

	msr_resp = uk_sev_ghcb_rdmsrl();
	
	uk_pr_debug("Result of calling SVSM protocol\n");
	uk_pr_debug("     msr_resp: 0x%016lx\n", msr_resp);
	uk_pr_debug("    ret (rax): 0x%016lx\n", reta);
	uk_pr_debug("          rcx: 0x%016lx\n", retc);
	uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", (__u64)svsm_caa_gpa);
	uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);

	uk_sev_ghcb_wrmsrl(msr_original);
	pending = 0;
	asm volatile("xchgb %0, %1" : "+r" (pending) : "m" (svsm_caa_gpa->call_pending) : "memory");
	if (pending)
		reta = -EINVAL;

	if (msr_resp != 0x17)
		reta = -EINVAL;

	// if (GHCB_MSR_VMPL_RESP_VAL(msr_resp) != 0)
	// 	reta = -EINVAL;

	return reta;
}

void *uk_sev_svsm_caa_buffer(void)
{
	// struct svsm_temp_print_call *temp_print_call_entry = svsm_caa_gpa->svsm_buffer;
	return svsm_caa_gpa->svsm_buffer;
}

int uk_sev_svsm_core_pvalidate_msr(__u64 vaddr, __u64 rmp_psize, __u64 validate)
{
	struct svsm_pvalidate_call *svsm_call;
	struct svsm_caa *svsm_caa;
	volatile __u64 function;
	volatile __u64 svsm_call_paddr;

	struct snp_secrets_page_layout *snp_sp;
	volatile __u64 rax, rcx, rdx, r8, r9;
	volatile __u64 msr_value, msr_original, msr_resp;
	volatile __u64 ret = 0xffffffff;

	uk_debug_beacon();
	svsm_caa = (struct svsm_caa *)svsm_caa_gpa;
	svsm_call = (struct svsm_pvalidate_call *)svsm_caa->svsm_buffer;
	svsm_call_paddr = (__u64)ukplat_virt_to_phys(svsm_call);

	// uk_pr_debug("         svsm_caa_gpa: 0x%016lx\n", svsm_caa_gpa);
	// uk_pr_debug("             svsm_caa: 0x%016lx\n", svsm_caa);
	// uk_pr_debug("svsm_caa->svsm_buffer: 0x%016lx\n", svsm_caa->svsm_buffer);
	// uk_pr_debug("            svsm_call: 0x%016lx\n", svsm_call);
	// uk_pr_debug("      svsm_call_paddr: 0x%016lx\n", svsm_call_paddr);

	svsm_call->entries = 1;
	svsm_call->next    = 0;
	svsm_call->entry[0].page_size = rmp_psize;
	svsm_call->entry[0].action    = validate;
	svsm_call->entry[0].ignore_cf = 0;
	svsm_call->entry[0].pfn       = ukplat_virt_to_phys(vaddr) >> PAGE_SHIFT;

	// uk_pr_debug("  entries: 0x%08x (%d)\n", svsm_call->entries, svsm_call->entries);
	// uk_pr_debug("     next: 0x%08x (%d)\n", svsm_call->next, svsm_call->next);
	// uk_pr_debug("page_size: 0x%08lx (%d)\n", svsm_call->entry[0].page_size, svsm_call->entry[0].page_size);
	// uk_pr_debug("   action: 0x%08lx (%d)\n", svsm_call->entry[0].action, svsm_call->entry[0].action);
	// uk_pr_debug("ignore_cf: 0x%08lx (%d)\n", svsm_call->entry[0].ignore_cf, svsm_call->entry[0].ignore_cf);
	// uk_pr_debug("      pfn: 0x%016lx (%d)\n", svsm_call->entry[0].pfn, svsm_call->entry[0].pfn);

	/*
	 * SVSM_CORE_PVALIDATE call:
	 *   RAX = 0x1 (Protocol=0, CallID=1)
	 *   RCX = gPA of the list of requested operations
	 */
	rax = SVSM_CALL_INDENTIFIER(SVSM_CORE_PROTOCOL, SVSM_CORE_PVALIDATE);
	rcx = svsm_call_paddr;
	rdx = 0;
	r8 = 0;
	r9 = 0;
	ret = 0;

	// uk_debug_beacon();
	// return __svsm_msr_protocol(function, (__u64)svsm_call, 0, 0, 0);

	/* 
	 * GHCB Run at VMPL Request/Response
	 * VMPL = 0
	 */
	msr_value = 0x16; 
	msr_original = uk_sev_ghcb_rdmsrl();

	// uk_pr_debug("Now calling SVSM protocol SVSM_CORE_PVALIDATE\n");
	// uk_pr_debug(" msr_original: 0x%016lx\n", msr_original);
	// uk_pr_debug("    msr_value: 0x%016lx\n", msr_value);
	// uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", svsm_caa_gpa);
	// uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);
	// uk_pr_debug("          rax: 0x%016lx\n", rax);
	// uk_pr_debug("          rcx: 0x%016lx\n", rcx);

	uk_sev_ghcb_wrmsrl(msr_value);

	asm volatile("mov %4, %%r8\n\t"
		     "mov %5, %%r9\n\t"
		     "movb $1, %6\n\t"
		     VMGEXIT_INST
		     : "=a" (ret)
		     : "a" (rax), "c" (rcx), "d" (rdx), "r" (r8), "r" (r9), "m" (svsm_caa_gpa->call_pending)
		     : "r8", "r9");
	
	msr_resp = uk_sev_ghcb_rdmsrl();
	uk_sev_ghcb_wrmsrl(msr_original);

	uk_pr_debug("Result of calling SVSM protocol SVSM_CORE_PVALIDATE\n");
	uk_pr_debug("     msr_resp: 0x%016lx\n", msr_resp);
	uk_pr_debug("    ret (rax): 0x%016lx\n", ret);
	uk_pr_debug("          rcx: 0x%016lx\n", rcx);

	uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", svsm_caa_gpa);
	uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);

	return ret;
}


int uk_sev_svsm_core_remap_ca_msr(__u64 pa)
{
	static struct svsm_caa *old_caa;
	struct snp_secrets_page_layout *snp_sp;
	volatile __u64 rax, rcx, rdx, r8, r9;
	volatile __u64 msr_value, msr_original, msr_resp;
	volatile __u64 ret = 0xffffffff;

	/*
	 * SVSM_CORE_REMAP_CA call:
	 *   RAX = 0 (Protocol=0, CallID=0)
	 *   RCX = New CAA GPA
	 *   RDX = 0
	 */
	old_caa = svsm_caa_gpa;
	rax = SVSM_CALL_INDENTIFIER(SVSM_CORE_PROTOCOL, SVSM_CORE_REMAP_CA);
	rcx = pa;
	rdx = 0;
	r8 = 0;
	r9 = 0;
	ret = 0;

	// return __svsm_msr_protocol(rax, rcx, 0, 0, 0);
	
	/* 
	 * GHCB Run at VMPL Request/Response
	 * VMPL = 0
	 */
	msr_value = 0x16; 
	msr_original = uk_sev_ghcb_rdmsrl();

	uk_pr_debug("Now calling SVSM protocol SVSM_CORE_REMAP_CA\n");
	uk_pr_debug(" msr_original: 0x%016lx\n", msr_original);
	uk_pr_debug("    msr_value: 0x%016lx\n", msr_value);
	uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", svsm_caa_gpa);
	uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);
	uk_pr_debug("          rax: 0x%016lx\n", rax);
	uk_pr_debug("          rcx: 0x%016lx\n", rcx);

	uk_sev_ghcb_wrmsrl(msr_value);

	asm volatile("mov %4, %%r8\n\t"
		     "mov %5, %%r9\n\t"
		     "movb $1, %6\n\t"
		     VMGEXIT_INST
		     : "=a" (ret)
		     : "a" (rax), "c" (rcx), "d" (rdx), "r" (r8), "r" (r9), "m" (svsm_caa_gpa->call_pending)
		     : "r8", "r9");
	
	msr_resp = uk_sev_ghcb_rdmsrl();
	if (msr_resp == 0x17 && ret == 0x0)
	{
		svsm_caa_gpa = (struct svsm_caa *)rcx;
	}

	uk_sev_ghcb_wrmsrl(msr_original);

	uk_pr_debug("Result of calling SVSM protocol SVSM_CORE_REMAP_CA\n");
	uk_pr_debug("     msr_resp: 0x%016lx\n", msr_resp);
	uk_pr_debug("    ret (rax): 0x%016lx\n", ret);
	uk_pr_debug("          rcx: 0x%016lx\n", rcx);

	uk_pr_debug("      old_caa: 0x%016lx\n", old_caa);
	uk_pr_debug(" call_pending: 0x%02x\n", old_caa->call_pending);
	uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", svsm_caa_gpa);
	uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);

	return 0;
}


int uk_sev_svsm_custom_make_page_msr(
	__u64 pt_kernel, __u64 va, __u64 pa, __u64 pages, 
	__u64 attr, __u64 flags, __u64 pte_num)
{
	volatile __u64 rax, rcx, rdx, r8, r9;
	volatile __u64 msr_value, msr_original, msr_resp;
	volatile __u64 ret = 0xffffffff, retc = 0xffffffff;
	volatile struct svsm_make_page_call *mp_entry;

	/*
	 * SVSM_CORE_REMAP_CA call:
	 *   RAX = 0x10 (Protocol=0, CallID=16)
	 *   RCX = GPA
	 *   RDX = 0
	 */
	rax = SVSM_CALL_INDENTIFIER(SVSM_CORE_PROTOCOL, SVSM_CUSTOM_MAKE_PAGE);
	rcx = svsm_caa_gpa->svsm_buffer;
	rdx = 0;
	r8 = 0;
	r9 = 0;
	ret = 0;

	mp_entry = svsm_caa_gpa->svsm_buffer;
	mp_entry->pt_kernel = pt_kernel;
	mp_entry->va = va;
	mp_entry->pa = pa;
	mp_entry->pages = pages;
	mp_entry->attr = attr;
	mp_entry->flags = flags;
	mp_entry->pte_num = pte_num;
	
	/* 
	 * GHCB Run at VMPL Request/Response
	 * VMPL = 0
	 */
	msr_value = 0x16; 
	msr_original = uk_sev_ghcb_rdmsrl();

	uk_pr_debug("Now calling SVSM protocol SVSM_CUSTOM_MAKE_PAGE\n");
	uk_pr_debug(" msr_original: 0x%016lx\n", msr_original);
	uk_pr_debug("    msr_value: 0x%016lx\n", msr_value);
	uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", svsm_caa_gpa);
	uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);
	uk_pr_debug("          rax: 0x%016lx\n", rax);
	uk_pr_debug("          rcx: 0x%016lx\n", rcx);

	uk_sev_ghcb_wrmsrl(msr_value);

	asm volatile("mov %5, %%r8\n\t"
		     "mov %6, %%r9\n\t"
		     "movb $1, %7\n\t"
		     VMGEXIT_INST
		     : "=a" (ret), "=c" (retc)
		     : "a" (rax), "c" (rcx), "d" (rdx), "r" (r8), "r" (r9), "m" (svsm_caa_gpa->call_pending)
		     : "r8", "r9");
	
	msr_resp = uk_sev_ghcb_rdmsrl();
	uk_sev_ghcb_wrmsrl(msr_original);

	uk_pr_debug("Result of calling SVSM protocol SVSM_CUSTOM_MAKE_PAGE\n");
	uk_pr_debug("     msr_resp: 0x%016lx\n", msr_resp);
	uk_pr_debug("    ret (rax): 0x%016lx\n", ret);
	uk_pr_debug("          rcx: 0x%016lx\n", retc);
	uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", svsm_caa_gpa);
	uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);

	return 0;
}


int uk_sev_svsm_custom_temp_print_msr(void)
{
	volatile __u64 rax, rcx, rdx, r8, r9;
	volatile __u64 msr_value, msr_original, msr_resp;
	volatile __u64 ret = 0xffffffff, retc = 0xffffffff;
	struct svsm_temp_print_call *temp_print_call_entry;

	/*
	 * SVSM_CORE_REMAP_CA call:
	 *   RAX = 0x10 (Protocol=0, CallID=16)
	 *   RCX = GPA
	 *   RDX = 0
	 */
	rax = SVSM_CALL_INDENTIFIER(SVSM_CORE_PROTOCOL, SVSM_CUSTOM_TEMP_PRINT);
	rcx = svsm_caa_gpa->svsm_buffer;
	rdx = 0;
	r8 = 0;
	r9 = 0;
	ret = 0;

	// uk_pr_info("str_len %d str '%s' at %016x\n", 
	// 	rdx, svsm_caa_gpa->svsm_buffer, svsm_caa_gpa->svsm_buffer);

	// return __svsm_msr_protocol(rax, rcx, 0, 0, 0);
	
	/* 
	 * GHCB Run at VMPL Request/Response
	 * VMPL = 0
	 */
	msr_value = 0x16; 
	msr_original = uk_sev_ghcb_rdmsrl();

	// uk_pr_debug("Now calling SVSM protocol SVSM_CUSTOM_TEMP_PRINT\n");
	// uk_pr_debug(" svsm_caa_gpa: 0x%016lx\n", svsm_caa_gpa);
	// uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);
	// uk_pr_debug("          rax: 0x%016lx\n", rax);
	// uk_pr_debug("          rcx: 0x%016lx\n", rcx);

	uk_sev_ghcb_wrmsrl(msr_value);

	asm volatile("mov %5, %%r8\n\t"
		     "mov %6, %%r9\n\t"
		     "movb $1, %7\n\t"
		     VMGEXIT_INST
		     : "=a" (ret), "=c" (retc)
		     : "a" (rax), "c" (rcx), "d" (rdx), "r" (r8), "r" (r9), "m" (svsm_caa_gpa->call_pending)
		     : "r8", "r9");
	
	msr_resp = uk_sev_ghcb_rdmsrl();
	uk_sev_ghcb_wrmsrl(msr_original);

	// uk_pr_debug("Result of calling SVSM protocol SVSM_CUSTOM_TEMP_PRINT\n");
	// uk_pr_debug("     msr_resp: 0x%016lx\n", msr_resp);
	// uk_pr_debug("    ret (rax): 0x%016lx\n", ret);
	// uk_pr_debug("          rcx: 0x%016lx\n", retc);
	// uk_pr_debug(" call_pending: 0x%02x\n", svsm_caa_gpa->call_pending);

	return 0;
}