/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_SEV_H__
#define __UK_SEV_H__

#include <uk/arch/lcpu.h>
#include <uk/asm/sev.h>

/* Macros for handling IOIO */
/* exitinfo1[31:16]: I/O port */
#define UK_SEV_IOIO_PORT(port)		(((port) & (UK_BIT(16) - 1)) << 16)
/* exitinfo1[12:10]: Segment selector */
#define UK_SEV_IOIO_SEG(seg)		(((seg) & (UK_BIT(3) - 1)) << 10)
#define UK_SEV_IOIO_SEG_ES		0
#define UK_SEV_IOIO_SEG_DS		3
#define UK_SEV_IOIO_A64			UK_BIT(9)
#define UK_SEV_IOIO_A32 		UK_BIT(8)
#define UK_SEV_IOIO_A16 		UK_BIT(7)
#define UK_SEV_IOIO_SZ32		UK_BIT(6)
#define UK_SEV_IOIO_SZ16 		UK_BIT(5)
#define UK_SEV_IOIO_SZ8			UK_BIT(4)
#define UK_SEV_IOIO_REP 		UK_BIT(3)
#define UK_SEV_IOIO_STR 		UK_BIT(2)
#define UK_SEV_IOIO_TYPE_OUT		0
#define UK_SEV_IOIO_TYPE_IN		UK_BIT(0)


int uk_sev_mem_encrypt_init(void);
int uk_sev_early_vc_handler_init(void);

int uk_sev_setup_ghcb(void);
void uk_sev_terminate(int set, int reason);
int uk_sev_ghcb_initialized(void);
int uk_sev_cpu_features_check(void);
int uk_sev_set_memory_private(__vaddr_t addr, unsigned long num_pages);
int uk_sev_set_memory_shared(__vaddr_t addr, unsigned long num_pages);

int uk_sev_set_pages_state(__vaddr_t vstart, __paddr_t pstart, unsigned long num_pages,
			   int page_state);

/* The #VC handler executed before a proper GHCB is set up. Only supports CPUID
 * #VC triggered by CPUID calls. */
int do_vmm_comm_exception_no_ghcb(struct __regs *regs,
				   unsigned long error_code);
void do_vmm_comm_exception(struct __regs *regs, unsigned long error_code);
void uk_sev_terminate(int set, int reason);

int uk_sev_svsm_discover(__u64 efi_st);
int uk_sev_svsm_core_pvalidate_msr(__u64 paddr, __u64 rmp_psize, __u64 validate);
int uk_sev_svsm_core_remap_ca_msr(__u64 pa);
int uk_sev_svsm_custom_make_page_msr(
	__u64 pt_kernel, __u64 va, __u64 pa, __u64 pages, 
	__u64 attr, __u64 flags, __u64 pte_num);
void *uk_sev_svsm_caa_buffer(void);
int uk_sev_svsm_custom_temp_print_msr(void);

/*
 * The secrets page contains 96-bytes of reserved field that can be used by
 * the guest OS. The guest OS uses the area to save the message sequence
 * number for each VMPCK.
 *
 * See the GHCB spec section Secret page layout for the format for this area.
 */
struct secrets_os_area {
	__u32 msg_seqno_0;
	__u32 msg_seqno_1;
	__u32 msg_seqno_2;
	__u32 msg_seqno_3;
	__u64 ap_jump_table_pa;
	__u8 rsvd[40];
	__u8 guest_usage[32];
} __packed;

#define VMPCK_KEY_LEN		32

/* See the SNP spec version 0.9 for secrets page format */
struct snp_secrets_page_layout {
	__u32 version;
	__u32 imien	: 1,
	    rsvd1	: 31;
	__u32 fms;
	__u32 rsvd2;
	__u8 gosvw[16];
	__u8 vmpck0[VMPCK_KEY_LEN];
	__u8 vmpck1[VMPCK_KEY_LEN];
	__u8 vmpck2[VMPCK_KEY_LEN];
	__u8 vmpck3[VMPCK_KEY_LEN];
	struct secrets_os_area os_area;

	__u8 vmsa_tweak_bitmap[64];

	/* SVSM fields */
	__u64 svsm_base;
	__u64 svsm_size;
	__u64 svsm_caa;
	__u32 svsm_max_version;
	__u8 svsm_guest_vmpl;
	__u8 rsvd3[3];

	/* Remainder of page */
	__u8 rsvd4[3744];
} __packed;

#define PAGE_SIZE				0x1000UL
#define MAX_SVSM_BUFFER_SIZE	PAGE_SIZE - 8

/*
 * The SVSM CAA related structures.
 */
struct svsm_caa {
	__u8 call_pending;
	__u8 mem_available;
	__u8 rsvd1[6];

	__u8 svsm_buffer[MAX_SVSM_BUFFER_SIZE];
};

/*
 * The SVSM PVALIDATE related structures
 */
struct svsm_pvalidate_entry {
	__u64 page_size	: 2,
	    action		: 1,
	    ignore_cf	: 1,
	    rsvd		: 8,
	    pfn			: 52;
};

struct svsm_pvalidate_call {
	__u16 entries;
	__u16 next;

	__u8 rsvd1[4];

	struct svsm_pvalidate_entry entry[];
};


struct svsm_temp_print_call {
	__u32 str_len;
	char str_ptr[];
};

// __u64 pt_kernel, __u64 va, __u64 pa, __u64 pages, __u64 attr, __u64 flags

struct svsm_make_page_call {
	__u64 pt_kernel;
	__u64 va;
	__u64 pa;
	__u64 pages;
	__u64 attr;
	__u64 flags;
	__u64 pte_num;
};

struct svsm_make_page_pte_entry {
	__u64 pt_paddr;
	__u32 lvl;
	__u32 idx;
	__u64 pte;
};

#define PTE_BATCH_ENTRY_MAX ((MAX_SVSM_BUFFER_SIZE - sizeof(struct svsm_make_page_call)) / sizeof(struct svsm_make_page_pte_entry))

union sev_svsm_calling_rax
{
	__u64 value;
	struct {
		__u32 call_identifier;
		__u32 protocol;
	};
};

//#define EFI_CC_BLOB_GUID			EFI_GUID(0x067b1f5f, 0xcf26, 0x44c5, 0x85, 0x54, 0x93, 0xd7, 0x77, 0x91, 0x2d, 0x42)
#define UK_EFI_CC_BLOB_GUID					\
	(&(struct uk_efi_guid){					\
		.b0_3 = 0x067b1f5f,					\
		.b4_5 = 0xcf26,						\
		.b6_7 = 0x44c5,						\
		.b8_15 = {0x85, 0x54, 0x93, 0xd7,   \
			  0x77, 0x91, 0x2d, 0x42},		\
	})


#define CC_BLOB_SEV_HDR_MAGIC	0x45444d41
struct uk_efi_cc_blob_tbl {
	__u32 magic;
	__u16 version;
	__u16 reserved;
	__u64 secrets_phys;
	__u32 secrets_len;
	__u32 rsvd1;
	__u64 cpuid_phys;
	__u32 cpuid_len;
	__u32 rsvd2;
};

#define SVSM_CALL_INDENTIFIER(protocol, call) ((protocol << 32) | call)

#define SVSM_CORE_PROTOCOL			0x0
#define SVSM_ATTESTATION_PROTOCOL	0x1
#define SVSM_VTPM_PROTOCOL			0x2

#define SVSM_CORE_REMAP_CA			0x0
#define SVSM_CORE_PVALIDATE			0x1
#define SVSM_CORE_CREATE_VCPU		0x2
#define SVSM_CORE_DELETE_VCPU		0x3
#define SVSM_CORE_DEPOSIT_MEM		0x4
#define SVSM_CORE_WITHDRAW_MEM		0x5
#define SVSM_CORE_QUERY_PROTOCOL	0x6
#define SVSM_CORE_CONFIGURE_VTOM	0x7

#define SVSM_CUSTOM_MAKE_PAGE		0x10

#define SVSM_CUSTOM_TEMP_PRINT		0x20

#endif /* __UK_SEV_H__ */
