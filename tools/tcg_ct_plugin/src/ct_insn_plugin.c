/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * pqcp_ct_insn - QEMU TCG plugin that counts guest instructions and guest
 * memory accesses executed between two marker addresses.
 *
 * The firmware brackets a measured region with two no-inline marker
 * functions whose guest addresses are resolved from the ELF symbol table by
 * the runner and passed here as begin=/end= plugin arguments. Counting
 * toggles on when the instruction at `begin` executes and off at `end`; each
 * completed region is written to the outfile as
 *
 *     PQCP_CT_INSN region=<n> insns=<count> loads=<count> stores=<count>
 *
 * Equal instruction counts prove the control flow is input-independent at
 * instruction granularity; equal load/store counts additionally prove the
 * *number* of data memory operations is input-independent. This is one rung
 * stronger than wall-clock cycles and one rung stronger than instruction
 * counts alone. It is still not a formal CT proof - which ADDRESSES are
 * accessed, and microarchitectural timing, remain out of scope - and the
 * project does not claim otherwise.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t begin_addr;
static uint64_t end_addr;
static FILE *out_file;
static int counting;
static uint64_t region_insns;
static uint64_t region_loads;
static uint64_t region_stores;
static uint64_t region_index;

static void emit_region(void)
{
	if (out_file != NULL) {
		fprintf(out_file,
			"PQCP_CT_INSN region=%" PRIu64 " insns=%" PRIu64
			" loads=%" PRIu64 " stores=%" PRIu64 "\n",
			region_index, region_insns, region_loads,
			region_stores);
		fflush(out_file);
	}
	region_index++;
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
	const uint64_t vaddr = (uint64_t)(uintptr_t)udata;

	(void)cpu_index;

	if (vaddr == begin_addr) {
		counting = 1;
		region_insns = 0U;
		region_loads = 0U;
		region_stores = 0U;
		return;
	}
	if (vaddr == end_addr) {
		if (counting) {
			counting = 0;
			emit_region();
		}
		return;
	}
	if (counting) {
		region_insns++;
	}
}

static void vcpu_mem_access(unsigned int cpu_index,
			    qemu_plugin_meminfo_t info, uint64_t vaddr,
			    void *udata)
{
	(void)cpu_index;
	(void)vaddr;
	(void)udata;

	if (!counting) {
		return;
	}
	if (qemu_plugin_mem_is_store(info)) {
		region_stores++;
	} else {
		region_loads++;
	}
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	size_t n = qemu_plugin_tb_n_insns(tb);

	(void)id;
	for (size_t i = 0U; i < n; ++i) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		uint64_t vaddr = qemu_plugin_insn_vaddr(insn);

		qemu_plugin_register_vcpu_insn_exec_cb(
			insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS,
			(void *)(uintptr_t)vaddr);
		qemu_plugin_register_vcpu_mem_cb(
			insn, vcpu_mem_access, QEMU_PLUGIN_CB_NO_REGS,
			QEMU_PLUGIN_MEM_RW, NULL);
	}
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
	(void)id;
	(void)p;
	if (out_file != NULL) {
		fprintf(out_file, "PQCP_CT_INSN done regions=%" PRIu64 "\n",
			region_index);
		fflush(out_file);
		if (out_file != stderr) {
			(void)fclose(out_file);
		}
		out_file = NULL;
	}
}

static uint64_t parse_addr(const char *value)
{
	return (uint64_t)strtoull(value, NULL, 0);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
					   const qemu_info_t *info,
					   int argc, char **argv)
{
	const char *outfile_path = NULL;

	(void)info;

	for (int i = 0; i < argc; ++i) {
		if (strncmp(argv[i], "begin=", strlen("begin=")) == 0) {
			begin_addr = parse_addr(argv[i] + strlen("begin="));
		} else if (strncmp(argv[i], "end=", strlen("end=")) == 0) {
			end_addr = parse_addr(argv[i] + strlen("end="));
		} else if (strncmp(argv[i], "outfile=",
				   strlen("outfile=")) == 0) {
			outfile_path = argv[i] + strlen("outfile=");
		}
	}

	if (begin_addr == 0U || end_addr == 0U) {
		fprintf(stderr,
			"pqcp_ct_insn: begin= and end= arguments are required\n");
		return -1;
	}

	out_file = outfile_path != NULL ? fopen(outfile_path, "w") : stderr;
	if (out_file == NULL) {
		fprintf(stderr, "pqcp_ct_insn: cannot open outfile %s\n",
			outfile_path);
		return -1;
	}

	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
	return 0;
}
