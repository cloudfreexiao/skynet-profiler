/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Copyright (c) 2022 LG Electronics
 *
 * Based on profile(8) from BCC by Brendan Gregg.
 * 28-Dec-2021 Eunseon Lee Created this,
 * 17-Jul-2022 Yusheng Zheng modified this.
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "profile.h"
#include "lua_stacks_map.h"
#include "profile.skel.h"
#include "stack_printer.h"

extern "C"
{
#include "trace_helpers.h"
#include "uprobe_helpers.h"
}

bool exiting = false;
class lua_stack_map lua_bt_map;

#define warn(...) fprintf(stderr, __VA_ARGS__)

struct profile_env env = {
	.pid = -1,
	.handle_id = 0,
	.stack_storage_size = 1024 * 20,
	.perf_max_stack_depth = 127,
	.duration = 3,
	.freq = 1,
	.sample_freq = 49,
	.cpu = -1,
	.frame_depth = 15
};

#define UPROBE_SIZE 3

const char *argp_program_version = "profile 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Profile CPU usage by sampling stack traces at a timed interval.\n"
	"\n"
	"USAGE: profile [OPTIONS...] [duration]\n"
	"EXAMPLES:\n"
	"    profile             # profile stack traces at 49 Hertz until Ctrl-C\n"
	"    profile -F 99       # profile stack traces at 99 Hertz\n"
	"    profile -c 1000000  # profile stack traces every 1 in a million events\n"
	"    profile 5           # profile at 49 Hertz for 5 seconds only\n"
	"    profile -f          # output in folded format for flame graphs\n"
	"    profile -p 185      # only profile process with PID 185\n"
	"    profile -U          # only show user space stacks (no kernel)\n"
	"    profile -K          # only show kernel space stacks (no user)\n";

#define OPT_PERF_MAX_STACK_DEPTH 1	 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE 2	 /* --stack-storage-size */
#define OPT_LUA_USER_STACK_ONLY 3	 /* --lua-user-stacks-only */
#define OPT_DISABLE_LUA_USER_TRACE 4 /* --disable-lua-user-trace */
#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "profile process with this PID only"},
	{"handle_id", 'S', "ServiceId", 0, "profile servicewith this handle_id only"},
	{"user-stacks-only", 'U', NULL, 0,
	 "show stacks from user space only (no kernel space stacks)"},
	{"kernel-stacks-only", 'K', NULL, 0,
	 "show stacks from kernel space only (no user space stacks)"},
	{"lua-user-stacks-only", OPT_LUA_USER_STACK_ONLY, NULL, 0,
	 "replace user stacks with lua stack traces (no other user space stacks)"},
	{"disable-lua-user-trace", OPT_DISABLE_LUA_USER_TRACE, NULL, 0,
	 "disable lua user space stack trace"},
	{"frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz"},
	{"delimited", 'd', NULL, 0, "insert delimiter between kernel/user stacks"},
	{"include-idle ", 'I', NULL, 0, "include CPU idle stacks"},
	{"folded", 'f', NULL, 0, "output folded format, one line per stack (for flame graphs)"},
	{"stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	 "the number of unique stack traces that can be stored and displayed (default 1024)"},
	{"cpu", 'C', "CPU", 0, "cpu number to run profile on"},
	{"perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	 "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)"},
	{"max-frame-depth", 'D', "DEPTH", 0, "max frame depth for eBPF to travel in the stack (default 15)"},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'S':
		errno = 0;
		env.handle_id = strtol(arg, NULL, 10);
		if (errno || env.handle_id <= 0)
		{
			fprintf(stderr, "Invalid handlerid: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'U':
		env.user_stacks_only = true;
		break;
	case 'K':
		env.kernel_stacks_only = true;
		break;
	case 'F':
		errno = 0;
		env.sample_freq = strtol(arg, NULL, 10);
		if (errno || env.sample_freq <= 0)
		{
			fprintf(stderr, "invalid FREQUENCY: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'D':
		errno = 0;
		env.frame_depth = strtol(arg, NULL, 10);
		if (errno || env.frame_depth <= 0)
		{
			fprintf(stderr, "invalid FREQUENCY: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		env.delimiter = true;
		break;
	case 'I':
		env.include_idle = true;
		break;
	case 'f':
		env.folded = true;
		break;
	case 'C':
		errno = 0;
		env.cpu = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid CPU: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_LUA_USER_STACK_ONLY:
		env.lua_user_stacks_only = true;
		break;
	case OPT_DISABLE_LUA_USER_TRACE:
		env.disable_lua_user_trace = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++)
		{
			fprintf(stderr,
					"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0)
		{
			fprintf(stderr, "Invalid duration (in s): %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int num_cpus;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags) {
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static int open_and_attach_perf_event(int freq, struct bpf_program *prog, struct bpf_link *links[]) {
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.sample_freq = env.sample_freq;
	attr.freq = env.freq;

	int i, fd;

	for (i = 0; i < num_cpus; i++) {
		if (env.cpu != -1 && env.cpu != i)
			continue;

		fd = perf_event_open(&attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;

			fprintf(stderr, "failed to init perf sampling: %s\n", strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}

		fprintf(stderr, "==== successful to attach perf event on cpu: %d ====\n", i);
	}

	fprintf(stderr, "===== open_and_attach_perf_event successful.====\n");
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
	exiting = true;
}

static void handle_lua_stack_event(void *ctx, int cpu, void *data, __u32 data_sz) {
	const struct lua_stack_event *et = static_cast<const struct lua_stack_event *>(data);
	lua_bt_map.insert_lua_stack_map(et);
}

static void handle_lua_stack_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static struct bpf_link *
attach_skynet_func(const char *lua_path, const char *func_name, const bpf_program *prog) {
	off_t offset = get_elf_func_offset(lua_path, func_name);
	if (offset < 0) {
		warn("could not find %s in %s\n", func_name, lua_path);
		return NULL;
	}
	struct bpf_link *link = bpf_program__attach_uprobe(prog, false, -1, lua_path, offset);
	if (!link) {
		warn("failed to attach %s: %d\n", func_name, -errno);
		return NULL;
	}
	warn("==attach_skynet_func %s in %s ok.===\n", func_name, lua_path);
	return link;
}

static int attach_skynet_uprobes(struct profile_bpf *obj, struct bpf_link *links[]) {
	char skynet_path[124];
	if (env.pid) {
		int res = resolve_binary_path("", env.pid, skynet_path, sizeof(skynet_path));
		if (res < 0) {
			fprintf(stderr, "warning: failed to get lib path for pid %d\n", env.pid);
			return -1;
		}
	}

	links[0] = attach_skynet_func(skynet_path, "luaD_call", obj->progs.handle_entry_lua);
	if (!links[0]) {
		return -1;
	}

	links[1] = attach_skynet_func(skynet_path, "luaD_pcall", obj->progs.handle_entry_lua);
	if (!links[1]) {
		return -1;
	}

	links[2] = attach_skynet_func(skynet_path, "luaD_poscall", obj->progs.handle_entry_lua_cancel);
	if (!links[2]) {
		return -1;
	}

	// links[3] = attach_skynet_func(skynet_path, "luaB_coresume", obj->progs.handle_entry_lua);
	// if (!links[3]) {
	// 	return -1;
	// }

	// links[4] = attach_skynet_func(skynet_path, "luaB_yield", obj->progs.handle_entry_lua_cancel);
	// if (!links[4]) {
	// 	return -1;
	// }

	fprintf(stderr, "==== attach_skynet_uprobes for pid[%d] successful=====\n", env.pid);
	return 0;
}

// sudo ./profile -f -F 499 -U -v -p 46633 --lua-user-stacks-only > a.bt
// sudo ./profile -f -F 499 -U -v -p 46633 > a.bt

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;
	struct bpf_link *cpu_links[MAX_CPU_NR] = {};
	struct bpf_link *uprobe_links[UPROBE_SIZE] = {};
	struct profile_bpf *skel = nullptr;
	struct perf_buffer *pb = nullptr;
	int err, i;
	const char *stack_context = "user + kernel";
	char thread_context[64];
	char sample_context[64];

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		fprintf(stderr, "argp_parse error[%d] \n", err);
		return err;
	}

	if (env.user_stacks_only && env.kernel_stacks_only) {
		fprintf(stderr, "user_stacks_only and kernel_stacks_only cannot be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus < 0) {
		printf("failed to get # of possible cpus: '%s'!\n", strerror(-num_cpus));
		return 1;
	}
	if (num_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	skel = profile_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	skel->rodata->targ_pid = env.pid;
	skel->rodata->handle_id = env.handle_id;
	skel->rodata->user_stacks_only = env.user_stacks_only;
	skel->rodata->kernel_stacks_only = env.kernel_stacks_only;
	skel->rodata->include_idle = env.include_idle;
	skel->rodata->frame_depth = env.frame_depth;

	bpf_map__set_value_size(skel->maps.stackmap,
							env.perf_max_stack_depth * sizeof(unsigned long));

	bpf_map__set_max_entries(skel->maps.stackmap, env.stack_storage_size);

	err = profile_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		fprintf(stderr, "try decrease the max frame depth with -D and rerun with sudo?\n");
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	err = attach_skynet_uprobes(skel, uprobe_links);
	if (err < 0) {
		fprintf(stderr, "cannot found lua lib, so skip lua uprobe\n");
		env.disable_lua_user_trace = true;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.lua_event_output), PERF_BUFFER_PAGES,
						handle_lua_stack_event,
						handle_lua_stack_lost_events,
						NULL,
						NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	err = open_and_attach_perf_event(env.freq, skel->progs.do_perf_event, cpu_links);
	if (err) {
		warn("failed open_and_attach_perf_event: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	if (env.pid != -1)
		snprintf(thread_context, sizeof(thread_context), "PID %d", env.pid);
	else if (env.handle_id != 0)
		snprintf(thread_context, sizeof(thread_context), "handler_id %u", env.handle_id);
	else
		snprintf(thread_context, sizeof(thread_context), "all threads");

	snprintf(sample_context, sizeof(sample_context), "%d Hertz", env.sample_freq);

	if (env.user_stacks_only)
		stack_context = "user";
	else if (env.kernel_stacks_only)
		stack_context = "kernel";

	if (!env.folded) {
		printf("Sampling at %s of %s by %s stack", sample_context, thread_context, stack_context);
		if (env.cpu != -1)
			printf(" on CPU#%d", env.cpu);
		if (env.duration < 99999999)
			printf(" for %d secs.\n", env.duration);
		else
			printf("... Hit Ctrl-C to end.\n");
	}

	/*
	 * We'll get sleep interrupted when someone presses Ctrl-C (which will
	 * be "handled" with noop by sig_handler).
	 */
	while (!exiting) {
		// print perf event to get stack trace
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

	warn("==== print_stack_trace begin ====\n");
	print_stack_trace(ksyms, syms_cache, skel);
	warn("==== print_stack_trace end ====\n");

cleanup:
	if (env.cpu != -1) {
		bpf_link__destroy(cpu_links[env.cpu]);
	}
	else {
		for (i = 0; i < num_cpus; i++) {
			bpf_link__destroy(cpu_links[i]);
		}
	}

	for (i = 0; i < UPROBE_SIZE; i++) {
		bpf_link__destroy(uprobe_links[i]);
	}
	
	profile_bpf__destroy(skel);
	perf_buffer__free(pb);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);
	return err != 0;
}
