/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 LG Electronics */

#include "lua_state.h"
// #include "skynet.h"
#include "profile.h"
#include "maps.bpf.h"

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool disable_lua_user_trace = false;
const volatile bool include_idle = false;
const volatile pid_t targ_pid = -1;
const volatile uint32_t handle_id = 0;
const volatile int frame_depth = 15;

#define MAX_ENTRIES 10240


struct
{
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct stack_key);
	__type(value, sizeof(u64));
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");


// for collecting lua stack trace function name
// and pass the pointer of Lua_state to perf event
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct lua_stack_event);
} lua_events SEC(".maps");

// output the lua stack to user space because we cannot keep all of them in
// ebpf maps
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} lua_event_output SEC(".maps");

/*
 * If PAGE_OFFSET macro is not available in vmlinux.h, determine ip whose MSB
 * (Most Significant Bit) is 1 as the kernel address.
 * TODO: use end address of user space to determine the address space of ip
 */
#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86)
#define BITS_PER_ADDR (64)
#define MSB_SET_ULONG (1UL << (BITS_PER_ADDR - 1))
static __always_inline bool is_kernel_addr(u64 addr)
{
	return !!(addr & MSB_SET_ULONG);
}
#else
static __always_inline bool is_kernel_addr(u64 addr)
{
	return false;
}
#endif /* __TARGET_ARCH_arm64 || __TARGET_ARCH_x86 */



static int
lua_get_funcdata(struct bpf_perf_event_data *ctx, CallInfo *ci,  int level, struct lua_stack_event *eventp) {
	StkId func = BPF_PROBE_READ_USER(ci, func);
	TValue val = BPF_PROBE_READ_USER(func, val);
	lu_byte tt = BPF_PROBE_READ_USER(&val, tt_);

	if(tt == LUA_VLCL || tt == LUA_VCCL) {
		Closure *cl = clvalue(&val);
		if (!cl) {
            return -1;
        }

		if (tt == LUA_VLCL) {
			// lua closure
			
			LClosure l = BPF_PROBE_READ_USER(cl, l);
			struct Proto *p = BPF_PROBE_READ_USER(&l, p);
			TString  *source = BPF_PROBE_READ_USER(p, source);
			const char *contents = BPF_PROBE_READ_USER(source, contents);

			Instruction *code = BPF_PROBE_READ_USER(p, code);
			const Instruction *savedpc = BPF_PROBE_READ_USER(ci, u.l.savedpc);
			int pc = savedpc - code - 1;

			ls_byte *lineinfo = BPF_PROBE_READ_USER(p, lineinfo);
			// ls_byte line = BPF_PROBE_READ_USER(lineinfo, pc);

			memcmp(eventp->name, contents, sizeof(eventp->name));
			eventp->type = FUNC_TYPE_LC;
			eventp->line = 1;

			// bpf_printk("level= %d, fn_name=%s\n", level, eventp->name);
		}
		else if (tt == LUA_VCCL) {
			// c closure
			CClosure c = BPF_PROBE_READ_USER(cl, c);
			eventp->type = FUNC_TYPE_CC;
			eventp->funcp = BPF_PROBE_READ_USER(&c, f);;
		} else {
			return -1;
		}
	}
	
      if (tt == LUA_VLCF) {
        // light c function
		Value v = BPF_PROBE_READ_USER(&val, value_);
		eventp->type = FUNC_TYPE_CF;
		eventp->funcp = BPF_PROBE_READ_USER(&v, f);
      }else {
		return -1;
	}

	eventp->level = level;
	bpf_perf_event_output(ctx, &lua_event_output, bpf_get_smp_processor_id(), eventp, sizeof(*eventp));
	// bpf_perf_event_output(ctx, &lua_event_output, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
	return 0;
}

static int
fix_lua_stack(struct bpf_perf_event_data *ctx, __u32 tid, int stack_id) {
	if (stack_id == 0){
		return 0;
	}

	struct lua_stack_event * eventp;
	eventp = bpf_map_lookup_elem(&lua_events, &tid);
	if (!eventp) {
		return 0;
	}

	eventp->user_stack_id = stack_id;
	lua_State *L = eventp->L;
	if (!L) {
		return 0;
	}

	// start from the top of the stack and trace back
	// count the number of function calls founded
	int level = 0;

	CallInfo *ci = BPF_PROBE_READ_USER(L, ci);

	// if(handle_id > 0) {
	// 	int idx = 1;
	// 	if(idx <= s2v(ci->func)->)
	// 	struct skynet_context * context = lua_touserdata(event.L, lua_upvalueindex(1));
	// 	if(context->handle != handle_id) {
	// 		return 0;
	// 	}
	// }

	// CallInfo base_ci = BPF_PROBE_READ_USER(L, base_ci);

	// for the ebpf verifier insns (limit 1000000), we need to limit the max loop times to 13
	int i=0;
	for (; i < frame_depth; i++) {
		StkId func = BPF_PROBE_READ_USER(ci, func);
		if(func) {
			if (lua_get_funcdata(ctx, ci, level, eventp) == 0) {
				level++;
			}
		}
		ci = BPF_PROBE_READ_USER(ci, previous);
	}

	return 0;
}

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	bpf_printk("skynet do_perf_event\n");

	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = id;
	__u64 *valp;
	static const __u64 zero;
	struct stack_key key = {};

	if (targ_pid != -1 && targ_pid != pid)
		return 0;


	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));

	if (user_stacks_only) {
		key.kern_stack_id = -1;
	}
	else {
		key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, 0);
	}

	if (kernel_stacks_only) {
		key.user_stack_id = -1;
	}
	else {
		key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, BPF_F_USER_STACK);
	}

	if (key.kern_stack_id >= 0) {
		// populate extras to fix the kernel stack
		__u64 ip = PT_REGS_IP(&ctx->regs);

		if (is_kernel_addr(ip)) {
			key.kernel_ip = ip;
		}
	}

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp) {
		__sync_fetch_and_add(valp, 1);
	}

	if (!disable_lua_user_trace && (!valp || *valp <= 1))
	{
		fix_lua_stack(ctx, tid, key.user_stack_id);
	}
	return 0;
}

SEC("uprobe/handle_entry_lua_cancel")
int handle_entry_lua_cancel(struct pt_regs *ctx) {
	bpf_printk("skynet probe_entry_lua_cancel\n");

	if (!PT_REGS_PARM2(ctx))
		return 0;
	if (!PT_REGS_PARM4(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (targ_pid != -1 && targ_pid != pid)
		return 0;
	bpf_map_delete_elem(&lua_events, &tid);
	return 0;
}

SEC("uprobe/handle_entry_lua")
int handle_entry_lua(struct pt_regs *ctx) {
	bpf_printk("skynet probe_entry_lua\n");

	if (!PT_REGS_PARM1(ctx)) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct lua_stack_event event = {};

	if (targ_pid != -1 && targ_pid != pid) {
		return 0;
	}

	event.pid = pid;
	event.L = (void *)PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&lua_events, &tid, &event, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
