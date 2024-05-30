// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include "tc.skel.h"

#include "common.h"
#include "influxdb_wrapper_int.h"

#define LO_IFINDEX 2

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	MHandler_t *infh = (MHandler_t *)ctx;
	const struct event *e = data;
	int rc;

	printf("ts: %llu, flowid: %llu, a: %llu\n",
	       e->ts, e->flowid, e->counter);

	rc = write_flowrate_influxdb(infh, e->ts, e->flowid, e->counter);
	if (rc)
		fprintf(stderr, "An error (%d) occurred while writing point to InfluxDB\n",
			rc);

	return 0;
}

int main(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = LO_IFINDEX,
			    .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	bool hook_created = false;
	struct ring_buffer *rbuf;
	struct tc_bpf *skel;
	MHandler_t *infh;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	infh = create_influxdb("http://localhost:8086?db=traffic_rate_db");
	if (!infh) {
		err = -EINVAL;
		fprintf(stderr, "Failed to create InfluxDB handler");
		goto cleanup;
	}

	/* ring buffer */
	rbuf = ring_buffer__new(bpf_map__fd(skel->maps.rbuf),
				handle_event, infh, NULL);
	if (!rbuf) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup_influx;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	while (!exiting) {
		err = ring_buffer__poll(rbuf, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}

		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup_influx;
	}

cleanup_influx:
	destroy_influxdb(infh);
cleanup:
	ring_buffer__free(rbuf);

	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	tc_bpf__destroy(skel);
	return -err;
}
