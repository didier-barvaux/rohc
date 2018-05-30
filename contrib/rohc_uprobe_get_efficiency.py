#!/usr/bin/python
#
# quick howto:
#  1. Get BCC
#     $ git clone https://github.com/iovisor/bcc.git
#     $ cd bcc/
#     $ mkdir build
#     $ cd build
#     $ cmake .. -DCMAKE_INSTALL_PREFIX=/usr
#     $ make
#  2. Run the ROHC sniffer (or any other app using librohc)
#     # ./app/sniffer/rohc_sniffer
#  3. Collect information about compression efficiency with uprobes
#     # LD_LIBRARY_PATH=<path-to-bcc>/build/src/cc/ \
#       PYTHONPATH=<path-to-bcc>/build/src/python/ \
#       ./contrib/rohc_uprobe_get_efficiency.py $( pidof rohc_sniffer )
#
#     (LD_LIBRARY_PATH and PYTHONPATH may be avoided if bcc is installed
#      in system paths /usr/lib/...)
#
# Example of output:
#   Tracing ROHC compression for PID 19140 with profile ID = -1...
#   TIME(s)        PID    PROFILE PACKET       HDR-LEN      FULL-LEN  EFFICIENCY
#   0.000000       19140        2      0     28->   28      0->    0  min 77%, avg 83%, max 100%
#   0.000355       19140        2      3     28->    5      0->    0  min 77%, avg 88%, max 100%
#   0.199681       19140        4      7     20->    5      0->    0  min 48%, avg 86%, max 100%
#   0.399757       19140        4      2     20->    2      0->    0  min 37%, avg 84%, max 100%
#   0.400096       19140        2      0     28->   28      0->    0  min 37%, avg 85%, max 100%
#   0.409683       19140        2      2     48->    4      0->    0  min 37%, avg 83%, max 100%
#   0.410033       19140        2      0     28->   28      0->    0  min 37%, avg 89%, max 100%
#   0.649847       19140        2      0     28->   28      0->    0  min 37%, avg 91%, max 100%
#   0.650214       19140        2      3     28->    5      0->    0  min 37%, avg 91%, max 100%
#   1.119680       19140        2      7     28->    7      0->    0  min 37%, avg 91%, max 100%
#   1.129905       19140        2      0     28->   28      0->    0  min 37%, avg 93%, max 100%
#   1.130455       19140        2      0     48->   52      0->    0  min 37%, avg 94%, max 100%
#   1.139832       19140        2      0     28->   28      0->    0  min 37%, avg 95%, max 100%
#

from __future__ import print_function
from bcc import BPF, USDT
import sys
import ctypes as ct

# arguments
def usage():
    print("USAGE: rohc_uprobe_get_efficiency PID [profile]")
    exit()
if len(sys.argv) < 2:
    usage()
if sys.argv[1][0:1] == "-":
    usage()
pid = int(sys.argv[1])
profile_id = -1
if len(sys.argv) == 3:
    profile_id = int(sys.argv[2])

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct event_data_t
{
    u64 pid;
    u64 ts;
    u16 profile_id;
    u16 pkt_type;
    u64 uncomp_hdr_len;
    u64 uncomp_pkt_len;
    u64 comp_hdr_len;
    u64 comp_pkt_len;
    u64 efficiency_min;
    u64 efficiency_avg;
    u64 efficiency_max;
};

struct efficiency_t
{
    u64 total_uncomp_bytes_nr;
    u64 total_comp_bytes_nr;
    u64 min;
    u64 max;
};

BPF_HASH(rohc_efficiency, u32, struct efficiency_t);
BPF_PERF_OUTPUT(events);

int compute_efficiency_min_avg_max(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u16 profile_id = 0;

    /* get profile ID of the last compressed packet from the first parameter
       of the uprobe tracepoint */
    bpf_usdt_readarg(1, ctx, &profile_id);

    /* filter out the packets that do not match the profile we want to display
       information about */
    if (""" + str(profile_id) + """ < 0 ||
        profile_id == """ + str(profile_id) + """) {
        struct efficiency_t *efficiency = NULL;
        u64 uncomp_pkt_len = 0;
        u64 comp_pkt_len = 0;

        /* retrieve the uncompressed and compressed lengths from the uprobe
           tracepoint */
        bpf_usdt_readarg(4, ctx, &uncomp_pkt_len);
        bpf_usdt_readarg(6, ctx, &comp_pkt_len);

        /* init or update compression efficiency */
        efficiency = rohc_efficiency.lookup(&pid);
        if (efficiency == NULL) {
            /* first packet for that PID, init the efficiency to 0 */
            struct efficiency_t initial_efficiency = {
                .total_uncomp_bytes_nr = 0,
                .total_comp_bytes_nr = 0,
                .min = 100,
                .max = 0,
            };
            /* put data in the hash table to retrieve it for next packets */
            rohc_efficiency.update(&pid, &initial_efficiency);
            /* get it again to update it */
            efficiency = rohc_efficiency.lookup(&pid);
            if (efficiency == NULL) {
                return 0; /* should not happen, but required by eBPF verifier */
            }
        }
        efficiency->total_uncomp_bytes_nr += uncomp_pkt_len;
        efficiency->total_comp_bytes_nr += comp_pkt_len;
        u64 efficiency_cur = comp_pkt_len * 100 / uncomp_pkt_len;
        if (efficiency_cur < efficiency->min) {
            efficiency->min = efficiency_cur;
        }
        if (efficiency_cur > efficiency->max) {
            efficiency->max = efficiency_cur;
        }

        /* build and send the perf event to report to the listener */
        {
            struct event_data_t event_data = { };

            /* build the perf event to report to the listener */
            event_data.pid = pid;
            event_data.ts = bpf_ktime_get_ns();
            event_data.profile_id = profile_id;
            bpf_usdt_readarg(2, ctx, &event_data.pkt_type);
            bpf_usdt_readarg(3, ctx, &event_data.uncomp_hdr_len);
            bpf_usdt_readarg(5, ctx, &event_data.comp_hdr_len);
            event_data.efficiency_min = efficiency->min;
            event_data.efficiency_max = efficiency->max;
            event_data.efficiency_avg = efficiency->total_comp_bytes_nr * 100 /
                                        efficiency->total_uncomp_bytes_nr;

            /* send the event to the listener */
            events.perf_submit(ctx, &event_data, sizeof(event_data));
        }
    }

    return 0;
};

"""

# enable USDT probe from given PID
u = USDT(pid=pid)
u.enable_probe(probe="rohc-compression", fn_name="compute_efficiency_min_avg_max")

# initialize the eBPF program
b = BPF(text=bpf_text, usdt_contexts=[u])

# header
print("Tracing ROHC compression for PID %d with profile ID = %d..." \
    % (pid, profile_id))
print("%-14s %-6s %7s %6s  %12s  %12s  %s" \
    % ("TIME(s)", "PID", "PROFILE", "PACKET", "HDR-LEN", "FULL-LEN", "EFFICIENCY"))

# mapping for the event data sent by the eBPF program
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
        ("profile", ct.c_ushort),
        ("pkt_type", ct.c_ushort),
        ("uncomp_hdr_len", ct.c_ulonglong),
        ("uncomp_pkt_len", ct.c_ulonglong),
        ("comp_hdr_len", ct.c_ulonglong),
        ("comp_pkt_len", ct.c_ulonglong),
        ("efficiency_min", ct.c_ulonglong),
        ("efficiency_avg", ct.c_ulonglong),
        ("efficiency_max", ct.c_ulonglong)
    ]

# process the given perf event
start = 0
def print_event(cpu, event_data, size):
    global start
    event = ct.cast(event_data, ct.POINTER(Data)).contents
    if start == 0:
        start = event.ts
    print("%-14.6f %-6d %7d %6d  %5d->%5d  %5d->%5d  min %d%%, avg %d%%, max %d%%" % \
        (float(event.ts - start) / 1000000000, \
        event.pid, event.profile, event.pkt_type, \
        event.uncomp_hdr_len, event.comp_hdr_len, \
        event.uncomp_pkt_len, event.comp_pkt_len, \
        event.efficiency_min, event.efficiency_avg, event.efficiency_max))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()

