from bcc import BPF
import time

bpf_text = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

int xdp_reroute_port(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // Check for UDP instead of TCP
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        __u16 src_port = bpf_htons(5000);
        __u16 dst_port = bpf_htons(8080);
        __u16 new_port = bpf_htons(9090);

        if (udp->source == src_port && udp->dest == dst_port) {
            
            // Rewrite the destination port
            udp->dest = new_port;
            
            // In IPv4, setting the UDP checksum to 0 disables validation
            udp->check = 0; 

            return XDP_PASS; 
        }
    }
    return XDP_PASS;
}
"""

device = "lo" 
b = BPF(text=bpf_text)

fn = b.load_func("xdp_reroute_port", BPF.XDP)
b.attach_xdp(device, fn, 0)
print(f"Attached XDP rerouter to {device}. Rerouting UDP 5000->8080 to 9090. Press Ctrl+C to exit.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\nDetaching XDP from {device}...")
    b.remove_xdp(device, 0)