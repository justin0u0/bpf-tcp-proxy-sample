//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SERVER_PORT 8080
#define PROXY_PORT 8081

// client <--[key=0]--> proxy <--[key=1]--> server

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 32);
	__type(key, __u32);
	__type(value, __u32); // socket FD
} sockmap SEC(".maps");

SEC("sockops/prog")
int sockops_prog(struct bpf_sock_ops *skops) {
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // SYN-ACK
		if (skops->local_port == PROXY_PORT) {
			__u32 key = 0;
			bpf_sock_map_update(skops, &sockmap, &key, BPF_ANY);
		}
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // SYN
		if (bpf_ntohl(skops->remote_port) == SERVER_PORT) {
			__u32 key = 1;
			bpf_sock_map_update(skops, &sockmap, &key, BPF_ANY);
		}
		break;
	}

	return 0;
}

SEC("sk_skb/stream_verdict/prog")
int sk_skb_stream_verdict_prog(struct __sk_buff *skb) {
	int res;

	if (skb->local_port == PROXY_PORT) {
		// doesn't work
		res = bpf_sk_redirect_map(skb, &sockmap, 0, BPF_F_INGRESS);

		// works
		// res = bpf_sk_redirect_map(skb, &sockmap, 1, 0);
		return res;
	}

	if (bpf_ntohl(skb->remote_port) == SERVER_PORT) {
		// doesn't work
		res = bpf_sk_redirect_map(skb, &sockmap, 1, BPF_F_INGRESS);

		// works
		// res = bpf_sk_redirect_map(skb, &sockmap, 0, 0);
		return res;
	}

	return SK_DROP;
}

char _license[] SEC("license") = "GPL";
