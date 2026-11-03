// SPDX-License-Identifier: MIT
/*
 * rrp server data plane: stateless TC port redirection into a WireGuard tunnel.
 *
 * Two programs, both attached as TC ingress classifiers on the rrp server:
 *
 *  rrp_public_ingress  (public NIC)
 *      visitor -> public_ip:P   ==>   visitor -> client_tunnel_ip:X, redirected into the
 *      WireGuard interface. The visitor's source address is preserved; the client routes
 *      replies back through the tunnel with a policy route.
 *
 *  rrp_tunnel_ingress  (WireGuard interface)
 *      client_tunnel_ip:X -> visitor   ==>   public_ip:P -> visitor, redirected out of the
 *      public NIC with the L2 header filled in by the neighbour subsystem.
 *
 * Both directions are pure table lookups on (family, proto, port): no connection tracking,
 * no per-flow state. The control plane fills the maps when a client registers a proxy and
 * clears them when it disconnects. Packets without a mapping are passed to the stack
 * untouched (TC_ACT_OK), so the kernel answers them exactly as if rrp were not running.
 *
 * The structs below are mirrored byte-for-byte in src/tunnel/bpf_types.rs.
 */
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define RRP_FAMILY_V4 4
#define RRP_FAMILY_V6 6
#define RRP_MAX_PORTS 65536
#define TCP_FLAG_SYN 0x02
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MSS 2
#define TCP_MAX_OPTION_BYTES 40

struct rrp_port_key {
	__u8 family; /* RRP_FAMILY_V4 / RRP_FAMILY_V6 */
	__u8 proto;  /* IPPROTO_TCP / IPPROTO_UDP */
	__u16 port;  /* public port P, host byte order */
};

struct rrp_port_val {
	__u8 tunnel_ip[16]; /* client tunnel address, network order (IPv4 in the first 4 bytes) */
	__u16 tunnel_port;  /* client listener port X, host byte order */
	__u16 pad;
};

struct rrp_rev_key {
	__u8 family;
	__u8 proto;
	__u16 tunnel_port; /* X, host byte order */
	__u8 tunnel_ip[16];
};

struct rrp_rev_val {
	__u16 public_port; /* P, host byte order */
	__u16 pad;
};

struct rrp_config {
	__u32 public_ifindex;
	__u32 tunnel_ifindex;
	__u8 public_ipv4[4];
	__u8 public_ipv6[16];
	__u16 mss_clamp_v4; /* 0 disables clamping */
	__u16 mss_clamp_v6;
};

struct rrp_stats {
	__u64 rx_packets; /* visitor -> client */
	__u64 rx_bytes;
	__u64 tx_packets; /* client -> visitor */
	__u64 tx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, RRP_MAX_PORTS);
	__type(key, struct rrp_port_key);
	__type(value, struct rrp_port_val);
} rrp_portmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, RRP_MAX_PORTS);
	__type(key, struct rrp_rev_key);
	__type(value, struct rrp_rev_val);
} rrp_revmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rrp_config);
} rrp_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, RRP_MAX_PORTS);
	__type(key, struct rrp_port_key);
	__type(value, struct rrp_stats);
} rrp_stats SEC(".maps");

/* Minimal header layouts; only the fields we touch, in wire order. */
struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

struct iphdr {
	__u8 ihl_version; /* version:4 (high nibble), ihl:4 (low nibble) */
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ipv6hdr {
	__u8 version_class; /* version:4, traffic class high nibble */
	__u8 flow[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff_res; /* data offset in high nibble */
	__u8 flags;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

/* Everything a rewrite needs, gathered while the packet pointers are still valid. */
struct parsed {
	__u8 family;
	__u8 proto;
	__u8 is_syn;
	__u32 ip_off;   /* offset of the IP header from skb->data */
	__u32 l4_off;   /* offset of the TCP/UDP header */
	__u32 csum_off; /* offset of the L4 checksum field */
	__u16 src_port; /* host order */
	__u16 dst_port; /* host order */
	__u16 l4_csum;  /* raw UDP checksum (zero means "none" on IPv4) */
	__u8 saddr[16];
	__u8 daddr[16];
	__u32 mss_off; /* offset of the MSS option value, 0 if absent */
	__u16 mss;     /* host order */
};

static __always_inline int parse_packet(struct __sk_buff *skb, __u32 ip_off, struct parsed *p)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	__builtin_memset(p, 0, sizeof(*p));
	p->ip_off = ip_off;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + ip_off;
		if ((void *)(ip + 1) > data_end)
			return -1;
		if ((ip->ihl_version >> 4) != 4)
			return -1;
		__u32 ihl = (ip->ihl_version & 0x0f) * 4;
		if (ihl < sizeof(*ip))
			return -1;
		/* Fragments carry no L4 header we can map; leave them to the stack. */
		if (ip->frag_off & bpf_htons(0x3fff))
			return -1;
		p->family = RRP_FAMILY_V4;
		p->proto = ip->protocol;
		p->l4_off = ip_off + ihl;
		__builtin_memcpy(p->saddr, &ip->saddr, 4);
		__builtin_memcpy(p->daddr, &ip->daddr, 4);
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + ip_off;
		if ((void *)(ip6 + 1) > data_end)
			return -1;
		if ((ip6->version_class >> 4) != 6)
			return -1;
		/* Extension headers are rare on proxied traffic; only direct TCP/UDP is mapped. */
		p->family = RRP_FAMILY_V6;
		p->proto = ip6->nexthdr;
		p->l4_off = ip_off + sizeof(*ip6);
		__builtin_memcpy(p->saddr, ip6->saddr, 16);
		__builtin_memcpy(p->daddr, ip6->daddr, 16);
	} else {
		return -1;
	}

	if (p->proto == IPPROTO_TCP) {
		struct tcphdr *tcp = data + p->l4_off;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		p->src_port = bpf_ntohs(tcp->source);
		p->dst_port = bpf_ntohs(tcp->dest);
		p->csum_off = p->l4_off + __builtin_offsetof(struct tcphdr, check);
		p->l4_csum = tcp->check;
		if (tcp->flags & TCP_FLAG_SYN) {
			p->is_syn = 1;
			__u32 doff = (tcp->doff_res >> 4) * 4;
			if (doff > sizeof(*tcp)) {
				__u32 opt_len = doff - sizeof(*tcp);
				if (opt_len > TCP_MAX_OPTION_BYTES)
					opt_len = TCP_MAX_OPTION_BYTES;
				__u8 *opt = (__u8 *)(tcp + 1);
				__u32 i = 0;
				/* Bounded loop (kernel 5.3+); the verifier tracks i < opt_len <= 40. */
				for (int n = 0; n < TCP_MAX_OPTION_BYTES; n++) {
					if (i >= opt_len)
						break;
					if ((void *)(opt + i + 1) > data_end)
						break;
					__u8 kind = opt[i];
					if (kind == TCPOPT_EOL)
						break;
					if (kind == TCPOPT_NOP) {
						i += 1;
						continue;
					}
					if ((void *)(opt + i + 2) > data_end)
						break;
					__u8 len = opt[i + 1];
					if (len < 2)
						break;
					if (kind == TCPOPT_MSS && len == 4) {
						if ((void *)(opt + i + 4) > data_end)
							break;
						p->mss = ((__u16)opt[i + 2] << 8) | opt[i + 3];
						p->mss_off = p->l4_off + sizeof(*tcp) + i + 2;
						break;
					}
					i += len;
				}
			}
		}
	} else if (p->proto == IPPROTO_UDP) {
		struct udphdr *udp = data + p->l4_off;
		if ((void *)(udp + 1) > data_end)
			return -1;
		p->src_port = bpf_ntohs(udp->source);
		p->dst_port = bpf_ntohs(udp->dest);
		p->csum_off = p->l4_off + __builtin_offsetof(struct udphdr, check);
		p->l4_csum = udp->check;
	} else {
		return -1;
	}

	return 0;
}

/* Flags for bpf_l4_csum_replace: UDP over IPv4 may legitimately carry a zero checksum. */
static __always_inline __u64 l4_flags(const struct parsed *p)
{
	__u64 flags = 0;
	if (p->proto == IPPROTO_UDP && p->family == RRP_FAMILY_V4)
		flags |= BPF_F_MARK_MANGLED_0;
	return flags;
}

static __always_inline int rewrite_address(struct __sk_buff *skb, const struct parsed *p,
					   __u32 addr_off, const __u8 *old_addr,
					   const __u8 *new_addr)
{
	if (p->family == RRP_FAMILY_V4) {
		__be32 old = *(const __be32 *)old_addr;
		__be32 new = *(const __be32 *)new_addr;
		if (old == new)
			return 0;
		__u32 ip_csum_off = p->ip_off + __builtin_offsetof(struct iphdr, check);
		if (bpf_l3_csum_replace(skb, ip_csum_off, old, new, sizeof(new)) < 0)
			return -1;
		if (bpf_l4_csum_replace(skb, p->csum_off, old, new,
					BPF_F_PSEUDO_HDR | l4_flags(p) | sizeof(new)) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, addr_off, &new, sizeof(new), 0) < 0)
			return -1;
		return 0;
	}

	__be32 old6[4], new6[4];
	__builtin_memcpy(old6, old_addr, 16);
	__builtin_memcpy(new6, new_addr, 16);
	__s64 diff = bpf_csum_diff(old6, 16, new6, 16, 0);
	if (diff < 0)
		return -1;
	if (bpf_l4_csum_replace(skb, p->csum_off, 0, (__u32)diff, BPF_F_PSEUDO_HDR | l4_flags(p)) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, addr_off, new6, 16, 0) < 0)
		return -1;
	return 0;
}

static __always_inline int rewrite_port(struct __sk_buff *skb, const struct parsed *p,
					__u32 port_off, __u16 old_port, __u16 new_port)
{
	if (old_port == new_port)
		return 0;
	__be16 old = bpf_htons(old_port);
	__be16 new = bpf_htons(new_port);
	if (bpf_l4_csum_replace(skb, p->csum_off, old, new, l4_flags(p) | sizeof(new)) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, port_off, &new, sizeof(new), 0) < 0)
		return -1;
	return 0;
}

/* Lower the MSS advertised in a SYN so segments fit inside the tunnel MTU. */
static __always_inline int clamp_mss(struct __sk_buff *skb, const struct parsed *p, __u16 clamp)
{
	if (!p->is_syn || !p->mss_off || clamp == 0 || p->mss <= clamp)
		return 0;
	__be16 old = bpf_htons(p->mss);
	__be16 new = bpf_htons(clamp);
	if (bpf_l4_csum_replace(skb, p->csum_off, old, new, sizeof(new)) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, p->mss_off, &new, sizeof(new), 0) < 0)
		return -1;
	return 0;
}

static __always_inline void account(struct rrp_port_key *key, __u32 len, int tx)
{
	struct rrp_stats *stats = bpf_map_lookup_elem(&rrp_stats, key);
	if (!stats)
		return;
	if (tx) {
		stats->tx_packets += 1;
		stats->tx_bytes += len;
	} else {
		stats->rx_packets += 1;
		stats->rx_bytes += len;
	}
}

static __always_inline __u32 port_field_off(const struct parsed *p, int dst)
{
	/* source/dest port offsets are identical for TCP and UDP. */
	return p->l4_off + (dst ? 2 : 0);
}

static __always_inline __u32 addr_field_off(const struct parsed *p, int dst)
{
	if (p->family == RRP_FAMILY_V4)
		return p->ip_off + (dst ? __builtin_offsetof(struct iphdr, daddr)
					: __builtin_offsetof(struct iphdr, saddr));
	return p->ip_off + (dst ? __builtin_offsetof(struct ipv6hdr, daddr)
				: __builtin_offsetof(struct ipv6hdr, saddr));
}

SEC("tc")
int rrp_public_ingress(struct __sk_buff *skb)
{
	struct parsed p;
	if (parse_packet(skb, ETH_HLEN, &p) < 0)
		return TC_ACT_OK;

	struct rrp_port_key key = {
		.family = p.family,
		.proto = p.proto,
		.port = p.dst_port,
	};
	struct rrp_port_val *val = bpf_map_lookup_elem(&rrp_portmap, &key);
	if (!val)
		return TC_ACT_OK;

	__u32 zero = 0;
	struct rrp_config *cfg = bpf_map_lookup_elem(&rrp_config, &zero);
	if (!cfg || cfg->tunnel_ifindex == 0)
		return TC_ACT_OK;

	__u16 clamp = p.family == RRP_FAMILY_V4 ? cfg->mss_clamp_v4 : cfg->mss_clamp_v6;
	__u32 len = skb->len;
	__u8 new_addr[16];
	__builtin_memcpy(new_addr, val->tunnel_ip, 16);
	__u16 new_port = val->tunnel_port;

	/* Order matters only in that every helper below works on offsets, not pointers. */
	if (clamp_mss(skb, &p, clamp) < 0)
		return TC_ACT_SHOT;
	if (rewrite_address(skb, &p, addr_field_off(&p, 1), p.daddr, new_addr) < 0)
		return TC_ACT_SHOT;
	if (rewrite_port(skb, &p, port_field_off(&p, 1), p.dst_port, new_port) < 0)
		return TC_ACT_SHOT;

	account(&key, len, 0);
	/* The kernel strips the Ethernet header when redirecting to an L3 device. */
	return bpf_redirect(cfg->tunnel_ifindex, 0);
}

SEC("tc")
int rrp_tunnel_ingress(struct __sk_buff *skb)
{
	/* The WireGuard interface has no link-layer header: data starts at the IP header. */
	struct parsed p;
	if (parse_packet(skb, 0, &p) < 0)
		return TC_ACT_OK;

	struct rrp_rev_key key = {
		.family = p.family,
		.proto = p.proto,
		.tunnel_port = p.src_port,
	};
	__builtin_memcpy(key.tunnel_ip, p.saddr, 16);
	struct rrp_rev_val *val = bpf_map_lookup_elem(&rrp_revmap, &key);
	if (!val)
		return TC_ACT_OK;

	__u32 zero = 0;
	struct rrp_config *cfg = bpf_map_lookup_elem(&rrp_config, &zero);
	if (!cfg || cfg->public_ifindex == 0)
		return TC_ACT_OK;

	__u8 new_addr[16] = {};
	if (p.family == RRP_FAMILY_V4)
		__builtin_memcpy(new_addr, cfg->public_ipv4, 4);
	else
		__builtin_memcpy(new_addr, cfg->public_ipv6, 16);
	__u16 public_port = val->public_port;
	__u32 len = skb->len;

	if (rewrite_address(skb, &p, addr_field_off(&p, 0), p.saddr, new_addr) < 0)
		return TC_ACT_SHOT;
	if (rewrite_port(skb, &p, port_field_off(&p, 0), p.src_port, public_port) < 0)
		return TC_ACT_SHOT;

	struct rrp_port_key stats_key = {
		.family = p.family,
		.proto = p.proto,
		.port = public_port,
	};
	account(&stats_key, len, 1);

	/*
	 * bpf_redirect_neigh expects an L2 header in front of the IP header (it pulls it and
	 * lets the neighbour subsystem write the real one). Prepend a zeroed placeholder with
	 * the right EtherType; a zero destination is not multicast, so it is accepted.
	 */
	if (bpf_skb_change_head(skb, ETH_HLEN, 0) < 0)
		return TC_ACT_SHOT;
	struct ethhdr eth = {};
	eth.h_proto = p.family == RRP_FAMILY_V4 ? bpf_htons(ETH_P_IP) : bpf_htons(ETH_P_IPV6);
	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) < 0)
		return TC_ACT_SHOT;

	return bpf_redirect_neigh(cfg->public_ifindex, NULL, 0, 0);
}
