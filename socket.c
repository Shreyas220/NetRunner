//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// #include <bpf/bpf_helper_defs.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IPV6 0xDD86 // Network byte order for 0x86DD
#define ETH_P_IP 0x0800 /* Internet Protocol packet     */

#define ETH_HLEN 14
#define AF_INET 2

// unsigned long long load_half(const void *skb,unsigned long long off) asm("llvm.bpf.load.half");

// SEC("kprobe/udp_sendmsg")
// int BPF_KPROBE(ig_udp_sendmsg, struct sock *sk , struct msghdr *msg ,size_t len)
// {
//     u32 key = 1;
//     u32 value = 2;

//     bpf_map_update_elem(&shared_map, &key, &value, BPF_ANY);
    
//     return 0 ;
// }
#define PACKET_HOST 0
#define MAX_BUF_SIZE 168

struct sockets_key {
	__u32 netns;
	__u32 family;

	// proto is IPPROTO_TCP(6) or IPPROTO_UDP(17)
	__u32 proto;
	__u32 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sockets_key));
	__uint(value_size, sizeof(u32));
    __uint(max_entries, 128);
} shared_map SEC(".maps");


struct event_t {
	// Keep netns at the top: networktracer depends on it
	__u32 netns;
	__u32 saddr_v4;
	__u32 daddr_v4;
	__u32 af; // AF_INET or AF_INET6
	// Internet protocol and port numbers.
	__u16 sport;
	__u16 dport;
	__u16 dns_off; // DNS offset in the packet
    __u16 dns_end;
    __u32 dns_length;
	__u8 proto;
    __u16 payload[MAX_BUF_SIZE];
};

// struct bpf_map_def SEC("maps") socket_perf_event = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .key_size = sizeof(int),
//     .value_size = sizeof(int),
//     .max_entries = 128,  // Adjust based on your needs
// };

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} socket_events SEC(".maps");


SEC("socket")
int simple_socket_handler(struct __sk_buff *skb)
{    
    struct sockets_key key = {
		0,
	};
    key.netns = skb->cb[0];

    __u16 sport, dport, l4_off, dns_off, id;
    __u8 proto;
    __u8 udp = 17;
    __u32 ip_proto = 0;
    __u32 h_proto;
	
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));
    
    if (bpf_ntohs(h_proto) == ETH_P_IP){    
    __u8 protoc;
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),&protoc, sizeof(protoc));
    key.proto = protoc;
    key.family = AF_INET;
    if (protoc == IPPROTO_UDP){
        

        __u8 ihl_byte;
        bpf_skb_load_bytes(skb, ETH_HLEN, &ihl_byte,sizeof(ihl_byte));
		struct iphdr *iph = (struct iphdr *)&ihl_byte;
		__u8 ip_header_len = iph->ihl * 4;
		l4_off = ETH_HLEN + ip_header_len;
        
        int off = l4_off;
        
        if (skb->pkt_type == PACKET_HOST)
			off += offsetof(struct udphdr, dest);
		else
			off += offsetof(struct udphdr, source);
        
        bpf_skb_load_bytes(skb, off, &key.port, sizeof(key.port));
        bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, dest),&dport, sizeof(dport));
        bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, source),&sport, sizeof(sport));
        
        bpf_printk("Size of struct udphdr: %lu bytes\n", sizeof(struct udphdr));

        if (bpf_ntohs(sport) == 53 || bpf_ntohs(dport) == 53) {
        
        // struct event_t event;
        
        struct event_t *event;
        event = bpf_ringbuf_reserve(&socket_events, sizeof(struct event_t), 0);

        bpf_printk("l4 is %u sport is%u dport is %u",l4_off,sport,dport);
        if (!event) {
            return 0; // Failed to reserve space
        }

        __u16 udp_total_length;
        bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, len), &udp_total_length, sizeof(udp_total_length));
        // udp_total_length &= 0xf0; // clean-up res1
        // udp_total_length >>= 4; // move the upper 4 bits to low
        // dudp_total_lengthoff *= 4; // convert to bytes length

        __u32 dns_length = bpf_ntohs(udp_total_length) - sizeof(struct udphdr);
        event->dns_length = bpf_ntohs(dns_length);
        
        dns_off = l4_off + sizeof(struct udphdr);
    
        bpf_skb_load_bytes(skb, dns_off , event->payload, MAX_BUF_SIZE);
        // for (int i = 0; i < MAX_BUF_SIZE; i++) {
        // event->payload[i] = bpf_ntohs(event->payload[i]);
        // }

        bpf_printk("payload %s",event->payload);
        // bpf_skb_load_bytes(skb, ETH_HLEN ,&event->ip_proto, sizeof(ip_header_len));
        // bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),&event->ip_proto, sizeof(event->ip_proto));
        
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),&event->saddr_v4, sizeof(event->saddr_v4));
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),&event->daddr_v4, sizeof(event->daddr_v4));

        BPF_CORE_READ_INTO(&event->netns, skb, cb[0]);    
        // BPF_CORE_READ_INTO(&event->saddr_v4, skb, local_ip4);    
        // BPF_CORE_READ_INTO(&event->daddr_v4, skb, remote_ip4);    
        BPF_CORE_READ_INTO(&event->af, skb, family);    
        // BPF_CORE_READ_INTO(&event->pkt_type, skb, pkt_type);
        // BPF_CORE_READ_INTO(&event->proto, skb, protocol);
        BPF_CORE_READ_INTO(&event->dns_off, skb, data);    
        BPF_CORE_READ_INTO(&event->dns_end, skb, data_end);    
 
        event->sport = bpf_ntohs(sport);
        event->dport = bpf_ntohs(dport); 
        event->proto = bpf_ntohs(protoc);    
        event->dns_off = bpf_ntohs(dns_off);
        
        // bpf_printk("DNS offset is & %x",dns_off);
        
        bpf_ringbuf_submit(event, 0);
        // bpf_perf_event_output(skb, &socket_perf_event, BPF_F_CURRENT_CPU, &event, sizeof(event));

        }

        }
        // else if (protoc == IPPROTO_TCP){
        //     bpf_printk("IPV4 BUT TCP it is %x proto and protocol is %x ", h_proto,protoc);

        // }
    }
    // else {
    // bpf_printk("IP6 it is %x proto ", h_proto);

    // }

    return 0;
}

