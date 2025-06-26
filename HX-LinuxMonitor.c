#include <linux/module.h> // included for all kernel modules
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/init.h>   // included for __init and __exit macros
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A Simple Hello Packet Module");

struct Data
{
    const char *ip;
    int port;
};

static struct nf_hook_ops out_nfho; // net filter hook option struct

unsigned int hook_sent_request(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
#define NIPQUAD(addr) ((unsigned char *)&addr)[0], \
                      ((unsigned char *)&addr)[1], \ 
                      ((unsigned char *)&addr)[2], \ 
                      ((unsigned char *)&addr)[3]

    // 如果是ip协议
    if ((skb->protocol) == htons(ETH_P_IP)) {
        struct iphdr* nh = ip_hdr(skb);
        // printk("src: %u.%u.%u.%u, dst: %u.%u.%u.%u\n", NIPQUAD(nh->saddr), NIPQUAD(nh->daddr));
        switch (nh->protocol) {
            case IPPROTO_TCP: {
                struct tcphdr* th = tcp_hdr(skb);
                // src: 192.168.0.202, sport: 57572 dst: 121.36.16.180 dport: 47873 
                printk("[TCP] %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", 
                    NIPQUAD(nh->saddr), th->source, // 源ip - 端口
                    NIPQUAD(nh->daddr), th->dest);  // 目标ip - 端口
                    
                // 如果目标 ip:端口 是黑名单内容, 则禁止
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr* uh = udp_hdr(skb);
                printk("[UDP] %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", 
                    NIPQUAD(nh->saddr), uh->source, // 源ip - 端口
                    NIPQUAD(nh->daddr), uh->dest);  // 目标ip - 端口
                break;
            }
            case IPPROTO_IPV6: {
                printk("[IPv6]"); // @todo
                break;
            }
            default: {
                break;
            }
        }
    }

    return NF_ACCEPT;

#undef NIPQUAD
    // return NF_DROP; //会导致上不了网
}

static int __init init_func(void)
{
    /* from: https://zhuanlan.zhihu.com/p/81866818
    --->[NF_IP_PRE_ROUTING]--->[ROUTE]--->[NF_IP_FORWARD]--->[NF_IP_POST_ROUTING]--->
                              |                        ^
                              |                        |
                              |                     [ROUTE]
                              v                        |
                       [NF_IP_LOCAL_IN]        [NF_IP_LOCAL_OUT]
                              |                        ^
                              |                        |
                              v                        |
    NF_IP_PRE_ROUTING: 位于路由之前，报文一致性检查之后（报文一致性检查包括: 报文版本、报文长度和checksum）。
    NF_IP_LOCAL_IN: 位于报文经过路由之后，并且目的是本机的。
    NF_IP_FORWARD：位于在报文路由之后，目的地非本机的。
    NF_IP_LOCAL_OUT: 由本机发出去的报文，并且在路由之前。
    NF_IP_POST_ROUTING: 所有即将离开本机的报文。
    */
    // NF_IP_LOCAL_OUT hook
    printk("run ...\n");
    out_nfho.hook = hook_sent_request;
    out_nfho.hooknum = NF_INET_LOCAL_OUT;
    out_nfho.pf = PF_INET;
    out_nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &out_nfho);
    return 0;
}

static void __exit exit_func(void)
{
    nf_unregister_net_hook(&init_net, &out_nfho);
    printk(KERN_INFO "Cleaning up Hello_Packet module.\n");
}

module_init(init_func);
module_exit(exit_func);