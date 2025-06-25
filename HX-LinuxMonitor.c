#include <linux/module.h> // included for all kernel modules
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/init.h>   // included for __init and __exit macros
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A Simple Hello Packet Module");

enum
{
    NF_IP_PRE_ROUTING,
    NF_IP_LOCAL_IN,
    NF_IP_FORWARD,
    NF_IP_LOCAL_OUT,
    NF_IP_POST_ROUTING,
    NF_IP_NUMHOOKS
};

static struct nf_hook_ops in_nfho;  // net filter hook option struct
static struct nf_hook_ops out_nfho; // net filter hook option struct

static void dump_addr(unsigned char *iphdr)
{
    int i;
    // @todo 有bug...
    unsigned char str[24] = {};
    for (i = 0; i < 4; i++)
    {
        str[i * 2] = *(iphdr + 12 + i);
        str[i * 2 + 1] = '.';
    }
    str[8] = '-';
    str[9] = '>';
    for (i = 0; i < 4; i++)
    {
        str[i * 2 + 10] = *(iphdr + 16 + i);
        str[i * 2 + 1 + 10] = '.';
    }
    printk("%s\n", str);
}

unsigned int my_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    printk("Hello packet! ");
    // printk("from %s to %s\n", in->name, out->name);
    unsigned char *iphdr = skb_network_header(skb);
    if (iphdr)
    {
        dump_addr(iphdr);
    }
    return NF_ACCEPT;
    // return NF_DROP;//会导致上不了网
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
    // NF_IP_PRE_ROUTING hook
    in_nfho.hook = my_hook;
    in_nfho.hooknum = NF_IP_LOCAL_IN;
    in_nfho.pf = PF_INET;
    in_nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &in_nfho);

    // NF_IP_LOCAL_OUT hook
    out_nfho.hook = my_hook;
    out_nfho.hooknum = NF_IP_LOCAL_OUT;
    out_nfho.pf = PF_INET;
    out_nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &out_nfho);
    return 0;
}

static void __exit exit_func(void)
{
    nf_unregister_net_hook(&init_net, &in_nfho);
    nf_unregister_net_hook(&init_net, &out_nfho);
    printk(KERN_INFO "Cleaning up Hello_Packet module.\n");
}

module_init(init_func);
module_exit(exit_func);