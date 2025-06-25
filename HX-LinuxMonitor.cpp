#include <linux/init.h>   // included for __init and __exit macros
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/module.h> // included for all kernel modules
#include <linux/netdevice.h>
#include <linux/lsm_hook_defs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A Simple Hello Packet Module");

enum {
  NF_IP_PRE_ROUTING,
  NF_IP_LOCAL_IN,
  NF_IP_FORWARD,
  NF_IP_LOCAL_OUT,
  NF_IP_POST_ROUTING,
  NF_IP_NUMHOOKS
};

static struct nf_hook_ops in_nfho;  // net filter hook option struct
static struct nf_hook_ops out_nfho; // net filter hook option struct

static void dump_addr(unsigned char *iphdr) {
  int i;
  for (i = 0; i < 4; i++) {
    printk("%d.", *(iphdr + 12 + i));
  }
  printk(" -> ");
  for (i = 0; i < 4; i++) {
    printk("%d.", *(iphdr + 16 + i));
  }
  printk("\n");
}

unsigned int my_hook(void *priv, struct sk_buff *skb,
                     const struct nf_hook_state *state) {
  printk("Hello packet! ");
  // printk("from %s to %s\n", in->name, out->name);
  unsigned char *iphdr = skb_network_header(skb);
  if (iphdr) {
    dump_addr(iphdr);
  }
  return NF_ACCEPT;
  // return NF_DROP;//会导致上不了网
}

static int __init init_func(void) {
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

static void __exit exit_func(void) {
  nf_unregister_net_hook(&init_net, &in_nfho);
  nf_unregister_net_hook(&init_net, &out_nfho);
  printk(KERN_INFO "Cleaning up Hello_Packet module.\n");
}

module_init(init_func);
module_exit(exit_func);