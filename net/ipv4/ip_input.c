/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <net/dst_metadata.h>

/*
 *	Process Router Attention IP option (RFC 2113)
 */
bool ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);

	for (ra = rcu_dereference(ip_ra_chain); ra; ra = rcu_dereference(ra->next)) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex) &&
		    net_eq(sock_net(sk), net)) {
			if (ip_is_fragment(ip_hdr(skb))) {
				if (ip_defrag(net, skb, IP_DEFRAG_CALL_RA_CHAIN))
					return true;
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		return true;
	}
	return false;
}

static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
//指针操作“删除”IP首部后
	/* 取走网络层报文头部          重置传输层报文头部*/
	/* 拉出IP报文首部，因为马上就要脱离IP层，进入传输层了。 */
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	{
	 	/* 得到传输层协议 */
		int protocol = ip_hdr(skb)->protocol;
		const struct net_protocol *ipprot;
		int raw;

	resubmit:
		/* 将数据包传递给对应的原始套接字 */
		/* 如果有RAW socket传递给RAW socket处理 */
		raw = raw_local_deliver(skb, protocol);
		/* 得到注册协议 */
		/* 根据传输协议确定对应的inet协议 */
		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot) {
			/* 找到了匹配传输层的协议 */
			int ret;
			/* 该协议是否有xfrm策略检查 */
			/* 协议的安全策略检查 */
			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			/* 调用协议的处理函数 */
			 /* 将数据包传递给传输层处理 */
			//udp:udp_rcv->__udp4_lib_rcv
			//tcp:tcp_v4_rcv
			ret = ipprot->handler(skb);
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
		} else {
			/* 没有对应的网络协议 */
			if (!raw) {
				 /* 没有任何已注册的网络协议可以处理这个数据包，因此回复ICMP proto unreachable */
			 /* 若没有匹配的原始套接字，则进行安全策略检查 */
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					IP_INC_STATS_BH(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					/* 若没有对应的安全策略，则使用ICMP返回不可达错误 */
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
				kfree_skb(skb);
			} else {
				IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
				consume_skb(skb);
			}
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	 /* 得到设备的网络空间 */
	struct net *net = dev_net(skb->dev);
	/* 该数据包是一个IP分片数据包 */
	if (ip_is_fragment(ip_hdr(skb))) {
		/* 进行IP分片重组处理 */
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}
//调用netfilter挂钩NF_IP_LOCAL_IN，恢复在ip_local_deliver_finish函数中的处理
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
							     &iph->saddr,
							     &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

int sysctl_ip_early_demux __read_mostly = 1;
EXPORT_SYMBOL(sysctl_ip_early_demux);

static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
	if (sysctl_ip_early_demux && !skb_dst(skb) && !skb->sk) {
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot && ipprot->early_demux) {
			ipprot->early_demux(skb);
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_valid_dst(skb)) {
		/* 如果数据包没有设置路由信息，则进行路由查询 */
		int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					       iph->tos, skb->dev);
		if (unlikely(err)) {
			/* 若查找路由失败，增加相应的错误计数，并丢弃数据包 */
			if (err == -EXDEV)
				NET_INC_STATS_BH(net, LINUX_MIB_IPRPFILTER);
			goto drop;
		}
	}
	/*
	 * 如果配置了流量控制功能，则更新QoS的统计信息
	 */

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif
	 /* iph大于5，即首部长度大于固定首部长度20字节。因此说明该IP报文具有IP选项，
	 于是调用ip_rcv_options处理IP选项 */
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;
	 /* 根据路由类型，增加相应的计数 */
	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS_BH(net, IPSTATS_MIB_INMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(net, IPSTATS_MIB_INBCAST, skb->len);
	  /* 调用路由的输入函数 
	  函数指针的值可能为 ip_local_deliver 或 ip_forward 函数
		*/
	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 * 	Main IP Receive routine.
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	struct net *net;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	  /* 如果该数据是发给其他终端的，则丢弃这个数据包。
	  这里的pkt_type是根据二层地址来判断是否发给本机的。    */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;


	net = dev_net(dev);
	IP_UPD_PO_STATS_BH(net, IPSTATS_MIB_IN, skb->len);
	 /* 对数据包进行共享检查，保证IP协议处理的数据包独享一个skb。 */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		IP_INC_STATS_BH(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}
	 /* 检查IP首部，如果数据包小于IP首部的大小，则出错 */
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;
	/* 得到IP首部地址 */
	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */
	/* 根据RFC标准，IP首部小于20字节，或者版本号不是4的，就报错丢弃 */
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	IP_ADD_STATS_BH(net,
			IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
			max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));
	 /* 根据IP首部指定的长度，再次检查数据包的大小 */
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;
	  /* 重新获取IP首部地址。之所以要重新获取，是因为pskb_may_pull可能要重新申请skb */
	iph = ip_hdr(skb);
	//检查计算的校验和与首部中存储的校验和是否一致
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;
	/* 对数据包长度进行检查 */
	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		IP_INC_STATS_BH(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	 /* 因为传输媒介可能会给数据包进行补齐，现在已经根据IP首部明确了数据包的长度，因此需要将数据
	  包的长度变为真正的长度并改变 */
	if (pskb_trim_rcsum(skb, len)) {
		IP_INC_STATS_BH(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	skb->transport_header = skb->network_header + iph->ihl*4;

	/* Remove any debris in the socket control block */
	/* 重置数据包的控制块信息 */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	/* Must drop socket now because of tproxy. */
	/* 重置数据包的套接字信息 */
	skb_orphan(skb);
	//NetFilter HOOK,用户空间可以对分组做操作
	  /* 遍历执行netfilter在PREROUTING点上的规则，如果数据包没有被丢弃，则进入ip_rcv_finish */
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);

csum_error:
	IP_INC_STATS_BH(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	IP_INC_STATS_BH(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}
