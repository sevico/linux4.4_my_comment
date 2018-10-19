/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The User Datagram Protocol (UDP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 * Fixes:
 *		Alan Cox	:	verify_area() calls
 *		Alan Cox	: 	stopped close while in use off icmp
 *					messages. Not a fix but a botch that
 *					for udp at least is 'valid'.
 *		Alan Cox	:	Fixed icmp handling properly
 *		Alan Cox	: 	Correct error for oversized datagrams
 *		Alan Cox	:	Tidied select() semantics.
 *		Alan Cox	:	udp_err() fixed properly, also now
 *					select and read wake correctly on errors
 *		Alan Cox	:	udp_send verify_area moved to avoid mem leak
 *		Alan Cox	:	UDP can count its memory
 *		Alan Cox	:	send to an unknown connection causes
 *					an ECONNREFUSED off the icmp, but
 *					does NOT close.
 *		Alan Cox	:	Switched to new sk_buff handlers. No more backlog!
 *		Alan Cox	:	Using generic datagram code. Even smaller and the PEEK
 *					bug no longer crashes it.
 *		Fred Van Kempen	: 	Net2e support for sk->broadcast.
 *		Alan Cox	:	Uses skb_free_datagram
 *		Alan Cox	:	Added get/set sockopt support.
 *		Alan Cox	:	Broadcasting without option set returns EACCES.
 *		Alan Cox	:	No wakeup calls. Instead we now use the callbacks.
 *		Alan Cox	:	Use ip_tos and ip_ttl
 *		Alan Cox	:	SNMP Mibs
 *		Alan Cox	:	MSG_DONTROUTE, and 0.0.0.0 support.
 *		Matt Dillon	:	UDP length checks.
 *		Alan Cox	:	Smarter af_inet used properly.
 *		Alan Cox	:	Use new kernel side addressing.
 *		Alan Cox	:	Incorrect return on truncated datagram receive.
 *	Arnt Gulbrandsen 	:	New udp_send and stuff
 *		Alan Cox	:	Cache last socket
 *		Alan Cox	:	Route cache
 *		Jon Peatfield	:	Minor efficiency fix to sendto().
 *		Mike Shaver	:	RFC1122 checks.
 *		Alan Cox	:	Nonblocking error fix.
 *	Willy Konynenberg	:	Transparent proxying support.
 *		Mike McLagan	:	Routing by source
 *		David S. Miller	:	New socket lookup architecture.
 *					Last socket cache retained as it
 *					does have a high hit rate.
 *		Olaf Kirch	:	Don't linearise iovec on sendmsg.
 *		Andi Kleen	:	Some cleanups, cache destination entry
 *					for connect.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Melvin Smith	:	Check msg_name not msg_namelen in sendto(),
 *					return ENOTCONN for unconnected sockets (POSIX)
 *		Janos Farkas	:	don't deliver multi/broadcasts to a different
 *					bound-to-device socket
 *	Hirokazu Takahashi	:	HW checksumming for outgoing UDP
 *					datagrams.
 *	Hirokazu Takahashi	:	sendfile() on UDP works now.
 *		Arnaldo C. Melo :	convert /proc/net/udp to seq_file
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov:		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *	Derek Atkins <derek@ihtfp.com>: Add Encapulation Support
 *	James Chapman		:	Add L2TP encapsulation type.
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "UDP: " fmt

#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>
#include <trace/events/skb.h>
#include <net/busy_poll.h>
#include "udp_impl.h"

struct udp_table udp_table __read_mostly;
EXPORT_SYMBOL(udp_table);

long sysctl_udp_mem[3] __read_mostly;
EXPORT_SYMBOL(sysctl_udp_mem);

int sysctl_udp_rmem_min __read_mostly;
EXPORT_SYMBOL(sysctl_udp_rmem_min);

int sysctl_udp_wmem_min __read_mostly;
EXPORT_SYMBOL(sysctl_udp_wmem_min);

atomic_long_t udp_memory_allocated;
EXPORT_SYMBOL(udp_memory_allocated);

#define MAX_UDP_PORTS 65536
#define PORTS_PER_CHAIN (MAX_UDP_PORTS / UDP_HTABLE_SIZE_MIN)

static int udp_lib_lport_inuse(struct net *net, __u16 num,
			       const struct udp_hslot *hslot,
			       unsigned long *bitmap,
			       struct sock *sk,
			       int (*saddr_comp)(const struct sock *sk1,
						 const struct sock *sk2),
			       unsigned int log)
{
	struct sock *sk2;
	struct hlist_nulls_node *node;
	kuid_t uid = sock_i_uid(sk);

	sk_nulls_for_each(sk2, node, &hslot->head) {
		if (net_eq(sock_net(sk2), net) &&
		    sk2 != sk &&
		    (bitmap || udp_sk(sk2)->udp_port_hash == num) &&
		    (!sk2->sk_reuse || !sk->sk_reuse) &&
		    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if ||
		     sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
		    (!sk2->sk_reuseport || !sk->sk_reuseport ||
		     !uid_eq(uid, sock_i_uid(sk2))) &&
		    saddr_comp(sk, sk2)) {
			if (!bitmap)
				return 1;
			__set_bit(udp_sk(sk2)->udp_port_hash >> log, bitmap);
		}
	}
	return 0;
}

/*
 * Note: we still hold spinlock of primary hash chain, so no other writer
 * can insert/delete a socket with local_port == num
 */
static int udp_lib_lport_inuse2(struct net *net, __u16 num,
				struct udp_hslot *hslot2,
				struct sock *sk,
				int (*saddr_comp)(const struct sock *sk1,
						  const struct sock *sk2))
{
	struct sock *sk2;
	struct hlist_nulls_node *node;
	kuid_t uid = sock_i_uid(sk);
	int res = 0;

	spin_lock(&hslot2->lock);
	udp_portaddr_for_each_entry(sk2, node, &hslot2->head) {
		if (net_eq(sock_net(sk2), net) &&
		    sk2 != sk &&
		    (udp_sk(sk2)->udp_port_hash == num) &&
		    (!sk2->sk_reuse || !sk->sk_reuse) &&
		    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if ||
		     sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
		    (!sk2->sk_reuseport || !sk->sk_reuseport ||
		     !uid_eq(uid, sock_i_uid(sk2))) &&
		    saddr_comp(sk, sk2)) {
			res = 1;
			break;
		}
	}
	spin_unlock(&hslot2->lock);
	return res;
}

/**
 *  udp_lib_get_port  -  UDP/-Lite port lookup for IPv4 and IPv6
 *
 *  @sk:          socket struct in question
 *  @snum:        port number to look up
 *  @saddr_comp:  AF-dependent comparison of bound local IP addresses
 *  @hash2_nulladdr: AF-dependent hash value in secondary hash chains,
 *                   with NULL address
 */
int udp_lib_get_port(struct sock *sk, unsigned short snum,
		     int (*saddr_comp)(const struct sock *sk1,
				       const struct sock *sk2),
		     unsigned int hash2_nulladdr)
{
	struct udp_hslot *hslot, *hslot2;
	struct udp_table *udptable = sk->sk_prot->h.udp_table;
	int    error = 1;
	struct net *net = sock_net(sk);

	if (!snum) {
		int low, high, remaining;
		unsigned int rand;
		unsigned short first, last;
		DECLARE_BITMAP(bitmap, PORTS_PER_CHAIN);

		inet_get_local_port_range(net, &low, &high);
		remaining = (high - low) + 1;

		rand = prandom_u32();
		first = reciprocal_scale(rand, remaining) + low;
		/*
		 * force rand to be an odd multiple of UDP_HTABLE_SIZE
		 */
		rand = (rand | 1) * (udptable->mask + 1);
		last = first + udptable->mask + 1;
		do {
			hslot = udp_hashslot(udptable, net, first);
			bitmap_zero(bitmap, PORTS_PER_CHAIN);
			spin_lock_bh(&hslot->lock);
			udp_lib_lport_inuse(net, snum, hslot, bitmap, sk,
					    saddr_comp, udptable->log);

			snum = first;
			/*
			 * Iterate on all possible values of snum for this hash.
			 * Using steps of an odd multiple of UDP_HTABLE_SIZE
			 * give us randomization and full range coverage.
			 */
			do {
				if (low <= snum && snum <= high &&
				    !test_bit(snum >> udptable->log, bitmap) &&
				    !inet_is_local_reserved_port(net, snum))
					goto found;
				snum += rand;
			} while (snum != first);
			spin_unlock_bh(&hslot->lock);
		} while (++first != last);
		goto fail;
	} else {
		hslot = udp_hashslot(udptable, net, snum);
		spin_lock_bh(&hslot->lock);
		if (hslot->count > 10) {
			int exist;
			unsigned int slot2 = udp_sk(sk)->udp_portaddr_hash ^ snum;

			slot2          &= udptable->mask;
			hash2_nulladdr &= udptable->mask;

			hslot2 = udp_hashslot2(udptable, slot2);
			if (hslot->count < hslot2->count)
				goto scan_primary_hash;

			exist = udp_lib_lport_inuse2(net, snum, hslot2,
						     sk, saddr_comp);
			if (!exist && (hash2_nulladdr != slot2)) {
				hslot2 = udp_hashslot2(udptable, hash2_nulladdr);
				exist = udp_lib_lport_inuse2(net, snum, hslot2,
							     sk, saddr_comp);
			}
			if (exist)
				goto fail_unlock;
			else
				goto found;
		}
scan_primary_hash:
		if (udp_lib_lport_inuse(net, snum, hslot, NULL, sk,
					saddr_comp, 0))
			goto fail_unlock;
	}
found:
	inet_sk(sk)->inet_num = snum;
	udp_sk(sk)->udp_port_hash = snum;
	udp_sk(sk)->udp_portaddr_hash ^= snum;
	if (sk_unhashed(sk)) {
		sk_nulls_add_node_rcu(sk, &hslot->head);
		hslot->count++;
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);
		spin_lock(&hslot2->lock);
		hlist_nulls_add_head_rcu(&udp_sk(sk)->udp_portaddr_node,
					 &hslot2->head);
		hslot2->count++;
		spin_unlock(&hslot2->lock);
	}
	error = 0;
fail_unlock:
	spin_unlock_bh(&hslot->lock);
fail:
	return error;
}
EXPORT_SYMBOL(udp_lib_get_port);

static int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
{
	struct inet_sock *inet1 = inet_sk(sk1), *inet2 = inet_sk(sk2);

	return 	(!ipv6_only_sock(sk2)  &&
		 (!inet1->inet_rcv_saddr || !inet2->inet_rcv_saddr ||
		   inet1->inet_rcv_saddr == inet2->inet_rcv_saddr));
}

static u32 udp4_portaddr_hash(const struct net *net, __be32 saddr,
			      unsigned int port)
{
	return jhash_1word((__force u32)saddr, net_hash_mix(net)) ^ port;
}

int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr =
		udp4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
	unsigned int hash2_partial =
		udp4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
	return udp_lib_get_port(sk, snum, ipv4_rcv_saddr_equal, hash2_nulladdr);
}

static inline int compute_score(struct sock *sk, struct net *net,
				__be32 saddr, unsigned short hnum, __be16 sport,
				__be32 daddr, __be16 dport, int dif)
{
	int score;
	struct inet_sock *inet;
	/* 比较名称空间，端口等 */
	if (!net_eq(sock_net(sk), net) ||
	    udp_sk(sk)->udp_port_hash != hnum ||
	    ipv6_only_sock(sk))
		return -1;
	/* 若套接字指明为PF_INET，则加1分 */
	score = (sk->sk_family == PF_INET) ? 2 : 1;
	inet = inet_sk(sk);
	/* 套接字绑定了接收地址 */
	if (inet->inet_rcv_saddr) {
		/* 如果数据包的目的地址与绑定接收地址不符，则分数为-1，相同则增加4分。*/
		if (inet->inet_rcv_saddr != daddr)
			return -1;
		score += 4;
	}
	 /* 套接字设置了对端目的地址 */
	if (inet->inet_daddr) {
		/* 如果数据包的源地址与设置的目的地址不同，则分数为-1，相同则增加4分 */
		if (inet->inet_daddr != saddr)
			return -1;
		score += 4;
	}
	/* 套接字设置了对端目的端口 */
	if (inet->inet_dport) {
		/* 如果数据包的源端口与设置的目的端口不同，则分数为-1，相同则增加4分 */
		if (inet->inet_dport != sport)
			return -1;
		score += 4;
	}
	/* 套接字绑定了网卡 */
	if (sk->sk_bound_dev_if) {
		 /* 如果接受数据包的网卡与绑定网卡不同，则分数为-1，相同则增加4分 */
		if (sk->sk_bound_dev_if != dif)
			return -1;
		score += 4;
	}
	if (sk->sk_incoming_cpu == raw_smp_processor_id())
		score++;
	return score;
}

/*
 * In this second variant, we check (daddr, dport) matches (inet_rcv_sadd, inet_num)
 */
static inline int compute_score2(struct sock *sk, struct net *net,
				 __be32 saddr, __be16 sport,
				 __be32 daddr, unsigned int hnum, int dif)
{
	int score;
	struct inet_sock *inet;

	if (!net_eq(sock_net(sk), net) ||
	    ipv6_only_sock(sk))
		return -1;

	inet = inet_sk(sk);

	if (inet->inet_rcv_saddr != daddr ||
	    inet->inet_num != hnum)
		return -1;

	score = (sk->sk_family == PF_INET) ? 2 : 1;

	if (inet->inet_daddr) {
		if (inet->inet_daddr != saddr)
			return -1;
		score += 4;
	}

	if (inet->inet_dport) {
		if (inet->inet_dport != sport)
			return -1;
		score += 4;
	}

	if (sk->sk_bound_dev_if) {
		if (sk->sk_bound_dev_if != dif)
			return -1;
		score += 4;
	}

	if (sk->sk_incoming_cpu == raw_smp_processor_id())
		score++;

	return score;
}

static u32 udp_ehashfn(const struct net *net, const __be32 laddr,
		       const __u16 lport, const __be32 faddr,
		       const __be16 fport)
{
	static u32 udp_ehash_secret __read_mostly;

	net_get_random_once(&udp_ehash_secret, sizeof(udp_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport,
			      udp_ehash_secret + net_hash_mix(net));
}

/* called with read_rcu_lock() */
static struct sock *udp4_lib_lookup2(struct net *net,
		__be32 saddr, __be16 sport,
		__be32 daddr, unsigned int hnum, int dif,
		struct udp_hslot *hslot2, unsigned int slot2)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	int score, badness, matches = 0, reuseport = 0;
	u32 hash = 0;

begin:
	result = NULL;
	badness = 0;
	udp_portaddr_for_each_entry_rcu(sk, node, &hslot2->head) {
		score = compute_score2(sk, net, saddr, sport,
				      daddr, hnum, dif);
		if (score > badness) {
			result = sk;
			badness = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				hash = udp_ehashfn(net, daddr, hnum,
						   saddr, sport);
				matches = 1;
			}
		} else if (score == badness && reuseport) {
			matches++;
			if (reciprocal_scale(hash, matches) == 0)
				result = sk;
			hash = next_pseudo_random32(hash);
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot2)
		goto begin;
	if (result) {
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(compute_score2(result, net, saddr, sport,
				  daddr, hnum, dif) < badness)) {
			sock_put(result);
			goto begin;
		}
	}
	return result;
}

/* UDP is nearly always wildcards out the wazoo, it makes no sense to try
 * harder than this. -DaveM
 */
struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr,
		__be16 sport, __be32 daddr, __be16 dport,
		int dif, struct udp_table *udptable)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(dport);
	 /* 使用目的端口确定hash桶索引 */
	unsigned int hash2, slot2, slot = udp_hashfn(net, hnum, udptable->mask);
	struct udp_hslot *hslot2, *hslot = &udptable->hash[slot];
	int score, badness, matches = 0, reuseport = 0;
	u32 hash = 0;

	rcu_read_lock();
	/* 若该桶的套接字个数多于10个，则需要再次定位 */
	if (hslot->count > 10) {
		 /* 使用目的地址和目的端口确定hash桶索引 */
		hash2 = udp4_portaddr_hash(net, daddr, hnum);
		slot2 = hash2 & udptable->mask;
	/*
UDP套接字表维护了两个hash表：
 第一个hash表，使用端口来索引
 第二个hash表，使用地址+端口来索引
 在进行UDP套接字匹配的时候，优先使用第一个hash表，因为第一个hash表使用的是端口进行散
 列索引，那么只要端口相同，无论是监听的指定IP还是任意IP，都可以在一个桶中进行匹配。但
 是由于端口只有65535种可能，所以可能导致不够分散，一个桶的套接字个数会比较多。而第二个
 hash表是使用地址+端口来索引的，因此理论上套接字的分布会比第一个hash表更加分散。
 因此当第一个hash表对应桶的套接字多于10个时，内核会尝试去第二个hash表中进行匹配查找。
 */
		hslot2 = &udptable->hash2[slot2];
	/* 尽管第二个hash表理论上会比第一个hash表分散，但是如果实际上第二个表的桶中套接字个数大于第一个表的桶中套接字个数，
那么这时还是利用第一个hash表进行匹配 */
		if (hslot->count < hslot2->count)
			goto begin;
		/* 在第二个hash表的桶中匹配查找套接字 */
		result = udp4_lib_lookup2(net, saddr, sport,
					  daddr, hnum, dif,
					  hslot2, slot2);
		if (!result) {
			/* 若利用指定的IP和端口在该桶中没能找到匹配的套接字，则通常使用任意IP+端口来进行散列索引 */
			hash2 = udp4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
			slot2 = hash2 & udptable->mask;
			hslot2 = &udptable->hash2[slot2];
			/* 还是要与第一个hash桶中的个数进行比较 */
			if (hslot->count < hslot2->count)
				goto begin;
			/* 在第二个hash表中使用任意IP+端口进行匹配查找 */
			result = udp4_lib_lookup2(net, saddr, sport,
						  htonl(INADDR_ANY), hnum, dif,
						  hslot2, slot2);
		}
		rcu_read_unlock();
		return result;
	}
begin:
	result = NULL;
	badness = 0;
	/* 在第一个hash表的桶中进行查找 */
	sk_nulls_for_each_rcu(sk, node, &hslot->head) {
	 /* 计算该套接字的匹配得分 */
		score = compute_score(sk, net, saddr, hnum, sport,
				      daddr, dport, dif);
		if (score > badness) {
			result = sk;
			badness = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				hash = udp_ehashfn(net, daddr, hnum,
						   saddr, sport);
				matches = 1;
			}
		} else if (score == badness && reuseport) {
			matches++;
			if (reciprocal_scale(hash, matches) == 0)
				result = sk;
			hash = next_pseudo_random32(hash);
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	 /*检查在查找的过程中，是否遇到了某个套接字被移到另外一个桶内的情况。这时，需要重新进行匹配。*/
	if (get_nulls_value(node) != slot)
		goto begin;
	 /* 找到了匹配的套接字 */
	if (result) {
		/* 增加套接字引用计数 */
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		 /* 再次计算套接字得分，如小于最大分数，则重新匹配查找。之所以做二次检查，也是为了防止在匹配与增加引用的过程中，套接字发生变化。 */
		else if (unlikely(compute_score(result, net, saddr, hnum, sport,
				  daddr, dport, dif) < badness)) {
			sock_put(result);
			goto begin;
		}
	}
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL_GPL(__udp4_lib_lookup);

static inline struct sock *__udp4_lib_lookup_skb(struct sk_buff *skb,
						 __be16 sport, __be16 dport,
						 struct udp_table *udptable)
{
	const struct iphdr *iph = ip_hdr(skb);

	return __udp4_lib_lookup(dev_net(skb_dst(skb)->dev), iph->saddr, sport,
				 iph->daddr, dport, inet_iif(skb),
				 udptable);
}

struct sock *udp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
			     __be32 daddr, __be16 dport, int dif)
{
	return __udp4_lib_lookup(net, saddr, sport, daddr, dport, dif, &udp_table);
}
EXPORT_SYMBOL_GPL(udp4_lib_lookup);

static inline bool __udp_is_mcast_sock(struct net *net, struct sock *sk,
				       __be16 loc_port, __be32 loc_addr,
				       __be16 rmt_port, __be32 rmt_addr,
				       int dif, unsigned short hnum)
{
	struct inet_sock *inet = inet_sk(sk);

	if (!net_eq(sock_net(sk), net) ||
	    udp_sk(sk)->udp_port_hash != hnum ||
	    (inet->inet_daddr && inet->inet_daddr != rmt_addr) ||
	    (inet->inet_dport != rmt_port && inet->inet_dport) ||
	    (inet->inet_rcv_saddr && inet->inet_rcv_saddr != loc_addr) ||
	    ipv6_only_sock(sk) ||
	    (sk->sk_bound_dev_if && sk->sk_bound_dev_if != dif))
		return false;
	if (!ip_mc_sf_allow(sk, loc_addr, rmt_addr, dif))
		return false;
	return true;
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition.  If err < 0 then the socket should
 * be closed and the error returned to the user.  If err > 0
 * it's just the icmp type << 8 | icmp code.
 * Header points to the ip header of the error packet. We move
 * on past this. Then (as it used to claim before adjustment)
 * header points to the first 8 bytes of the udp header.  We need
 * to find the appropriate port.
 */

void __udp4_lib_err(struct sk_buff *skb, u32 info, struct udp_table *udptable)
{
	struct inet_sock *inet;
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	struct udphdr *uh = (struct udphdr *)(skb->data+(iph->ihl<<2));
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	struct sock *sk;
	int harderr;
	int err;
	struct net *net = dev_net(skb->dev);

	sk = __udp4_lib_lookup(net, iph->daddr, uh->dest,
			iph->saddr, uh->source, skb->dev->ifindex, udptable);
	if (!sk) {
		ICMP_INC_STATS_BH(net, ICMP_MIB_INERRORS);
		return;	/* No socket for error */
	}

	err = 0;
	harderr = 0;
	inet = inet_sk(sk);

	switch (type) {
	default:
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	case ICMP_SOURCE_QUENCH:
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		harderr = 1;
		break;
	case ICMP_DEST_UNREACH:
		if (code == ICMP_FRAG_NEEDED) { /* Path MTU discovery */
			ipv4_sk_update_pmtu(skb, sk, info);
			if (inet->pmtudisc != IP_PMTUDISC_DONT) {
				err = EMSGSIZE;
				harderr = 1;
				break;
			}
			goto out;
		}
		err = EHOSTUNREACH;
		if (code <= NR_ICMP_UNREACH) {
			harderr = icmp_err_convert[code].fatal;
			err = icmp_err_convert[code].errno;
		}
		break;
	case ICMP_REDIRECT:
		ipv4_sk_redirect(skb, sk);
		goto out;
	}

	/*
	 *      RFC1122: OK.  Passes ICMP errors back to application, as per
	 *	4.1.3.3.
	 */
	if (!inet->recverr) {
		if (!harderr || sk->sk_state != TCP_ESTABLISHED)
			goto out;
	} else
		ip_icmp_error(sk, skb, err, uh->dest, info, (u8 *)(uh+1));

	sk->sk_err = err;
	sk->sk_error_report(sk);
out:
	sock_put(sk);
}

void udp_err(struct sk_buff *skb, u32 info)
{
	__udp4_lib_err(skb, info, &udp_table);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
void udp_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip_flush_pending_frames(sk);
	}
}
EXPORT_SYMBOL(udp_flush_pending_frames);

/**
 * 	udp4_hwcsum  -  handle outgoing HW checksumming
 * 	@skb: 	sk_buff containing the filled-in UDP header
 * 	        (checksum field must be zeroed out)
 *	@src:	source IP address
 *	@dst:	destination IP address
 */
void udp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst)
{
	struct udphdr *uh = udp_hdr(skb);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int hlen = len;
	__wsum csum = 0;

	if (!skb_has_frag_list(skb)) {
		/*
		 * Only one fragment on the socket.
		 */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(src, dst, len,
					       IPPROTO_UDP, 0);
	} else {
		struct sk_buff *frags;

		/*
		 * HW-checksum won't work as there are two or more
		 * fragments on the socket so that all csums of sk_buffs
		 * should be together
		 */
		skb_walk_frags(skb, frags) {
			csum = csum_add(csum, frags->csum);
			hlen -= frags->len;
		}

		csum = skb_checksum(skb, offset, hlen, csum);
		skb->ip_summed = CHECKSUM_NONE;

		uh->check = csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}
EXPORT_SYMBOL_GPL(udp4_hwcsum);

/* Function to set UDP checksum for an IPv4 UDP packet. This is intended
 * for the simple case like when setting the checksum for a UDP tunnel.
 */
void udp_set_csum(bool nocheck, struct sk_buff *skb,
		  __be32 saddr, __be32 daddr, int len)
{
	struct udphdr *uh = udp_hdr(skb);

	if (nocheck)
		uh->check = 0;
	else if (skb_is_gso(skb))
		uh->check = ~udp_v4_check(len, saddr, daddr, 0);
	else if (skb_dst(skb) && skb_dst(skb)->dev &&
		 (skb_dst(skb)->dev->features & NETIF_F_V4_CSUM)) {

		BUG_ON(skb->ip_summed == CHECKSUM_PARTIAL);

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~udp_v4_check(len, saddr, daddr, 0);
	} else {
		__wsum csum;

		BUG_ON(skb->ip_summed == CHECKSUM_PARTIAL);

		uh->check = 0;
		csum = skb_checksum(skb, 0, len, 0);
		uh->check = udp_v4_check(len, saddr, daddr, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;

		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
}
EXPORT_SYMBOL(udp_set_csum);

static int udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct udphdr *uh;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	__wsum csum = 0;

	/*
	 * Create a UDP header
	 */
	 /* 创建UDP报文头部 */
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = fl4->fl4_dport;
	uh->len = htons(len);
	uh->check = 0;
	/*　如果是轻量级UDP协议，则调用相应的校验和计算函数*/
	if (is_udplite)  				 /*     UDP-Lite      */
		csum = udplite_csum(skb);
	 /* 禁止了UDP校验和 */
	else if (sk->sk_no_check_tx && !skb_is_gso(skb)) {   /* UDP csum off */

		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
		/* 硬件支持校验和的计算 */
		udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
		goto send;

	} else
		/* 一般情况下的校验和计算 */
		csum = udp_csum(skb);

	/* add protocol-dependent pseudo-header */
		/* 计算UDP的校验和，需要考虑伪首部 */
	uh->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
				      sk->sk_protocol, csum);
	 /* 如果校验和为0，则需要将其设置为0xFFFF。因为UDP的零校验和，有特殊的含义，表示没有校验和。*/
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	/* 发送IP数据包 */
	err = ip_send_skb(sock_net(sk), skb);
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) {
			UDP_INC_STATS_USER(sock_net(sk),
					   UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP_INC_STATS_USER(sock_net(sk),
				   UDP_MIB_OUTDATAGRAMS, is_udplite);
	return err;
}

/*
 * Push out all pending data as one UDP datagram. Socket is locked.
 */
int udp_push_pending_frames(struct sock *sk)
{
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	struct sk_buff *skb;
	int err = 0;

	skb = ip_finish_skb(sk, fl4);
	if (!skb)
		goto out;

	err = udp_send_skb(skb, fl4);

out:
	up->len = 0;
	up->pending = 0;
	return err;
}
EXPORT_SYMBOL(udp_push_pending_frames);

int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	/* 从inet通用套接字得到inet套接字 */
	struct inet_sock *inet = inet_sk(sk);
	 /* 从inet通用套接字得到UDP套接字 */
	struct udp_sock *up = udp_sk(sk);
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_udplite = IS_UDPLITE(sk);
	/* 是否有数据包聚合：或者UDP套接字设置了聚合选项，或者数据包消息指明了还有更多数据 */
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;
	/* 数据包长度检查 */
	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */
	/* 检查消息标志，UDP不支持带外数据 */
	if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;
	  /* 设置正确的分片函数 */
	getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
	/* 该UDP套接字还有待发的数据包 */
	if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);	
		 /*  常见的上锁双重检查机制 */
		if (likely(up->pending)) {
			/* 若待发的数据不是INET数据，则报错返回 */
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			 /* 调到追加数据处 */
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address.
	 */
	 /* 若指定了目标地址，则对其进行校验 */
	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
		/* 检查长度 */
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		 /* 检查协议族。目前只支持AF_INET和AF_UNSPEC协议族 */
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}
		 /* 若通过了检查，则设置目的地址与目的端口 */
		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
	 /* 如果没有指定目的地址和目的端口，则当前套接字的状态必须是已连接，即已经调用过connect设置了目的地址 */
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		 /* 使用之前设置的目的地址和目的端口 */
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		connected = 1;
	}
	ipc.addr = inet->inet_saddr;

	ipc.oif = sk->sk_bound_dev_if;
	/* 设置时间戳标志 */
	sock_tx_timestamp(sk, &ipc.tx_flags);
	/* 发送的消息包含控制数据 */

	if (msg->msg_controllen) {
		 /* 虽然这个函数的名字叫作send，其实并没有任何发送动作，而只是将控制消息设置到ipc中 */
		err = ip_cmsg_send(sock_net(sk), msg, &ipc,
				   sk->sk_family == AF_INET6);
		if (unlikely(err)) {
			kfree(ipc.opt);
			return err;
		}
		 /* 设置释放ipc.opt的标志 */
		if (ipc.opt)
			free = 1;
		connected = 0;
	}
	if (!ipc.opt) {
		 /* 如果没有使用控制消息指定IP选项，则检查套接字的IP选项设置。如果有，则使用套接字的IP选项 */
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;
	/* 设置了严格路由 */
	if (ipc.opt && ipc.opt->opt.srr) {
		if (!daddr) {
			err = -EINVAL;
			goto out_free;
		}
		faddr = ipc.opt->opt.faddr;
		connected = 0;
	}
	tos = get_rttos(&ipc, inet);
	/*
若有下列情况之一的：
1）套接字设置了本地路由标志。
2）发送消息时，指明了不做路由。
3）设置了IP严格路由选项。
则设置不查找路由标志
*/
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->opt.is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}
	 /* 如果目的地址是多播地址 */
	if (ipv4_is_multicast(daddr)) {
		/* 若未指定出口接口，则使用套接字的多播接口索引 */
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		/* 若源地址为0，则使用套接字的多播地址 */
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	} else if (!ipc.oif)
		ipc.oif = inet->uc_index;
	/* 连接标志为真，即此次发送的数据包与上次的地址相同，则判断保存的路由缓存是否还可用。*/
	if (connected)
		 /* 从套接字检查并获得保存的路由缓存 */
		rt = (struct rtable *)sk_dst_check(sk, 0);
	 /* 若目前路由缓存为空，则需要查找路由 */
	if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);

		fl4 = &fl4_stack;
		 /* 根据套接字和数据包的信息，初始化flowi4—这是查找路由的key */
		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   flow_flags,
				   faddr, saddr, dport, inet->inet_sport);

		if (!saddr && ipc.oif) {
			err = l3mdev_get_saddr(net, ipc.oif, fl4);
			if (err < 0)
				goto out;
		}

		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		 /* 查找出口路由 */
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			//查找路由失败
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		 /* 若路由是广播路由，并且套接字非广播套接字 */
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			/* 若该UDP为已连接状态，则保存这个路由缓存 */
			sk_dst_set(sk, dst_clone(&rt->dst));
	}
/* 如果数据包设置了MSG_CONFIRM标志，则是要告诉链路层，对端是可达的。调到do_confrim处，可
以发现其实现方法是在有neibour信息的情况下，直接更新neibour确认时间戳为当前时间。 */
	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;

	/* Lockless fast path for the non-corking case. */
	 /* 没有使用cork选项或MSG_MORE标志。这也是最常见的情况。 */
	if (!corkreq) {
		/* 每次都生成一个UDP数据包 */
		skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
				  sizeof(struct udphdr), &ipc, &rt,
				  msg->msg_flags);
		err = PTR_ERR(skb);
		/* 成功生成了数据包 */
		if (!IS_ERR_OR_NULL(skb))
			err = udp_send_skb(skb, fl4);
		goto out;
	}

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		/*现在马上要做cork处理，但发现套接字已经cork了。因此这是一个应用程序bug。释放套接字锁，并返回错误。*/
		release_sock(sk);

		net_dbg_ratelimited("cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	  /* 设置cork中的流信息 */
	fl4 = &inet->cork.fl.u.ip4;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->fl4_dport = dport;
	fl4->fl4_sport = inet->inet_sport;
	up->pending = AF_INET;

do_append_data:
	/* 增加UDP数据长度 */
	up->len += ulen;
	/* 向IP数据包中追加新的数据 */
	err = ip_append_data(sk, fl4, getfrag, msg, ulen,
			     sizeof(struct udphdr), &ipc, &rt,
			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)// 若发生错误，则丢弃所有未决的数据包
		udp_flush_pending_frames(sk);
	else if (!corkreq)// 若不在cork即阻塞，则发送所有未决的数据包
		err = udp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		/* 若没有未决的数据包，则重置未决标志 */
		up->pending = 0;
	release_sock(sk);

out:
	 /* 清理工作，释放各种资源，并增加相应的统计计数 */
	ip_rt_put(rt);
out_free:
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS_USER(sock_net(sk),
				UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

do_confirm:
	dst_confirm(&rt->dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}
EXPORT_SYMBOL(udp_sendmsg);

int udp_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	int ret;

	if (flags & MSG_SENDPAGE_NOTLAST)
		flags |= MSG_MORE;

	if (!up->pending) {
		struct msghdr msg = {	.msg_flags = flags|MSG_MORE };

		/* Call udp_sendmsg to specify destination address which
		 * sendpage interface can't pass.
		 * This will succeed only when the socket is connected.
		 */
		ret = udp_sendmsg(sk, &msg, 0);
		if (ret < 0)
			return ret;
	}

	lock_sock(sk);

	if (unlikely(!up->pending)) {
		release_sock(sk);

		net_dbg_ratelimited("udp cork app bug 3\n");
		return -EINVAL;
	}

	ret = ip_append_page(sk, &inet->cork.fl.u.ip4,
			     page, offset, size, flags);
	if (ret == -EOPNOTSUPP) {
		release_sock(sk);
		return sock_no_sendpage(sk->sk_socket, page, offset,
					size, flags);
	}
	if (ret < 0) {
		udp_flush_pending_frames(sk);
		goto out;
	}

	up->len += size;
	if (!(up->corkflag || (flags&MSG_MORE)))
		ret = udp_push_pending_frames(sk);
	if (!ret)
		ret = size;
out:
	release_sock(sk);
	return ret;
}

/**
 *	first_packet_length	- return length of first packet in receive queue
 *	@sk: socket
 *
 *	Drops all bad checksum frames, until a valid one is found.
 *	Returns the length of found skb, or 0 if none is found.
 */
static unsigned int first_packet_length(struct sock *sk)
{
	struct sk_buff_head list_kill, *rcvq = &sk->sk_receive_queue;
	struct sk_buff *skb;
	unsigned int res;

	__skb_queue_head_init(&list_kill);

	spin_lock_bh(&rcvq->lock);
	while ((skb = skb_peek(rcvq)) != NULL &&
		udp_lib_checksum_complete(skb)) {
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_CSUMERRORS,
				 IS_UDPLITE(sk));
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS,
				 IS_UDPLITE(sk));
		atomic_inc(&sk->sk_drops);
		__skb_unlink(skb, rcvq);
		__skb_queue_tail(&list_kill, skb);
	}
	res = skb ? skb->len : 0;
	spin_unlock_bh(&rcvq->lock);

	if (!skb_queue_empty(&list_kill)) {
		bool slow = lock_sock_fast(sk);

		__skb_queue_purge(&list_kill);
		sk_mem_reclaim_partial(sk);
		unlock_sock_fast(sk, slow);
	}
	return res;
}

/*
 *	IOCTL requests applicable to the UDP protocol
 */

int udp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	{
		int amount = sk_wmem_alloc_get(sk);

		return put_user(amount, (int __user *)arg);
	}

	case SIOCINQ:
	{
		unsigned int amount = first_packet_length(sk);

		if (amount)
			/*
			 * We will only return the amount
			 * of this packet since that is all
			 * that will be read.
			 */
			amount -= sizeof(struct udphdr);

		return put_user(amount, (int __user *)arg);
	}

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}
EXPORT_SYMBOL(udp_ioctl);

/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */

int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	/* 让sin指向msg_name，用于保存发送端地址 */
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int peeked, off = 0;
	int err;
	int is_udplite = IS_UDPLITE(sk);
	bool checksum_valid = false;
	bool slow;
	/* 用户设置了MSG_ERRQUEUE标志，用于接收错误消息。因为这个应用并不广泛，因此在此忽略这种情况，不进入该函数。 */
	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len, addr_len);

try_again:
	/* 接收了一个数据报文 */
	skb = __skb_recv_datagram(sk, flags | (noblock ? MSG_DONTWAIT : 0),
				  &peeked, &off, &err);
	if (!skb)
		goto out;
	 /* 得到UDP的数据长度 */
	ulen = skb->len - sizeof(struct udphdr);
	/* 要复制的长度被初始化为用户指定的长度 */
	copied = len;
	 /* 若复制长度大于UDP的数据长度，则调整复制长度为数据长度。若复制长度小于数据长度，则设置标志MSG_TRUNC，表示数据发生了截断。 */
	if (copied > ulen)
		copied = ulen;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	/*
	 * If checksum is needed at all, try to do it while copying the
	 * data.  If the data is truncated, or if we only want a partial
	 * coverage checksum (UDP-Lite), do it before the copy.
	 */
	  /*    如果发生了数据截断，或者我们只需要部分覆盖的校验和，那么就在
	  复制前进行校验。
	  */

	if (copied < ulen || UDP_SKB_CB(skb)->partial_cov) {
		 /* 进行UDP校验和校验 */
		checksum_valid = !udp_lib_checksum_complete(skb);
		if (!checksum_valid)
			goto csum_copy_err;
	}
	/* 判断是否需要进行校验和校验 */
	if (checksum_valid || skb_csum_unnecessary(skb))
		 /*  若不需要进行校验，则直接复制数据包内容到msg_iov中 */
		err = skb_copy_datagram_msg(skb, sizeof(struct udphdr),
					    msg, copied);
	else {
		 /* 复制数据包内容的同时，进行校验和校验 */
		err = skb_copy_and_csum_datagram_msg(skb, sizeof(struct udphdr),
						     msg);

		if (err == -EINVAL)
			goto csum_copy_err;
	}
	/* 复制错误检查 */
	if (unlikely(err)) {
		trace_kfree_skb(skb, udp_recvmsg);
		if (!peeked) {
			atomic_inc(&sk->sk_drops);
			UDP_INC_STATS_USER(sock_net(sk),
					   UDP_MIB_INERRORS, is_udplite);
		}
		goto out_free;
	}
	/* 如果不是peek动作，则增加相应的统计计数 */
	if (!peeked)
		UDP_INC_STATS_USER(sock_net(sk),
				UDP_MIB_INDATAGRAMS, is_udplite);
	/* 更新套接字的最新的接收数据包时间戳及丢包消息 */
	sock_recv_ts_and_drops(msg, sk, skb);

	/* Copy the address. */
	 /* 如果用户指定了保存对端地址的参数，则从数据包中复制地址和端口信息 */
	if (sin) {
		sin->sin_family = AF_INET;
		sin->sin_port = udp_hdr(skb)->source;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
		*addr_len = sizeof(*sin);
	}
	/* 设置了接收控制消息 */
	if (inet->cmsg_flags)
		ip_cmsg_recv_offset(msg, skb, sizeof(struct udphdr), off);
	/* 设置了已复制的字节长度 */
	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

out_free:
	/* 释放接收到的这个数据包 */
	skb_free_datagram_locked(sk, skb);
out:
	 /* 返回读取的字节数 */
	return err;
	/* 错误处理 */
csum_copy_err:
	slow = lock_sock_fast(sk);
	if (!skb_kill_datagram(sk, skb, flags)) {
		UDP_INC_STATS_USER(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
		UDP_INC_STATS_USER(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	}
	unlock_sock_fast(sk, slow);

	/* starting over for a new packet, but check if we need to yield */
	cond_resched();
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}

int udp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	/*
	 *	1003.1g - break association.
	 */

	sk->sk_state = TCP_CLOSE;
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sock_rps_reset_rxhash(sk);
	sk->sk_bound_dev_if = 0;
	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
		sk->sk_prot->unhash(sk);
		inet->inet_sport = 0;
	}
	sk_dst_reset(sk);
	return 0;
}
EXPORT_SYMBOL(udp_disconnect);

void udp_lib_unhash(struct sock *sk)
{
	if (sk_hashed(sk)) {
		struct udp_table *udptable = sk->sk_prot->h.udp_table;
		struct udp_hslot *hslot, *hslot2;

		hslot  = udp_hashslot(udptable, sock_net(sk),
				      udp_sk(sk)->udp_port_hash);
		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);

		spin_lock_bh(&hslot->lock);
		if (sk_nulls_del_node_init_rcu(sk)) {
			hslot->count--;
			inet_sk(sk)->inet_num = 0;
			sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

			spin_lock(&hslot2->lock);
			hlist_nulls_del_init_rcu(&udp_sk(sk)->udp_portaddr_node);
			hslot2->count--;
			spin_unlock(&hslot2->lock);
		}
		spin_unlock_bh(&hslot->lock);
	}
}
EXPORT_SYMBOL(udp_lib_unhash);

/*
 * inet_rcv_saddr was changed, we must rehash secondary hash
 */
void udp_lib_rehash(struct sock *sk, u16 newhash)
{
	if (sk_hashed(sk)) {
		struct udp_table *udptable = sk->sk_prot->h.udp_table;
		struct udp_hslot *hslot, *hslot2, *nhslot2;

		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);
		nhslot2 = udp_hashslot2(udptable, newhash);
		udp_sk(sk)->udp_portaddr_hash = newhash;
		if (hslot2 != nhslot2) {
			hslot = udp_hashslot(udptable, sock_net(sk),
					     udp_sk(sk)->udp_port_hash);
			/* we must lock primary chain too */
			spin_lock_bh(&hslot->lock);

			spin_lock(&hslot2->lock);
			hlist_nulls_del_init_rcu(&udp_sk(sk)->udp_portaddr_node);
			hslot2->count--;
			spin_unlock(&hslot2->lock);

			spin_lock(&nhslot2->lock);
			hlist_nulls_add_head_rcu(&udp_sk(sk)->udp_portaddr_node,
						 &nhslot2->head);
			nhslot2->count++;
			spin_unlock(&nhslot2->lock);

			spin_unlock_bh(&hslot->lock);
		}
	}
}
EXPORT_SYMBOL(udp_lib_rehash);

static void udp_v4_rehash(struct sock *sk)
{
	u16 new_hash = udp4_portaddr_hash(sock_net(sk),
					  inet_sk(sk)->inet_rcv_saddr,
					  inet_sk(sk)->inet_num);
	udp_lib_rehash(sk, new_hash);
}

static int __udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	if (inet_sk(sk)->inet_daddr) {
		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
		sk_incoming_cpu_update(sk);
	}

	rc = sock_queue_rcv_skb(sk, skb);
	if (rc < 0) {
		int is_udplite = IS_UDPLITE(sk);

		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
					 is_udplite);
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
		kfree_skb(skb);
		trace_udp_fail_queue_rcv_skb(rc, sk);
		return -1;
	}

	return 0;

}

static struct static_key udp_encap_needed __read_mostly;
void udp_encap_enable(void)
{
	if (!static_key_enabled(&udp_encap_needed))
		static_key_slow_inc(&udp_encap_needed);
}
EXPORT_SYMBOL(udp_encap_enable);

/* returns:
 *  -1: error
 *   0: success
 *  >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
int udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;
	int is_udplite = IS_UDPLITE(sk);

	/*
	 *	Charge it to the socket, dropping if the queue is full.
	 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

	if (static_key_false(&udp_encap_needed) && up->encap_type) {
		int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);

		/*
		 * This is an encapsulation socket so pass the skb to
		 * the socket's udp_encap_rcv() hook. Otherwise, just
		 * fall through and pass this up the UDP socket.
		 * up->encap_rcv() returns the following value:
		 * =0 if skb was successfully passed to the encap
		 *    handler or was discarded by it.
		 * >0 if skb should be passed on to UDP.
		 * <0 if skb should be resubmitted as proto -N
		 */

		/* if we're overly short, let UDP handle it */
		encap_rcv = ACCESS_ONCE(up->encap_rcv);
		if (encap_rcv) {
			int ret;

			/* Verify checksum before giving to encap */
			if (udp_lib_checksum_complete(skb))
				goto csum_error;

			ret = encap_rcv(sk, skb);
			if (ret <= 0) {
				UDP_INC_STATS_BH(sock_net(sk),
						 UDP_MIB_INDATAGRAMS,
						 is_udplite);
				return -ret;
			}
		}

		/* FALLTHROUGH -- it's a UDP Packet */
	}

	/*
	 * 	UDP-Lite specific tests, ignored on UDP sockets
	 */
	if ((is_udplite & UDPLITE_RECV_CC)  &&  UDP_SKB_CB(skb)->partial_cov) {

		/*
		 * MIB statistics other than incrementing the error count are
		 * disabled for the following two types of errors: these depend
		 * on the application settings, not on the functioning of the
		 * protocol stack as such.
		 *
		 * RFC 3828 here recommends (sec 3.3): "There should also be a
		 * way ... to ... at least let the receiving application block
		 * delivery of packets with coverage values less than a value
		 * provided by the application."
		 */
		if (up->pcrlen == 0) {          /* full coverage was set  */
			net_dbg_ratelimited("UDPLite: partial coverage %d while full coverage %d requested\n",
					    UDP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		/* The next case involves violating the min. coverage requested
		 * by the receiver. This is subtle: if receiver wants x and x is
		 * greater than the buffersize/MTU then receiver will complain
		 * that it wants x while sender emits packets of smaller size y.
		 * Therefore the above ...()->partial_cov statement is essential.
		 */
		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			net_dbg_ratelimited("UDPLite: coverage %d too small, need min %d\n",
					    UDP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	if (rcu_access_pointer(sk->sk_filter) &&
	    udp_lib_checksum_complete(skb))
		goto csum_error;

	if (sk_rcvqueues_full(sk, sk->sk_rcvbuf)) {
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
				 is_udplite);
		goto drop;
	}

	rc = 0;

	ipv4_pktinfo_prepare(sk, skb);
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk))
		rc = __udp_queue_rcv_skb(sk, skb);
	else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf)) {
		bh_unlock_sock(sk);
		goto drop;
	}
	bh_unlock_sock(sk);

	return rc;

csum_error:
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
drop:
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	atomic_inc(&sk->sk_drops);
	kfree_skb(skb);
	return -1;
}

static void flush_stack(struct sock **stack, unsigned int count,
			struct sk_buff *skb, unsigned int final)
{
	unsigned int i;
	struct sk_buff *skb1 = NULL;
	struct sock *sk;

	for (i = 0; i < count; i++) {
		sk = stack[i];
		if (likely(!skb1))
			skb1 = (i == final) ? skb : skb_clone(skb, GFP_ATOMIC);

		if (!skb1) {
			atomic_inc(&sk->sk_drops);
			UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
					 IS_UDPLITE(sk));
			UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS,
					 IS_UDPLITE(sk));
		}

		if (skb1 && udp_queue_rcv_skb(sk, skb1) <= 0)
			skb1 = NULL;

		sock_put(sk);
	}
	if (unlikely(skb1))
		kfree_skb(skb1);
}

/* For TCP sockets, sk_rx_dst is protected by socket lock
 * For UDP, we use xchg() to guard against concurrent changes.
 */
static void udp_sk_rx_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old;

	dst_hold(dst);
	old = xchg(&sk->sk_rx_dst, dst);
	dst_release(old);
}

/*
 *	Multicasts and broadcasts go to each listener.
 *
 *	Note: called only from the BH handler context.
 */
static int __udp4_lib_mcast_deliver(struct net *net, struct sk_buff *skb,
				    struct udphdr  *uh,
				    __be32 saddr, __be32 daddr,
				    struct udp_table *udptable,
				    int proto)
{
	struct sock *sk, *stack[256 / sizeof(struct sock *)];
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(uh->dest);
	struct udp_hslot *hslot = udp_hashslot(udptable, net, hnum);
	int dif = skb->dev->ifindex;
	unsigned int count = 0, offset = offsetof(typeof(*sk), sk_nulls_node);
	unsigned int hash2 = 0, hash2_any = 0, use_hash2 = (hslot->count > 10);
	bool inner_flushed = false;

	if (use_hash2) {
		hash2_any = udp4_portaddr_hash(net, htonl(INADDR_ANY), hnum) &
			    udp_table.mask;
		hash2 = udp4_portaddr_hash(net, daddr, hnum) & udp_table.mask;
start_lookup:
		hslot = &udp_table.hash2[hash2];
		offset = offsetof(typeof(*sk), __sk_common.skc_portaddr_node);
	}

	spin_lock(&hslot->lock);
	sk_nulls_for_each_entry_offset(sk, node, &hslot->head, offset) {
		if (__udp_is_mcast_sock(net, sk,
					uh->dest, daddr,
					uh->source, saddr,
					dif, hnum)) {
			if (unlikely(count == ARRAY_SIZE(stack))) {
				flush_stack(stack, count, skb, ~0);
				inner_flushed = true;
				count = 0;
			}
			stack[count++] = sk;
			sock_hold(sk);
		}
	}

	spin_unlock(&hslot->lock);

	/* Also lookup *:port if we are using hash2 and haven't done so yet. */
	if (use_hash2 && hash2 != hash2_any) {
		hash2 = hash2_any;
		goto start_lookup;
	}

	/*
	 * do the slow work with no lock held
	 */
	if (count) {
		flush_stack(stack, count, skb, count - 1);
	} else {
		if (!inner_flushed)
			UDP_INC_STATS_BH(net, UDP_MIB_IGNOREDMULTI,
					 proto == IPPROTO_UDPLITE);
		consume_skb(skb);
	}
	return 0;
}

/* Initialize UDP checksum. If exited with zero value (success),
 * CHECKSUM_UNNECESSARY means, that no more checks are required.
 * Otherwise, csum completion requires chacksumming packet body,
 * including udp header and folding it to skb->csum.
 */
static inline int udp4_csum_init(struct sk_buff *skb, struct udphdr *uh,
				 int proto)
{
	int err;

	UDP_SKB_CB(skb)->partial_cov = 0;
	UDP_SKB_CB(skb)->cscov = skb->len;

	if (proto == IPPROTO_UDPLITE) {
		err = udplite_checksum_init(skb, uh);
		if (err)
			return err;

		if (UDP_SKB_CB(skb)->partial_cov) {
			skb->csum = inet_compute_pseudo(skb, proto);
			return 0;
		}
	}

	return skb_checksum_init_zero_check(skb, proto, uh->check,
					    inet_compute_pseudo);
}

/*
 *	All we need to do is get the socket, and then do a checksum.
 */

int __udp4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable,
		   int proto)
{
	struct sock *sk;
	struct udphdr *uh;
	unsigned short ulen;
	struct rtable *rt = skb_rtable(skb);
	__be32 saddr, daddr;
	struct net *net = dev_net(skb->dev);

	/*
	 *  Validate the packet.
	 */
	 /* 校验数据包至少要有UDP首部大小 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;		/* No space for header. */
	 /* 得到UDP首部指针 */
	uh   = udp_hdr(skb);
	ulen = ntohs(uh->len);
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;
	 /* 如果UDP数据包长度超过数据包的实际长度，则出错 */
	if (ulen > skb->len)
		goto short_packet;
	/*
判断协议是否为UDP协议。
也许有的读者会觉得很奇怪，为什么在UDP的接收函数中还要判断协议是否为UDP？
因为这个函数还用于处理UDPLITE协议。
 */
	if (proto == IPPROTO_UDP) {
		/* UDP validates ulen. */
	 /* 如果是UDP协议，则将数据包的长度更新为UDP指定的长度，并更新校验和 */
		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
			goto short_packet;
		 /* 因为前面的操作可能会导致skb内存变化，所以需要重新获得UDP首部指针 */
		uh = udp_hdr(skb);
	}
	/* 初始化UDP校验和 */
	if (udp4_csum_init(skb, uh, proto))
		goto csum_error;

	sk = skb_steal_sock(skb);
	if (sk) {
		struct dst_entry *dst = skb_dst(skb);
		int ret;

		if (unlikely(sk->sk_rx_dst != dst))
			udp_sk_rx_dst_set(sk, dst);

		ret = udp_queue_rcv_skb(sk, skb);
		sock_put(sk);
		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
			return -ret;
		return 0;
	}
	 /* 如果路由标志位广播或多播，则表明该UDP数据包为广播或多播 */
	if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
		return __udp4_lib_mcast_deliver(net, skb, uh,
						saddr, daddr, udptable, proto);
	/* 确定匹配的UDP套接字 */
	sk = __udp4_lib_lookup_skb(skb, uh->source, uh->dest, udptable);
	if (sk) {
		int ret;

		if (inet_get_convert_csum(sk) && uh->check && !IS_UDPLITE(sk))
			skb_checksum_try_convert(skb, IPPROTO_UDP, uh->check,
						 inet_compute_pseudo);
		/* 找到了匹配的套接字 */
		/* 将数据包加入到UDP的接收队列 */
		ret = udp_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
			return -ret;
		return 0;
	}
	/* 进行xfrm策略检查 */
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto drop;
	/* 重置netfilter信息 */
	nf_reset(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	/* 检查UDP检验和 */
	if (udp_lib_checksum_complete(skb))
		goto csum_error;
	 /* 若不知道匹配的UDP套接字，则发送ICMP错误消息 */
	UDP_INC_STATS_BH(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
	 * Hmm.  We got an UDP packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb);
	return 0;

short_packet:
	net_dbg_ratelimited("UDP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
			    proto == IPPROTO_UDPLITE ? "Lite" : "",
			    &saddr, ntohs(uh->source),
			    ulen, skb->len,
			    &daddr, ntohs(uh->dest));
	goto drop;

csum_error:
	/*
	 * RFC1122: OK.  Discards the bad packet silently (as far as
	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
	 */
	net_dbg_ratelimited("UDP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
			    proto == IPPROTO_UDPLITE ? "Lite" : "",
			    &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
			    ulen);
	UDP_INC_STATS_BH(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
drop:
	UDP_INC_STATS_BH(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
	kfree_skb(skb);
	return 0;
}

/* We can only early demux multicast if there is a single matching socket.
 * If more than one socket found returns NULL
 */
static struct sock *__udp4_lib_mcast_demux_lookup(struct net *net,
						  __be16 loc_port, __be32 loc_addr,
						  __be16 rmt_port, __be32 rmt_addr,
						  int dif)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(loc_port);
	unsigned int count, slot = udp_hashfn(net, hnum, udp_table.mask);
	struct udp_hslot *hslot = &udp_table.hash[slot];

	/* Do not bother scanning a too big list */
	if (hslot->count > 10)
		return NULL;

	rcu_read_lock();
begin:
	count = 0;
	result = NULL;
	sk_nulls_for_each_rcu(sk, node, &hslot->head) {
		if (__udp_is_mcast_sock(net, sk,
					loc_port, loc_addr,
					rmt_port, rmt_addr,
					dif, hnum)) {
			result = sk;
			++count;
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begin;

	if (result) {
		if (count != 1 ||
		    unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(!__udp_is_mcast_sock(net, result,
						       loc_port, loc_addr,
						       rmt_port, rmt_addr,
						       dif, hnum))) {
			sock_put(result);
			result = NULL;
		}
	}
	rcu_read_unlock();
	return result;
}

/* For unicast we should only early demux connected sockets or we can
 * break forwarding setups.  The chains here can be long so only check
 * if the first socket is an exact match and if not move on.
 */
static struct sock *__udp4_lib_demux_lookup(struct net *net,
					    __be16 loc_port, __be32 loc_addr,
					    __be16 rmt_port, __be32 rmt_addr,
					    int dif)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(loc_port);
	unsigned int hash2 = udp4_portaddr_hash(net, loc_addr, hnum);
	unsigned int slot2 = hash2 & udp_table.mask;
	struct udp_hslot *hslot2 = &udp_table.hash2[slot2];
	INET_ADDR_COOKIE(acookie, rmt_addr, loc_addr);
	const __portpair ports = INET_COMBINED_PORTS(rmt_port, hnum);

	rcu_read_lock();
	result = NULL;
	udp_portaddr_for_each_entry_rcu(sk, node, &hslot2->head) {
		if (INET_MATCH(sk, net, acookie,
			       rmt_addr, loc_addr, ports, dif))
			result = sk;
		/* Only check first socket in chain */
		break;
	}

	if (result) {
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(!INET_MATCH(sk, net, acookie,
					      rmt_addr, loc_addr,
					      ports, dif))) {
			sock_put(result);
			result = NULL;
		}
	}
	rcu_read_unlock();
	return result;
}

void udp_v4_early_demux(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	const struct iphdr *iph;
	const struct udphdr *uh;
	struct sock *sk;
	struct dst_entry *dst;
	int dif = skb->dev->ifindex;
	int ours;

	/* validate the packet */
	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct udphdr)))
		return;

	iph = ip_hdr(skb);
	uh = udp_hdr(skb);

	if (skb->pkt_type == PACKET_BROADCAST ||
	    skb->pkt_type == PACKET_MULTICAST) {
		struct in_device *in_dev = __in_dev_get_rcu(skb->dev);

		if (!in_dev)
			return;

		/* we are supposed to accept bcast packets */
		if (skb->pkt_type == PACKET_MULTICAST) {
			ours = ip_check_mc_rcu(in_dev, iph->daddr, iph->saddr,
					       iph->protocol);
			if (!ours)
				return;
		}

		sk = __udp4_lib_mcast_demux_lookup(net, uh->dest, iph->daddr,
						   uh->source, iph->saddr, dif);
	} else if (skb->pkt_type == PACKET_HOST) {
		sk = __udp4_lib_demux_lookup(net, uh->dest, iph->daddr,
					     uh->source, iph->saddr, dif);
	} else {
		return;
	}

	if (!sk)
		return;

	skb->sk = sk;
	skb->destructor = sock_efree;
	dst = READ_ONCE(sk->sk_rx_dst);

	if (dst)
		dst = dst_check(dst, 0);
	if (dst) {
		/* DST_NOCACHE can not be used without taking a reference */
		if (dst->flags & DST_NOCACHE) {
			if (likely(atomic_inc_not_zero(&dst->__refcnt)))
				skb_dst_set(skb, dst);
		} else {
			skb_dst_set_noref(skb, dst);
		}
	}
}

int udp_rcv(struct sk_buff *skb)
{
	return __udp4_lib_rcv(skb, &udp_table, IPPROTO_UDP);
}

void udp_destroy_sock(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);
	bool slow = lock_sock_fast(sk);
	udp_flush_pending_frames(sk);
	unlock_sock_fast(sk, slow);
	if (static_key_false(&udp_encap_needed) && up->encap_type) {
		void (*encap_destroy)(struct sock *sk);
		encap_destroy = ACCESS_ONCE(up->encap_destroy);
		if (encap_destroy)
			encap_destroy(sk);
	}
}

/*
 *	Socket option code for UDP
 */
int udp_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, unsigned int optlen,
		       int (*push_pending_frames)(struct sock *))
{
	struct udp_sock *up = udp_sk(sk);
	int val, valbool;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	valbool = val ? 1 : 0;

	switch (optname) {
	case UDP_CORK:
		if (val != 0) {
			up->corkflag = 1;
		} else {
			up->corkflag = 0;
			lock_sock(sk);
			push_pending_frames(sk);
			release_sock(sk);
		}
		break;

	case UDP_ENCAP:
		switch (val) {
		case 0:
		case UDP_ENCAP_ESPINUDP:
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			up->encap_rcv = xfrm4_udp_encap_rcv;
			/* FALLTHROUGH */
		case UDP_ENCAP_L2TPINUDP:
			up->encap_type = val;
			udp_encap_enable();
			break;
		default:
			err = -ENOPROTOOPT;
			break;
		}
		break;

	case UDP_NO_CHECK6_TX:
		up->no_check6_tx = valbool;
		break;

	case UDP_NO_CHECK6_RX:
		up->no_check6_rx = valbool;
		break;

	/*
	 * 	UDP-Lite's partial checksum coverage (RFC 3828).
	 */
	/* The sender sets actual checksum coverage length via this option.
	 * The case coverage > packet length is handled by send module. */
	case UDPLITE_SEND_CSCOV:
		if (!is_udplite)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Illegal coverage: use default (8) */
			val = 8;
		else if (val > USHRT_MAX)
			val = USHRT_MAX;
		up->pcslen = val;
		up->pcflag |= UDPLITE_SEND_CC;
		break;

	/* The receiver specifies a minimum checksum coverage value. To make
	 * sense, this should be set to at least 8 (as done below). If zero is
	 * used, this again means full checksum coverage.                     */
	case UDPLITE_RECV_CSCOV:
		if (!is_udplite)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Avoid silly minimal values.       */
			val = 8;
		else if (val > USHRT_MAX)
			val = USHRT_MAX;
		up->pcrlen = val;
		up->pcflag |= UDPLITE_RECV_CC;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	return err;
}
EXPORT_SYMBOL(udp_lib_setsockopt);

int udp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return ip_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
}
#endif

int udp_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case UDP_CORK:
		val = up->corkflag;
		break;

	case UDP_ENCAP:
		val = up->encap_type;
		break;

	case UDP_NO_CHECK6_TX:
		val = up->no_check6_tx;
		break;

	case UDP_NO_CHECK6_RX:
		val = up->no_check6_rx;
		break;

	/* The following two cannot be changed on UDP sockets, the return is
	 * always 0 (which corresponds to the full checksum coverage of UDP). */
	case UDPLITE_SEND_CSCOV:
		val = up->pcslen;
		break;

	case UDPLITE_RECV_CSCOV:
		val = up->pcrlen;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(udp_lib_getsockopt);

int udp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ip_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return compat_ip_getsockopt(sk, level, optname, optval, optlen);
}
#endif
/**
 * 	udp_poll - wait for a UDP event.
 *	@file - file struct
 *	@sock - socket
 *	@wait - poll table
 *
 *	This is same as datagram poll, except for the special case of
 *	blocking sockets. If application is using a blocking fd
 *	and a packet with checksum error is in the queue;
 *	then it could get return from select indicating data available
 *	but then block when reading it. Add special case code
 *	to work around these arguably broken applications.
 */
unsigned int udp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask = datagram_poll(file, sock, wait);
	struct sock *sk = sock->sk;

	sock_rps_record_flow(sk);

	/* Check for false positives due to checksum errors */
	if ((mask & POLLRDNORM) && !(file->f_flags & O_NONBLOCK) &&
	    !(sk->sk_shutdown & RCV_SHUTDOWN) && !first_packet_length(sk))
		mask &= ~(POLLIN | POLLRDNORM);

	return mask;

}
EXPORT_SYMBOL(udp_poll);

struct proto udp_prot = {
	.name		   = "UDP",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = udp_sendmsg,
	.recvmsg	   = udp_recvmsg,
	.sendpage	   = udp_sendpage,
	.backlog_rcv	   = __udp_queue_rcv_skb,
	.release_cb	   = ip4_datagram_release_cb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.rehash		   = udp_v4_rehash,
	.get_port	   = udp_v4_get_port,
	.memory_allocated  = &udp_memory_allocated,
	.sysctl_mem	   = sysctl_udp_mem,
	.sysctl_wmem	   = &sysctl_udp_wmem_min,
	.sysctl_rmem	   = &sysctl_udp_rmem_min,
	.obj_size	   = sizeof(struct udp_sock),
	.slab_flags	   = SLAB_DESTROY_BY_RCU,
	.h.udp_table	   = &udp_table,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
	.clear_sk	   = sk_prot_clear_portaddr_nulls,
};
EXPORT_SYMBOL(udp_prot);

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

static struct sock *udp_get_first(struct seq_file *seq, int start)
{
	struct sock *sk;
	struct udp_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	for (state->bucket = start; state->bucket <= state->udp_table->mask;
	     ++state->bucket) {
		struct hlist_nulls_node *node;
		struct udp_hslot *hslot = &state->udp_table->hash[state->bucket];

		if (hlist_nulls_empty(&hslot->head))
			continue;

		spin_lock_bh(&hslot->lock);
		sk_nulls_for_each(sk, node, &hslot->head) {
			if (!net_eq(sock_net(sk), net))
				continue;
			if (sk->sk_family == state->family)
				goto found;
		}
		spin_unlock_bh(&hslot->lock);
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *udp_get_next(struct seq_file *seq, struct sock *sk)
{
	struct udp_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	do {
		sk = sk_nulls_next(sk);
	} while (sk && (!net_eq(sock_net(sk), net) || sk->sk_family != state->family));

	if (!sk) {
		if (state->bucket <= state->udp_table->mask)
			spin_unlock_bh(&state->udp_table->hash[state->bucket].lock);
		return udp_get_first(seq, state->bucket + 1);
	}
	return sk;
}

static struct sock *udp_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = udp_get_first(seq, 0);

	if (sk)
		while (pos && (sk = udp_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

static void *udp_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct udp_iter_state *state = seq->private;
	state->bucket = MAX_UDP_PORTS;

	return *pos ? udp_get_idx(seq, *pos-1) : SEQ_START_TOKEN;
}

static void *udp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == SEQ_START_TOKEN)
		sk = udp_get_idx(seq, 0);
	else
		sk = udp_get_next(seq, v);

	++*pos;
	return sk;
}

static void udp_seq_stop(struct seq_file *seq, void *v)
{
	struct udp_iter_state *state = seq->private;

	if (state->bucket <= state->udp_table->mask)
		spin_unlock_bh(&state->udp_table->hash[state->bucket].lock);
}

int udp_seq_open(struct inode *inode, struct file *file)
{
	struct udp_seq_afinfo *afinfo = PDE_DATA(inode);
	struct udp_iter_state *s;
	int err;

	err = seq_open_net(inode, file, &afinfo->seq_ops,
			   sizeof(struct udp_iter_state));
	if (err < 0)
		return err;

	s = ((struct seq_file *)file->private_data)->private;
	s->family		= afinfo->family;
	s->udp_table		= afinfo->udp_table;
	return err;
}
EXPORT_SYMBOL(udp_seq_open);

/* ------------------------------------------------------------------------ */
int udp_proc_register(struct net *net, struct udp_seq_afinfo *afinfo)
{
	struct proc_dir_entry *p;
	int rc = 0;

	afinfo->seq_ops.start		= udp_seq_start;
	afinfo->seq_ops.next		= udp_seq_next;
	afinfo->seq_ops.stop		= udp_seq_stop;

	p = proc_create_data(afinfo->name, S_IRUGO, net->proc_net,
			     afinfo->seq_fops, afinfo);
	if (!p)
		rc = -ENOMEM;
	return rc;
}
EXPORT_SYMBOL(udp_proc_register);

void udp_proc_unregister(struct net *net, struct udp_seq_afinfo *afinfo)
{
	remove_proc_entry(afinfo->name, net->proc_net);
}
EXPORT_SYMBOL(udp_proc_unregister);

/* ------------------------------------------------------------------------ */
static void udp4_format_sock(struct sock *sp, struct seq_file *f,
		int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->inet_daddr;
	__be32 src  = inet->inet_rcv_saddr;
	__u16 destp	  = ntohs(inet->inet_dport);
	__u16 srcp	  = ntohs(inet->inet_sport);

	seq_printf(f, "%5d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %d",
		bucket, src, srcp, dest, destp, sp->sk_state,
		sk_wmem_alloc_get(sp),
		sk_rmem_alloc_get(sp),
		0, 0L, 0,
		from_kuid_munged(seq_user_ns(f), sock_i_uid(sp)),
		0, sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp,
		atomic_read(&sp->sk_drops));
}

int udp4_seq_show(struct seq_file *seq, void *v)
{
	seq_setwidth(seq, 127);
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode ref pointer drops");
	else {
		struct udp_iter_state *state = seq->private;

		udp4_format_sock(v, seq, state->bucket);
	}
	seq_pad(seq, '\n');
	return 0;
}

static const struct file_operations udp_afinfo_seq_fops = {
	.owner    = THIS_MODULE,
	.open     = udp_seq_open,
	.read     = seq_read,
	.llseek   = seq_lseek,
	.release  = seq_release_net
};

/* ------------------------------------------------------------------------ */
static struct udp_seq_afinfo udp4_seq_afinfo = {
	.name		= "udp",
	.family		= AF_INET,
	.udp_table	= &udp_table,
	.seq_fops	= &udp_afinfo_seq_fops,
	.seq_ops	= {
		.show		= udp4_seq_show,
	},
};

static int __net_init udp4_proc_init_net(struct net *net)
{
	return udp_proc_register(net, &udp4_seq_afinfo);
}

static void __net_exit udp4_proc_exit_net(struct net *net)
{
	udp_proc_unregister(net, &udp4_seq_afinfo);
}

static struct pernet_operations udp4_net_ops = {
	.init = udp4_proc_init_net,
	.exit = udp4_proc_exit_net,
};

int __init udp4_proc_init(void)
{
	return register_pernet_subsys(&udp4_net_ops);
}

void udp4_proc_exit(void)
{
	unregister_pernet_subsys(&udp4_net_ops);
}
#endif /* CONFIG_PROC_FS */

static __initdata unsigned long uhash_entries;
static int __init set_uhash_entries(char *str)
{
	ssize_t ret;

	if (!str)
		return 0;

	ret = kstrtoul(str, 0, &uhash_entries);
	if (ret)
		return 0;

	if (uhash_entries && uhash_entries < UDP_HTABLE_SIZE_MIN)
		uhash_entries = UDP_HTABLE_SIZE_MIN;
	return 1;
}
__setup("uhash_entries=", set_uhash_entries);

void __init udp_table_init(struct udp_table *table, const char *name)
{
	unsigned int i;

	table->hash = alloc_large_system_hash(name,
					      2 * sizeof(struct udp_hslot),
					      uhash_entries,
					      21, /* one slot per 2 MB */
					      0,
					      &table->log,
					      &table->mask,
					      UDP_HTABLE_SIZE_MIN,
					      64 * 1024);

	table->hash2 = table->hash + (table->mask + 1);
	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_NULLS_HEAD(&table->hash[i].head, i);
		table->hash[i].count = 0;
		spin_lock_init(&table->hash[i].lock);
	}
	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_NULLS_HEAD(&table->hash2[i].head, i);
		table->hash2[i].count = 0;
		spin_lock_init(&table->hash2[i].lock);
	}
}

u32 udp_flow_hashrnd(void)
{
	static u32 hashrnd __read_mostly;

	net_get_random_once(&hashrnd, sizeof(hashrnd));

	return hashrnd;
}
EXPORT_SYMBOL(udp_flow_hashrnd);

void __init udp_init(void)
{
	unsigned long limit;

	udp_table_init(&udp_table, "UDP");
	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_udp_mem[0] = limit / 4 * 3;
	sysctl_udp_mem[1] = limit;
	sysctl_udp_mem[2] = sysctl_udp_mem[0] * 2;

	sysctl_udp_rmem_min = SK_MEM_QUANTUM;
	sysctl_udp_wmem_min = SK_MEM_QUANTUM;
}
