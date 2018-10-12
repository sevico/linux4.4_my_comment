/*
 *	common UDP/RAW code
 *	Linux INET implementation
 *
 * Authors:
 * 	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>
 *
 * 	This program is free software; you can redistribute it and/or
 * 	modify it under the terms of the GNU General Public License
 * 	as published by the Free Software Foundation; either version
 * 	2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/tcp_states.h>

int __ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;
	struct flowi4 *fl4;
	struct rtable *rt;
	__be32 saddr;
	int oif;
	int err;
	/* 地址的长度性检查 */

	if (addr_len < sizeof(*usin))
		return -EINVAL;
	/* 检查是否为AF_INET协议族 */
	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;
	/*因为connect会改变目的地址，所有socket中保存的路由缓存已经无用，必须重置*/

	sk_dst_reset(sk);
	/* 得到套接字绑定的发送接口 */
	oif = sk->sk_bound_dev_if;
	saddr = inet->inet_saddr;
	 /* 在目的地址是多播地址的情况下，
	  如果该套接字没有绑定网卡，则出口网卡为设置的多播网卡索引；
	   如果该套接字没有绑定源IP，则使用设置的多播源地址；
	   */
	if (ipv4_is_multicast(usin->sin_addr.s_addr)) {
		if (!oif)
			oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	}
	 /* 判断设置的目的地址是否存在正确的路由 */
	fl4 = &inet->cork.fl.u.ip4;
	rt = ip_route_connect(fl4, usin->sin_addr.s_addr, saddr,
			      RT_CONN_FLAGS(sk), oif,
			      sk->sk_protocol,
			      inet->inet_sport, usin->sin_port, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		if (err == -ENETUNREACH)
			IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		goto out;
	}
	/* 如果路由是广播类型，而套接字不是广播类型，则出错 */

	if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST)) {
		ip_rt_put(rt);
		err = -EACCES;
		goto out;
	}
	 /* 如果套接字没有设置发送地址或接收地址，则使用对应路由的源地址*/
	if (!inet->inet_saddr)
		inet->inet_saddr = fl4->saddr;	/* Update source address */
	if (!inet->inet_rcv_saddr) {
		inet->inet_rcv_saddr = fl4->saddr;
		if (sk->sk_prot->rehash)
			sk->sk_prot->rehash(sk);
	}
	/* 设置目的地址和端口 */
	inet->inet_daddr = fl4->daddr;
	inet->inet_dport = usin->sin_port;
	sk->sk_state = TCP_ESTABLISHED;
	sk_set_txhash(sk);
	inet->inet_id = jiffies;
	/* 重新设置路由信息 */
	sk_dst_set(sk, &rt->dst);
	err = 0;
out:
	return err;
}
EXPORT_SYMBOL(__ip4_datagram_connect);

int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	int res;

	lock_sock(sk);
	res = __ip4_datagram_connect(sk, uaddr, addr_len);
	release_sock(sk);
	return res;
}
EXPORT_SYMBOL(ip4_datagram_connect);

/* Because UDP xmit path can manipulate sk_dst_cache without holding
 * socket lock, we need to use sk_dst_set() here,
 * even if we own the socket lock.
 */
void ip4_datagram_release_cb(struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct ip_options_rcu *inet_opt;
	__be32 daddr = inet->inet_daddr;
	struct dst_entry *dst;
	struct flowi4 fl4;
	struct rtable *rt;

	rcu_read_lock();

	dst = __sk_dst_get(sk);
	if (!dst || !dst->obsolete || dst->ops->check(dst, 0)) {
		rcu_read_unlock();
		return;
	}
	inet_opt = rcu_dereference(inet->inet_opt);
	if (inet_opt && inet_opt->opt.srr)
		daddr = inet_opt->opt.faddr;
	rt = ip_route_output_ports(sock_net(sk), &fl4, sk, daddr,
				   inet->inet_saddr, inet->inet_dport,
				   inet->inet_sport, sk->sk_protocol,
				   RT_CONN_FLAGS(sk), sk->sk_bound_dev_if);

	dst = !IS_ERR(rt) ? &rt->dst : NULL;
	sk_dst_set(sk, dst);

	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(ip4_datagram_release_cb);
