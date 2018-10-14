#ifndef _LINUX_MSG_H
#define _LINUX_MSG_H

#include <linux/list.h>
#include <uapi/linux/msg.h>

/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};

/* one msq_queue structure for each present queue on the system */
struct msg_queue {
	struct kern_ipc_perm q_perm;
	/* 上一次 msgsnd的时间*/
	time_t q_stime;			/* last msgsnd time */
	/* 上一次 msgrcv的时间 */
	time_t q_rtime;			/* last msgrcv time */
	 /* 属性变化时间 */
	time_t q_ctime;			/* last change time */
	 /* 队列当前字节总数*/
	unsigned long q_cbytes;		/* current number of bytes on queue */
	 /*队列当前消息总数*/
	unsigned long q_qnum;		/* number of messages in queue */
	  /*一个消息队列允许的最大字节数*/
	unsigned long q_qbytes;		/* max number of bytes on queue */
	   /*上一个调用msgsnd的进程ID*/
	pid_t q_lspid;			/* pid of last msgsnd */
	   /*上一个调用msgrcv的进程ID*/
	pid_t q_lrpid;			/* last receive pid */

	struct list_head q_messages;
	struct list_head q_receivers;
	struct list_head q_senders;
};

/* Helper routines for sys_msgsnd and sys_msgrcv */
extern long do_msgsnd(int msqid, long mtype, void __user *mtext,
			size_t msgsz, int msgflg);
extern long do_msgrcv(int msqid, void __user *buf, size_t bufsz, long msgtyp,
		      int msgflg,
		      long (*msg_fill)(void __user *, struct msg_msg *,
				       size_t));

#endif /* _LINUX_MSG_H */
