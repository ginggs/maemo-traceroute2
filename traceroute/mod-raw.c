/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
					<buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netdb.h>

#include "traceroute.h"


static sockaddr_any dest_addr = {{ 0, }, };
static int protocol = DEF_RAW_PROT;

static char *data;
static size_t data_len = 0;

static int raw_sk = -1;
static int last_ttl = 0;
static int seq = 0;


static int set_protocol (CLIF_option *optn, char *arg) {
	char *q;

	protocol = strtoul (arg, &q, 0);
	if (q == arg) {
	    struct protoent *p = getprotobyname (arg);

	    if (!p)  return -1;
	    protocol = p->p_proto;
	}

	return 0;
}


static CLIF_option raw_options[] = {
	{ 0, "protocol", "PROT", "Use protocol %s (default is "
			_TEXT (DEF_RAW_PROT) ")",
			set_protocol, 0, 0, CLIF_ABBREV },
	CLIF_END_OPTION
};


static int raw_init (const sockaddr_any *dest,
				unsigned int port_seq, size_t packet_len) {
	int i;
	int af = dest->sa.sa_family;

	dest_addr = *dest;
	dest_addr.sin.sin_port = 0;

	if (port_seq)  protocol = port_seq;


	data_len = packet_len;
	data = malloc (data_len);
	if (!data)  error ("malloc");

        for (i = 0; i < data_len; i++)
                data[i] = 0x40 + (i & 0x3f);


	raw_sk = socket (af, SOCK_RAW, protocol);
	if (raw_sk < 0)
		error ("socket");

	tune_socket (raw_sk);

	/*  Don't want to catch packets from another hosts   */
	if (raw_can_connect () &&
	    connect (raw_sk, &dest_addr.sa, sizeof (dest_addr)) < 0
	)  error ("connect");

	use_recverr (raw_sk);


	add_poll (raw_sk, POLLIN | POLLERR);

	return 0;
}


static void raw_send_probe (probe *pb, int ttl) {

	if (ttl != last_ttl) {

	    set_ttl (raw_sk, ttl);

	    last_ttl = ttl;
	}


	pb->send_time = get_time ();

	if (do_send (raw_sk, data, data_len, &dest_addr) < 0) {
	    pb->send_time = 0;
	    return;
	}


	pb->seq = ++seq;

	return;
}


static void raw_recv_probe (int sk, int revents) {
	struct msghdr msg;
	sockaddr_any from;
	struct iovec iov;
	int err;
	probe *pb;
	char buf[1024];		/*  enough, enough...  */
	char control[1024];


	if (!(revents & (POLLIN | POLLERR)))
		return;

	err = !!(revents & POLLERR);


	memset (&msg, 0, sizeof (msg));
	msg.msg_name = &from;
	msg.msg_namelen = sizeof (from);
	msg.msg_control = control;
	msg.msg_controllen = sizeof (control);
	iov.iov_base = buf;
	iov.iov_len = sizeof (buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;


	if (recvmsg (sk, &msg, err ? MSG_ERRQUEUE : 0) < 0)
		return;

	if (!equal_addr (&dest_addr, &from))
		return;


	pb = probe_by_seq (seq);
	if (!pb)  return;


	parse_cmsg (pb, &msg);	/*  err (if any), tstamp, ttl   */

	if (!err) {

	    memcpy (&pb->res, &from, sizeof (pb->res));

	    pb->final = 1;
	}


	pb->seq = -1;

	pb->done = 1;
}


static void raw_expire_probe (probe *pb) {

	pb->seq = -1;

	pb->done = 1;
}


static tr_module raw_ops = {
	.name = "raw",
	.init = raw_init,
	.send_probe = raw_send_probe,
	.recv_probe = raw_recv_probe,
	.expire_probe = raw_expire_probe,
	.options = raw_options,
	.user = 0,
	.one_per_time = 1,
};

TR_MODULE (raw_ops);
