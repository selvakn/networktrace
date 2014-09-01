#!/usr/sbin/dtrace -s

#pragma D option quiet


BEGIN
{
  last = walltimestamp/1000000;
}

syscall::connect*:entry
{
	socks = (struct sockaddr*) copyin(arg1, arg2);
  hport = (uint_t) socks->sa_data[0];
  lport = (uint_t) socks->sa_data[1];
  hport <<= 8;
  port = hport + lport;

	self->port = port;
	self->socks = socks;
  self->fd = arg0 + 1;
}

syscall::recvmsg:return,
syscall::recvfrom:return,
syscall::sendmsg:return,
syscall::sendto:return
/self->fd && execname != "ocspd" && errno == 0/
{
  @stats[last, probefunc, probename, execname, pid,  self->socks->sa_data[2],  self->socks->sa_data[3],  self->socks->sa_data[4],  self->socks->sa_data[5]] = sum(arg0);

}

tick-10sec
{
  printa("{\"timestamp\": %ld, \"type\":\"%s:%s\", \"execname\":\"%s\", \"pid\":%d, \"IP\": \"%d.%d.%d.%d\", \"size\":%@d}\n", @stats);
  trunc(@stats);
  last = walltimestamp/1000000;
}
