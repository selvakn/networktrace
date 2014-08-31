#!/usr/sbin/dtrace -s

#pragma D option quiet

dtrace:::BEGIN
{
	err[0]            = "Success";

	err[EAGAIN]       = "EAGAIN";
	err[EBADF] = "EBADF";
	err[EFAULT] = "EFAULT";
	err[EINVAL] = "EINVAL";
	err[ENOMEM] = "ENOMEM";
	err[ENOTCONN] = "ENOTCONN";
	err[ENOTSOCK] = "ENOTSOCK";


	err[EINTR]        = "Interrupted syscall";
	err[EIO]          = "I/O error";
	err[EACCES]       = "Permission denied";
	err[ENETDOWN]     = "Network is down";
	err[ENETUNREACH]  = "Network unreachable";
	err[ECONNRESET]   = "Connection reset";
	err[ECONNREFUSED] = "Connection refused";
	err[ETIMEDOUT]    = "Timed out";
	err[EHOSTDOWN]    = "Host down";
	err[EHOSTUNREACH] = "No route to host";
	err[EINPROGRESS]  = "In progress";
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
/self->fd && execname != "ocspd"/
{
  self->start = walltimestamp / 1000000;
  this->errstr = err[errno] != NULL ? err[errno] : lltostr(errno);
  this->size = errno == 0 ? arg0 : 0;

  printf("{\"timestamp\": %ld, \"type\":\"%s:%s\", \"execname\":\"%s\", \"pid\":%d, \"size\":%d, \"error\": \"%s\", \"IP\": \"%d.%d.%d.%d\"}\n",
  self->start, probefunc, probename, execname, pid, this->size, this->errstr,
	self->socks->sa_data[2],
	self->socks->sa_data[3],
	self->socks->sa_data[4],
	self->socks->sa_data[5]
	);
}
