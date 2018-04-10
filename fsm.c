#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define SYSCALL_MAX 64 //Max is 314

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/inet.h>
#include <linux/inet_diag.h>
#include <linux/inet_lro.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/math64.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/inet_ecn.h>
#include <net/inet_frag.h>
#include <net/inet_hashtables.h>
#include <net/inet_sock.h>
#include <net/inetpeer.h>
#include <net/ip.h>
#include <linux/can.h>

MODULE_DESCRIPTION("system call trace module");
MODULE_LICENSE("Dual BSD/GPL");
/* following string SYSCALL_TABLE_ADDRESS will be replaced by set_syscall_table_address.sh */
static void **syscall_table = (void *) 0xffffffff81801400;
static int syscall_count[SYSCALL_MAX];
/* White List define */
#define W_LIST 1500
/********************************************************************
*********************************************************************
****************** original system call function ********************
*********************************************************************
********************************************************************/
asmlinkage long (*orig_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*orig_sys_write)(unsigned int fd, const char __user *buf,
                          size_t count);
asmlinkage long (*orig_sys_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*orig_sys_close)(unsigned int fd);
asmlinkage long (*orig_sys_stat)(const char __user *filename,
                        struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_fstat)(unsigned int fd,
                        struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_lstat)(const char __user *filename,
                        struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_poll)(struct pollfd __user *ufds, unsigned int nfds,
                                int timeout);
asmlinkage long (*orig_sys_lseek)(unsigned int fd, off_t offset,
                          unsigned int whence);
asmlinkage long (*orig_sys_mmap)(struct mmap_arg_struct __user *arg);
asmlinkage long (*orig_sys_mprotect)(unsigned long start, size_t len,
                                unsigned long prot);
asmlinkage long (*orig_sys_munmap)(unsigned long addr, size_t len);
asmlinkage long (*orig_sys_brk)(unsigned long brk);
asmlinkage long (*orig_sys_rt_sigaction)(int,
                                 const struct sigaction __user *,
                                 struct sigaction __user *,
                                 size_t);
asmlinkage long (*orig_sys_rt_sigprocmask)(int how, sigset_t __user *set,
                                sigset_t __user *oset, size_t sigsetsize);
asmlinkage long (*orig_sys_ioctl)(unsigned int fd, unsigned int cmd,
                                unsigned long arg);
asmlinkage long (*orig_sys_pread64)(unsigned int fd, char __user *buf,
                            size_t count, loff_t pos);
asmlinkage long (*orig_sys_pwrite64)(unsigned int fd, const char __user *buf,
                             size_t count, loff_t pos);
asmlinkage long (*orig_sys_readv)(unsigned long fd,
                          const struct iovec __user *vec,
                          unsigned long vlen);
asmlinkage long (*orig_sys_writev)(unsigned long fd,
                           const struct iovec __user *vec,
                           unsigned long vlen);
asmlinkage long (*orig_sys_access)(const char __user *filename, int mode);
asmlinkage long (*orig_sys_pipe)(int __user *fildes);
asmlinkage long (*orig_sys_select)(int n, fd_set __user *inp, fd_set __user *outp,
                        fd_set __user *exp, struct timeval __user *tvp);
asmlinkage long (*orig_sys_sched_yield)(void);
asmlinkage long (*orig_sys_mremap)(unsigned long addr,
                           unsigned long old_len, unsigned long new_len,
                           unsigned long flags, unsigned long new_addr);
asmlinkage long (*orig_sys_msync)(unsigned long start, size_t len, int flags);
asmlinkage long (*orig_sys_mincore)(unsigned long start, size_t len,
                                unsigned char __user * vec);
asmlinkage long (*orig_sys_madvise)(unsigned long start, size_t len, int behavior);
asmlinkage long (*orig_sys_shmget)(key_t key, size_t size, int flag);
asmlinkage long (*orig_sys_shmat)(int shmid, char __user *shmaddr, int shmflg);
asmlinkage long (*orig_sys_shmctl)(int shmid, int cmd, struct shmid_ds __user *buf);
asmlinkage long (*orig_sys_dup)(unsigned int fildes);
asmlinkage long (*orig_sys_dup2)(unsigned int oldfd, unsigned int newfd);
asmlinkage long (*orig_sys_pause)(void);
asmlinkage long (*orig_sys_nanosleep)(struct timespec __user *rqtp, struct timespec __user *rmtp);
asmlinkage long (*orig_sys_getitimer)(int which, struct itimerval __user *value);
asmlinkage long (*orig_sys_alarm)(unsigned int seconds);
asmlinkage long (*orig_sys_setitimer)(int which,
                                struct itimerval __user *value,
                                struct itimerval __user *ovalue);
asmlinkage long (*orig_sys_getpid)(void);
asmlinkage long (*orig_sys_sendfile)(int out_fd, int in_fd,
                             off_t __user *offset, size_t count);
asmlinkage long (*orig_sys_socket)(int, int, int);
asmlinkage long (*orig_sys_connect)(int, struct sockaddr __user *, int);
asmlinkage long (*orig_sys_accept)(int, struct sockaddr __user *, int __user *);
asmlinkage long (*orig_sys_sendto)(int, void __user *, size_t, unsigned,
                                struct sockaddr __user *, int);
asmlinkage long (*orig_sys_recvfrom)(int, void __user *, size_t, unsigned,
                                struct sockaddr __user *, int __user *);
asmlinkage long (*orig_sys_sendmsg)(int fd, struct msghdr __user *msg, unsigned flags);
asmlinkage long (*orig_sys_recvmsg)(int fd, struct msghdr __user *msg, unsigned flags);
asmlinkage long (*orig_sys_shutdown)(int, int);
asmlinkage long (*orig_sys_bind)(int, struct sockaddr __user *, int);
asmlinkage long (*orig_sys_listen)(int, int);
asmlinkage long (*orig_sys_getsockname)(int, struct sockaddr __user *, int __user *);
asmlinkage long (*orig_sys_getpeername)(int, struct sockaddr __user *, int __user *);
asmlinkage long (*orig_sys_socketpair)(int, int, int, int __user *);
asmlinkage long (*orig_sys_setsockopt)(int fd, int level, int optname,
                                char __user *optval, int optlen);
asmlinkage long (*orig_sys_getsockopt)(int fd, int level, int optname,
                                char __user *optval, int __user *optlen);
asmlinkage long (*orig_sys_clone)(unsigned long, unsigned long, int, int __user *,
			  int __user *, int);
asmlinkage long (*orig_sys_fork)(void);
asmlinkage long (*orig_sys_vfork)(void);
asmlinkage long (*orig_sys_execve)(const char __user *filename,
                const char __user *const __user *argv,
                const char __user *const __user *envp);
asmlinkage long (*orig_sys_exit)(int error_code);
asmlinkage long (*orig_sys_wait4)(pid_t pid, int __user *stat_addr,
                                int options, struct rusage __user *ru);
asmlinkage long (*orig_sys_kill)(int pid, int sig);
asmlinkage long (*orig_sys_uname)(struct old_utsname *buf);
/********************************************************************
*********************************************************************
******************* replace system call function ********************
*********************************************************************
********************************************************************/
asmlinkage long replace_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	int pid = orig_sys_getpid();
	syscall_count[__NR_read]++;
	ret = orig_sys_read(fd, buf, count);
	return ret;
}

asmlinkage long replace_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
	long ret;
	struct timespec ts_global;
	int pid = orig_sys_getpid();
	struct can_frame *frame = (struct can_frame *)buf;

	getnstimeofday(&ts_global);
	syscall_count[__NR_write]++;
	ret = orig_sys_write(fd, buf, count);
	return ret;
}

asmlinkage long replace_sys_open(const char __user *filename, int flags, umode_t mode)
{
	long ret;
	struct timespec ts_global;
	int pid = orig_sys_getpid();
	
	getnstimeofday(&ts_global);
	syscall_count[__NR_open]++;
	if (pid >= W_LIST) {
		printk(KERN_INFO "[forensic_open] Time:%ld.%09ld PID:%d Accessed_File:%s\n", ts_global.tv_sec, ts_global.tv_nsec, pid, filename);
	}
	ret = orig_sys_open(filename, flags, mode);
	return ret;
}

asmlinkage long replace_sys_close(unsigned int fd)
{
	long ret;
	int pid = orig_sys_getpid();
	syscall_count[__NR_close]++;
	ret = orig_sys_close(fd);
	return ret;
}

asmlinkage long replace_sys_stat(const char __user *filename,
                        struct __old_kernel_stat __user *statbuf)
{
	long ret;
	int pid = orig_sys_getpid();
	syscall_count[__NR_stat]++;
    	ret = orig_sys_stat(filename, statbuf);
    	return ret;
}

asmlinkage long replace_sys_fstat(unsigned int fd,
                        struct __old_kernel_stat __user *statbuf)
{
	long ret;
	int pid = orig_sys_getpid();
	syscall_count[__NR_fstat]++;
    	ret = orig_sys_fstat(fd, statbuf);
    	return ret;
}

asmlinkage long replace_sys_lstat(const char __user *filename,
                        struct __old_kernel_stat __user *statbuf)
{
	long ret;
	int pid = orig_sys_getpid();
	syscall_count[__NR_lstat]++;
    	ret = orig_sys_lstat(filename, statbuf);
    	return ret;
}

asmlinkage long replace_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
                                int timeout)
{
	long ret;
	int pid = orig_sys_getpid();
	syscall_count[__NR_poll]++;
    	ret = orig_sys_poll(ufds, nfds, timeout);
    	return ret;
}

asmlinkage long replace_sys_lseek(unsigned int fd, off_t offset,
                          unsigned int whence)
{
	long ret;
	
	syscall_count[__NR_lseek]++;
    	ret = orig_sys_lseek(fd, offset, whence);
    	return ret;
}

asmlinkage long replace_sys_mmap(struct mmap_arg_struct __user *arg)
{
	long ret;
	
	syscall_count[__NR_mmap]++;
    	ret = orig_sys_mmap(arg);
    	return ret;
}

asmlinkage long replace_sys_mprotect(unsigned long start, size_t len,
                                unsigned long prot)
{
	long ret;
	
	syscall_count[__NR_mprotect]++;
    	ret = orig_sys_mprotect(start, len, prot);
    	return ret;
}

asmlinkage long replace_sys_munmap(unsigned long addr, size_t len)
{
	long ret;
	
	syscall_count[__NR_munmap]++;
    	ret = orig_sys_munmap(addr, len);
    	return ret;
}

asmlinkage long replace_sys_brk(unsigned long brk)
{
	long ret;
	
	syscall_count[__NR_brk]++;
    	ret = orig_sys_brk(brk);
    	return ret;
}
asmlinkage long replace_sys_rt_sigaction(int arg1,
                                 const struct sigaction __user *arg2,
                                 struct sigaction __user *arg3,
                                 size_t arg4)

{
	long ret;
	
	syscall_count[__NR_rt_sigaction]++;
    	ret = orig_sys_rt_sigaction(arg1, arg2, arg3, arg4);
    	return ret;
}
asmlinkage long replace_sys_rt_sigprocmask(int how, sigset_t __user *set,
                                sigset_t __user *oset, size_t sigsetsize)
{
	long ret;
	
	syscall_count[__NR_rt_sigprocmask]++;
    	ret = orig_sys_rt_sigprocmask(how, set, oset, sigsetsize);
    	return ret;
}

asmlinkage long replace_sys_ioctl(unsigned int fd, unsigned int cmd,
                                unsigned long arg)
{
	long ret;
	
	syscall_count[__NR_ioctl]++;
    	ret = orig_sys_ioctl(fd, cmd, arg);
    	return ret;
}

asmlinkage long replace_sys_pread64(unsigned int fd, char __user *buf,
                            size_t count, loff_t pos)
{
	long ret;
	
	syscall_count[__NR_pread64]++;
    	ret = orig_sys_pread64(fd, buf, count, pos);
    	return ret;
}
asmlinkage long replace_sys_pwrite64(unsigned int fd, const char __user *buf,
                             size_t count, loff_t pos)
{
	long ret;
	
	syscall_count[__NR_pwrite64]++;
    	ret = orig_sys_pwrite64(fd, buf, count, pos);
    	return ret;
}
asmlinkage long replace_sys_readv(unsigned long fd,
                          const struct iovec __user *vec,
                          unsigned long vlen)
{
	long ret;
	
	syscall_count[__NR_readv]++;
    	ret = orig_sys_readv(fd, vec, vlen);
    	return ret;
}
asmlinkage long replace_sys_writev(unsigned long fd,
                           const struct iovec __user *vec,
                           unsigned long vlen)
{
	long ret;
	
	syscall_count[__NR_writev]++;
    	ret = orig_sys_writev(fd, vec, vlen);
    	return ret;
}
asmlinkage long replace_sys_access(const char __user *filename, int mode)
{
	long ret;
	
	syscall_count[__NR_access]++;
    	ret = orig_sys_access(filename, mode);
    	return ret;
}
asmlinkage long replace_sys_pipe(int __user *fildes)
{
	long ret;
	
	syscall_count[__NR_pipe]++;
    	ret = orig_sys_pipe(fildes);
    	return ret;
}
asmlinkage long replace_sys_select(int n, fd_set __user *inp, fd_set __user *outp,
                        fd_set __user *exp, struct timeval __user *tvp)
{
	long ret;
	
	syscall_count[__NR_select]++;
    	ret = orig_sys_select(n, inp, outp, exp, tvp);
    	return ret;
}
asmlinkage long replace_sys_sched_yield(void)
{
	long ret;
	
	syscall_count[__NR_sched_yield]++;
    	ret = orig_sys_sched_yield();
    	return ret;
}
asmlinkage long replace_sys_mremap(unsigned long addr,
                           unsigned long old_len, unsigned long new_len,
                           unsigned long flags, unsigned long new_addr)
{
	long ret;
	
	syscall_count[__NR_mremap]++;
    	ret = orig_sys_mremap(addr, old_len, new_len, flags, new_addr);
    	return ret;
}
asmlinkage long replace_sys_msync(unsigned long start, size_t len, int flags)
{
	long ret;
	
	syscall_count[__NR_msync]++;
    	ret = orig_sys_msync(start, len, flags);
    	return ret;
}
asmlinkage long replace_sys_mincore(unsigned long start, size_t len,
                                unsigned char __user * vec)
{
	long ret;
	
	syscall_count[__NR_mincore]++;
    	ret = orig_sys_mincore(start, len, vec);
    	return ret;
}
asmlinkage long replace_sys_madvise(unsigned long start, size_t len, int behavior)
{
	long ret;
	
	syscall_count[__NR_madvise]++;
    	ret = orig_sys_madvise(start, len, behavior);
    	return ret;
}
asmlinkage long replace_sys_shmget(key_t key, size_t size, int flag)
{
	long ret;
	
	syscall_count[__NR_shmget]++;
    	ret = orig_sys_shmget(key, size, flag);
    	return ret;
}
asmlinkage long replace_sys_shmat(int shmid, char __user *shmaddr, int shmflg)
{
	long ret;
	
	syscall_count[__NR_shmat]++;
    	ret = orig_sys_shmat(shmid, shmaddr, shmflg);
    	return ret;
}
asmlinkage long replace_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
	long ret;
	
	syscall_count[__NR_shmctl]++;
    	ret = orig_sys_shmctl(shmid, cmd, buf);
    	return ret;
}
asmlinkage long replace_sys_dup(unsigned int fildes)
{
	long ret;
	
	syscall_count[__NR_dup]++;
    	ret = orig_sys_dup(fildes);
    	return ret;
}
asmlinkage long replace_sys_dup2(unsigned int oldfd, unsigned int newfd)
{
	long ret;
	
	syscall_count[__NR_dup2]++;
    	ret = orig_sys_dup2(oldfd, newfd);
    	return ret;
}
asmlinkage long replace_sys_pause(void)
{
	long ret;
	
	syscall_count[__NR_pause]++;
    	ret = orig_sys_pause();
    	return ret;
}
asmlinkage long replace_sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	long ret;
	
	syscall_count[__NR_nanosleep]++;
    	ret = orig_sys_nanosleep(rqtp, rmtp);
    	return ret;
}
asmlinkage long replace_sys_getitimer(int which, struct itimerval __user *value)
{
	long ret;
	
	syscall_count[__NR_getitimer]++;
    	ret = orig_sys_getitimer(which, value);
    	return ret;
}
asmlinkage long replace_sys_alarm(unsigned int seconds)
{
	long ret;
	
	syscall_count[__NR_alarm]++;
    	ret = orig_sys_alarm(seconds);
    	return ret;
}
asmlinkage long replace_sys_setitimer(int which,
                                struct itimerval __user *value,
                                struct itimerval __user *ovalue)
{
	long ret;
	
	syscall_count[__NR_setitimer]++;
    	ret = orig_sys_setitimer(which, value, ovalue);
    	return ret;
}
asmlinkage long replace_sys_getpid(void)
{
	long ret;
	
	syscall_count[__NR_getpid]++;
    	ret = orig_sys_getpid();
    	return ret;
}
asmlinkage long replace_sys_sendfile(int out_fd, int in_fd,
                             off_t __user *offset, size_t count)
{
	long ret;
	
	syscall_count[__NR_sendfile]++;
    	ret = orig_sys_sendfile(out_fd, in_fd, offset, count);
    	return ret;
}
asmlinkage long replace_sys_socket(int arg1, int arg2, int arg3)
{
	long ret;
	
	syscall_count[__NR_socket]++;
    	ret = orig_sys_socket(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_connect(int arg1, struct sockaddr __user *arg2, int arg3)
{
	long ret;
	pid_t pid = orig_sys_getpid();
	struct timespec ts_global;
	struct sockaddr_in *addr = (struct sockaddr_in *)arg2;
	unsigned short port = ntohs(addr->sin_port);
	unsigned int ipaddr = addr->sin_addr.s_addr;
	
	syscall_count[__NR_connect]++;
	getnstimeofday(&ts_global);
	if (pid >= W_LIST) {
		printk(KERN_INFO "[syscall_connect] Time:%ld.%9ld PID:%d IP:%d.%d.%d.%d Port:%d\n", ts_global.tv_sec, ts_global.tv_nsec, pid, (ipaddr)&0xFF, (ipaddr>>8)&0xFF, (ipaddr>>16)&0xFF, (ipaddr>>24)&0xFF, port);
	}
	ret = orig_sys_connect(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_accept(int arg1, struct sockaddr __user *arg2, int __user *arg3)
{
	long ret;
	syscall_count[__NR_accept]++;
    	ret = orig_sys_accept(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_sendto(int arg1, void __user *arg2, size_t arg3, unsigned arg4,
                                struct sockaddr __user *arg5, int arg6)
{
	long ret;
	pid_t pid = orig_sys_getpid();
	struct timespec ts_global;
	struct sockaddr_in *addr = (struct sockaddr_in *)arg5;
	unsigned short port = ntohs(addr->sin_port);
	unsigned int ipaddr = addr->sin_addr.s_addr;
	
	syscall_count[__NR_sendto]++;
	getnstimeofday(&ts_global);
	if (pid >= W_LIST) {
		printk(KERN_INFO "[forensic_sendto] Time:%ld.%9ld PID:%d IP:%d.%d.%d.%d Port:%d\n", ts_global.tv_sec, ts_global.tv_nsec, pid, (ipaddr)&0xFF, (ipaddr>>8)&0xFF, (ipaddr>>16)&0xFF, (ipaddr>>24)&0xFF, port);
    	}
	ret = orig_sys_sendto(arg1, arg2, arg3, arg4, arg5, arg6);
    	return ret;
}
asmlinkage long replace_sys_recvfrom(int arg1, void __user *arg2, size_t arg3, unsigned arg4,
                                struct sockaddr __user *arg5, int __user *arg6)
{
	long ret;
	
	syscall_count[__NR_recvfrom]++;
    	ret = orig_sys_recvfrom(arg1, arg2, arg3, arg4, arg5, arg6);
    	return ret;
}
asmlinkage long replace_sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long ret;
	
	syscall_count[__NR_sendmsg]++;
    	ret = orig_sys_sendmsg(fd, msg, flags);
    	return ret;
}
asmlinkage long replace_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long ret;
	struct timespec ts_global;
	pid_t pid = orig_sys_getpid();
	struct can_frame *frame = (struct can_frame *)msg->msg_iov->iov_base;
	
	syscall_count[__NR_recvmsg]++;
	getnstimeofday(&ts_global);
	if (pid >= W_LIST) {
		if ((0x0 <= frame->can_id && frame->can_id <= 0x7FF) && (frame->can_dlc == 1)) {
			printk(KERN_INFO "[forensic_can] Time:%ld.%09ld CAN_PACKET:%03x[%d]%02x\n", ts_global.tv_sec, ts_global.tv_nsec, frame->can_id, frame->can_dlc, frame->data[0]);
		} else if ((0x0 <= frame->can_id && frame->can_id <= 0x7FF) && (frame->can_dlc == 2)) {
			printk(KERN_INFO "[forensic_can] Time:%ld.%09ld CAN_PACKET:%03x[%d]%02x%02x\n", ts_global.tv_sec, ts_global.tv_nsec, frame->can_id, frame->can_dlc, frame->data[0], frame->data[1]);
		} else if ((0x0 <= frame->can_id && frame->can_id <= 0x7FF) && (frame->can_dlc == 3)) {
			printk(KERN_INFO "[forensic_can] Time:%ld.%09ld CAN_PACKET:%03x[%d]%02x%02x%02x\n", ts_global.tv_sec, ts_global.tv_nsec, frame->can_id, frame->can_dlc, frame->data[0], frame->data[1], frame->data[2]);
		} else if ((0x0 <= frame->can_id && frame->can_id <= 0x7FF) && (frame->can_dlc == 4)) {
			printk(KERN_INFO "[forensic_can] Time:%ld.%09ld CAN_PACKET:%03x[%d]%02x%02x%02x%02x\n", ts_global.tv_sec, ts_global.tv_nsec, frame->can_id, frame->can_dlc, frame->data[0], frame->data[1], frame->data[2], frame->data[3]);
		} else if ((0x0 <= frame->can_id && frame->can_id <= 0x7FF) && (frame->can_dlc == 5)) {
			printk(KERN_INFO "[forensic_can] Time:%ld.%09ld CAN_PACKET:%03x[%d]%02x%02x%02x%02x%02x\n", ts_global.tv_sec, ts_global.tv_nsec, frame->can_id, frame->can_dlc, frame->data[0], frame->data[1], frame->data[2], frame->data[3], frame->data[4]);
		} else if ((0x0 <= frame->can_id && frame->can_id <= 0x7FF) && (frame->can_dlc == 6)) {
			printk(KERN_INFO "[forensic_can Time:%ld.%09ld CAN_PACKET:%03x[%d]%02x%02x%02x%02x%02x%02x\n", ts_global.tv_sec, ts_global.tv_nsec, frame->can_id, frame->can_dlc, frame->data[0], frame->data[1], frame->data[2], frame->data[3], frame->data[4], frame->data[5]);
		} else if ((0x0 <= frame->can_id && frame->can_id <= 0x7FF) && (frame->can_dlc == 7)) {
			printk(KERN_INFO "[forensic_can] Time:%ld.%09ld CAN_PACKET:%03x[%d]%02x%02x%02x%02x%02x%02x%02x\n", ts_global.tv_sec, ts_global.tv_nsec, frame->can_id, frame->can_dlc, frame->data[0], frame->data[1], frame->data[2], frame->data[3], frame->data[4], frame->data[5], frame->data[6]);
		} else if ((0x0 <= frame->can_id && frame->can_id <= 0x7FF) && (frame->can_dlc == 8)) {
			printk(KERN_INFO "[forensic_can] Time:%ld.%09ld CAN_PACKET:%03x[%d]%02x%02x%02x%02x%02x%02x%02x%02x\n", ts_global.tv_sec, ts_global.tv_nsec, frame->can_id, frame->can_dlc, frame->data[0], frame->data[1], frame->data[2], frame->data[3], frame->data[4], frame->data[5], frame->data[6], frame->data[7]);
		}
	}
	ret = orig_sys_recvmsg(fd, msg, flags);
	return ret;
}
asmlinkage long replace_sys_shutdown(int arg1, int arg2)
{
	long ret;
	
	syscall_count[__NR_shutdown]++;
    	ret = orig_sys_shutdown(arg1, arg2);
    	return ret;
}
asmlinkage long replace_sys_bind(int arg1, struct sockaddr __user *arg2, int arg3)
{
	long ret;
	
	syscall_count[__NR_bind]++;
    	ret = orig_sys_bind(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_listen(int arg1, int arg2)
{
	long ret;
	
	syscall_count[__NR_listen]++;
    	ret = orig_sys_listen(arg1, arg2);
    	return ret;
}
//End Graduation thesis
asmlinkage long replace_sys_getsockname(int arg1, struct sockaddr __user *arg2, int __user *arg3)
{
	long ret;
	syscall_count[__NR_getsockname]++;
    	ret = orig_sys_getsockname(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_getpeername(int arg1, struct sockaddr __user *arg2, int __user *arg3)
{
	long ret;
	syscall_count[__NR_getpeername]++;
    	ret = orig_sys_getpeername(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_socketpair(int arg1, int arg2, int arg3, int __user *arg4)
{
	long ret;
	syscall_count[__NR_socketpair]++;
    	ret = orig_sys_socketpair(arg1, arg2, arg3, arg4);
    	return ret;
}
asmlinkage long replace_sys_setsockopt(int fd, int level, int optname,
                                char __user *optval, int optlen)
{
	long ret;
	syscall_count[__NR_setsockopt]++;
    	ret = orig_sys_setsockopt(fd, level, optname, optval, optlen);
    	return ret;
}
asmlinkage long replace_sys_getsockopt(int fd, int level, int optname,
                                char __user *optval, int __user *optlen)
{
	long ret;
	syscall_count[__NR_getsockopt]++;
    	ret = orig_sys_getsockopt(fd, level, optname, optval, optlen);
    	return ret;
}
asmlinkage long replace_sys_clone(unsigned long arg1, unsigned long arg2, int arg3, int __user *arg4,
			  int __user *arg5, int arg6)
{
	long ret;
	syscall_count[__NR_clone]++;
    	ret = orig_sys_clone(arg1, arg2, arg3, arg4, arg5, arg6);
    	return ret;
}
asmlinkage long replace_sys_fork(void)
{
	long ret;
	syscall_count[__NR_fork]++;
    	ret = orig_sys_fork();
    	return ret;
}
asmlinkage long replace_sys_vfork(void)
{
	long ret;
	syscall_count[__NR_vfork]++;
    	ret = orig_sys_vfork();
    	return ret;
}
asmlinkage long replace_sys_execve(const char __user *filename,
                const char __user *const __user *argv,
                const char __user *const __user *envp)
{
	long ret;
	syscall_count[__NR_execve]++;
    	ret = orig_sys_execve(filename, argv, envp);
    	return ret;
}
asmlinkage long replace_sys_exit(int error_code)
{
	long ret;
	syscall_count[__NR_exit]++;
    	ret = orig_sys_exit(error_code);
    	return ret;
}
asmlinkage long replace_sys_wait4(pid_t pid, int __user *stat_addr,
                                int options, struct rusage __user *ru)
{
	long ret;
	syscall_count[__NR_wait4]++;
    	ret = orig_sys_wait4(pid, stat_addr, options, ru);
    	return ret;
}
asmlinkage long replace_sys_kill(int pid, int sig)
{
	long ret;
	syscall_count[__NR_kill]++;
    	ret = orig_sys_kill(pid, sig);
    	return ret;
}
asmlinkage long replace_sys_uname(struct old_utsname *buf)
{
	long ret;
	//int i;
	syscall_count[__NR_uname]++;
    	ret = orig_sys_uname(buf);
    	return ret;
}

static void save_original_syscall_address(void)
{
	orig_sys_read = syscall_table[__NR_read];
	orig_sys_write = syscall_table[__NR_write];
	orig_sys_open = syscall_table[__NR_open];
	orig_sys_close = syscall_table[__NR_close];
	orig_sys_stat = syscall_table[__NR_stat];
	orig_sys_fstat = syscall_table[__NR_fstat];
	orig_sys_lstat = syscall_table[__NR_lstat];
	orig_sys_poll = syscall_table[__NR_poll];
	orig_sys_lseek = syscall_table[__NR_lseek];
	orig_sys_mmap = syscall_table[__NR_mmap];
	orig_sys_mprotect = syscall_table[__NR_mprotect];
	orig_sys_munmap = syscall_table[__NR_munmap];
	orig_sys_brk = syscall_table[__NR_brk];
	orig_sys_rt_sigaction = syscall_table[__NR_rt_sigaction];
	orig_sys_rt_sigprocmask = syscall_table[__NR_rt_sigprocmask];
	//orig_sys_rt_sigreturn = syscall_table[__NR_rt_sigreturn];
	orig_sys_ioctl = syscall_table[__NR_ioctl];
	orig_sys_pread64 = syscall_table[__NR_pread64];
	orig_sys_pwrite64 = syscall_table[__NR_pwrite64];
	orig_sys_readv = syscall_table[__NR_readv];
	orig_sys_writev = syscall_table[__NR_writev];
	orig_sys_access = syscall_table[__NR_access];
	orig_sys_pipe = syscall_table[__NR_pipe];
	orig_sys_select = syscall_table[__NR_select];
	orig_sys_sched_yield = syscall_table[__NR_sched_yield];
	orig_sys_mremap = syscall_table[__NR_mremap];
	orig_sys_msync = syscall_table[__NR_msync];
	orig_sys_mincore = syscall_table[__NR_mincore];
	orig_sys_madvise = syscall_table[__NR_madvise];
	orig_sys_shmget = syscall_table[__NR_shmget];
	orig_sys_shmat = syscall_table[__NR_shmat];
	orig_sys_shmctl = syscall_table[__NR_shmctl];
	orig_sys_dup = syscall_table[__NR_dup];
	orig_sys_dup2 = syscall_table[__NR_dup2];
	orig_sys_pause = syscall_table[__NR_pause];
	orig_sys_nanosleep = syscall_table[__NR_nanosleep];
	orig_sys_getitimer = syscall_table[__NR_getitimer];
	orig_sys_alarm = syscall_table[__NR_alarm];
	orig_sys_setitimer = syscall_table[__NR_setitimer];
	orig_sys_getpid = syscall_table[__NR_getpid];
	orig_sys_sendfile = syscall_table[__NR_sendfile];
	orig_sys_socket = syscall_table[__NR_socket];
	orig_sys_connect = syscall_table[__NR_connect];
	orig_sys_accept = syscall_table[__NR_accept];
	orig_sys_sendto = syscall_table[__NR_sendto];
	orig_sys_recvfrom = syscall_table[__NR_recvfrom];
	orig_sys_sendmsg = syscall_table[__NR_sendmsg];
	orig_sys_recvmsg = syscall_table[__NR_recvmsg];
	//orig_sys_shutdown = syscall_table[__NR_shutdown];
	orig_sys_bind = syscall_table[__NR_bind];
	orig_sys_listen = syscall_table[__NR_listen];
	orig_sys_getsockname = syscall_table[__NR_getsockname];
	orig_sys_getpeername = syscall_table[__NR_getpeername];
	orig_sys_socketpair = syscall_table[__NR_socketpair];
	orig_sys_setsockopt = syscall_table[__NR_setsockopt];
	orig_sys_getsockopt = syscall_table[__NR_getsockopt];

	//orig_sys_clone = syscall_table[__NR_clone];
	//orig_sys_fork = syscall_table[__NR_fork];
	//orig_sys_vfork = syscall_table[__NR_vfork];
	//orig_sys_execve = syscall_table[__NR_execve];

	orig_sys_exit = syscall_table[__NR_exit];
	orig_sys_wait4 = syscall_table[__NR_wait4];
	//orig_sys_kill = syscall_table[__NR_kill];
	orig_sys_uname = syscall_table[__NR_uname];
}

static void change_page_attr_to_rw(pte_t *pte)
{
    set_pte_atomic(pte, pte_mkwrite(*pte));
}

static void change_page_attr_to_ro(pte_t *pte)
{
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
}

static void replace_system_call(void *new, unsigned int syscall_number)
{
   	unsigned int level = 0;
    	pte_t *pte;

    	pte = lookup_address((unsigned long) syscall_table, &level);
    	/* Need to set r/w to a page which syscall_table is in. */
    	change_page_attr_to_rw(pte);

    	syscall_table[syscall_number] = new;
	/* set back to read only */
    	change_page_attr_to_ro(pte);
}

static int syscall_replace_init(void)
{
	DEFINE_SPINLOCK(spinlock);
    	pr_info("sys_call_table address is 0x%p\n", syscall_table);
	spin_lock(&spinlock);
	save_original_syscall_address();
	replace_system_call(replace_sys_read, 0);
	replace_system_call(replace_sys_write, 1);
	replace_system_call(replace_sys_open, 2);
	replace_system_call(replace_sys_close, 3);
	replace_system_call(replace_sys_stat, 4);
	replace_system_call(replace_sys_fstat, 5);
	replace_system_call(replace_sys_lstat, 6);
	replace_system_call(replace_sys_poll, 7);
	replace_system_call(replace_sys_lseek, 8);
	replace_system_call(replace_sys_mmap, 9);
	replace_system_call(replace_sys_mprotect, 10);
	replace_system_call(replace_sys_munmap, 11);
	replace_system_call(replace_sys_brk, 12);
	replace_system_call(replace_sys_rt_sigaction, 13);
	replace_system_call(replace_sys_rt_sigprocmask, 14);
	//replace_system_call(replace_sys_rt_sigreturn, 15);
	replace_system_call(replace_sys_ioctl, 16);
	replace_system_call(replace_sys_pread64, 17);
	replace_system_call(replace_sys_pwrite64, 18);
	replace_system_call(replace_sys_readv, 19);
	replace_system_call(replace_sys_writev, 20);
	replace_system_call(replace_sys_access, 21);
	replace_system_call(replace_sys_pipe, 22);
	replace_system_call(replace_sys_select, 23);
	replace_system_call(replace_sys_sched_yield, 24);
	replace_system_call(replace_sys_mremap, 25);
	replace_system_call(replace_sys_msync, 26);
	replace_system_call(replace_sys_mincore, 27);
	replace_system_call(replace_sys_madvise, 28);
	replace_system_call(replace_sys_shmget, 29);
	replace_system_call(replace_sys_shmat, 30);
	replace_system_call(replace_sys_shmctl, 31);
	replace_system_call(replace_sys_dup, 32);
	replace_system_call(replace_sys_dup2, 33);
	replace_system_call(replace_sys_pause, 34);
	replace_system_call(replace_sys_nanosleep, 35);
	replace_system_call(replace_sys_getitimer, 36);
	replace_system_call(replace_sys_alarm, 37);
	replace_system_call(replace_sys_setitimer, 38);
	replace_system_call(replace_sys_getpid, 39);
	replace_system_call(replace_sys_sendfile, 40);
	replace_system_call(replace_sys_socket, 41);
	replace_system_call(replace_sys_connect, 42);
	replace_system_call(replace_sys_accept, 43);
	replace_system_call(replace_sys_sendto, 44);
	replace_system_call(replace_sys_recvfrom, 45);
	replace_system_call(replace_sys_sendmsg, 46);
	replace_system_call(replace_sys_recvmsg, 47);
	//replace_system_call(replace_sys_shutdown, 48);
	replace_system_call(replace_sys_bind, 49);
	replace_system_call(replace_sys_listen, 50);
	replace_system_call(replace_sys_getsockname, 51);
	replace_system_call(replace_sys_getpeername, 52);
	replace_system_call(replace_sys_socketpair, 53);
	replace_system_call(replace_sys_setsockopt, 54);
	replace_system_call(replace_sys_getsockopt, 55);

	//replace_system_call(replace_sys_clone, 56);
	//replace_system_call(replace_sys_fork, 57);
	//replace_system_call(replace_sys_vfork, 58);
	//replace_system_call(replace_sys_execve, 59);

	replace_system_call(replace_sys_exit, 60);
	replace_system_call(replace_sys_wait4, 61);
	//replace_system_call(replace_sys_kill, 62);
	replace_system_call(replace_sys_uname, 63);

	spin_unlock(&spinlock);
	pr_info("system call replaced\n");
	
	
	return 0;
}

static void syscall_replace_cleanup(void)
{
	//spinlock_t spinlock = SPIN_LOCK_UNLOCKED;
	DEFINE_SPINLOCK(spinlock);
    	pr_info("cleanup");
	spin_lock(&spinlock);
	replace_system_call(orig_sys_read, 0);
	replace_system_call(orig_sys_write, 1);
	replace_system_call(orig_sys_open, 2);
	replace_system_call(orig_sys_close, 3);
	replace_system_call(orig_sys_stat, 4);
	replace_system_call(orig_sys_fstat, 5);
	replace_system_call(orig_sys_lstat, 6);
	replace_system_call(orig_sys_poll, 7);
	replace_system_call(orig_sys_lseek, 8);
	replace_system_call(orig_sys_mmap, 9);
	replace_system_call(orig_sys_mprotect, 10);
	replace_system_call(orig_sys_munmap, 11);
	replace_system_call(orig_sys_brk, 12);
	replace_system_call(orig_sys_rt_sigaction, 13);
	replace_system_call(orig_sys_rt_sigprocmask, 14);
	//replace_system_call(orig_sys_rt_sigreturn, 15);
	replace_system_call(orig_sys_ioctl, 16);
	replace_system_call(orig_sys_pread64, 17);
	replace_system_call(orig_sys_pwrite64, 18);
	replace_system_call(orig_sys_readv, 19);
	replace_system_call(orig_sys_writev, 20);
	replace_system_call(orig_sys_access, 21);
	replace_system_call(orig_sys_pipe, 22);
	replace_system_call(orig_sys_select, 23);
	replace_system_call(orig_sys_sched_yield, 24);
	replace_system_call(orig_sys_mremap, 25);
	replace_system_call(orig_sys_msync, 26);
	replace_system_call(orig_sys_mincore, 27);
	replace_system_call(orig_sys_madvise, 28);
	replace_system_call(orig_sys_shmget, 29);
	replace_system_call(orig_sys_shmat, 30);
	replace_system_call(orig_sys_shmctl, 31);
	replace_system_call(orig_sys_dup, 32);
	replace_system_call(orig_sys_dup2, 33);
	replace_system_call(orig_sys_pause, 34);
	replace_system_call(orig_sys_nanosleep, 35);
	replace_system_call(orig_sys_getitimer, 36);
	replace_system_call(orig_sys_alarm, 37);
	replace_system_call(orig_sys_setitimer, 38);
	replace_system_call(orig_sys_getpid, 39);
	replace_system_call(orig_sys_sendfile, 40);
	replace_system_call(orig_sys_socket, 41);
	replace_system_call(orig_sys_connect, 42);
	replace_system_call(orig_sys_accept, 43);
	//replace_system_call(orig_sys_sendto, 44);
	replace_system_call(orig_sys_recvfrom, 45);
	replace_system_call(orig_sys_sendmsg, 46);
	replace_system_call(orig_sys_recvmsg, 47);
	//replace_system_call(orig_sys_shutdown, 48);
	replace_system_call(orig_sys_bind, 49);
	replace_system_call(orig_sys_listen, 50);
	replace_system_call(orig_sys_getsockname, 51);
	replace_system_call(orig_sys_getpeername, 52);
	replace_system_call(orig_sys_socketpair, 53);
	replace_system_call(orig_sys_setsockopt, 54);
	replace_system_call(orig_sys_getsockopt, 55);

	//replace_system_call(orig_sys_clone, 56);
	//replace_system_call(orig_sys_fork, 57);
	//replace_system_call(orig_sys_vfork, 58);
	//replace_system_call(orig_sys_execve, 59);

	replace_system_call(orig_sys_exit, 60);
	replace_system_call(orig_sys_wait4, 61);
	//replace_system_call(orig_sys_kill, 62);
	replace_system_call(orig_sys_uname, 63);
	spin_unlock(&spinlock);
}

module_init(syscall_replace_init);
module_exit(syscall_replace_cleanup);
