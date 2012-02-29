/* ex: set ts=4 et: */
/*
 * Copyright 2012 Ryan Flynn <parseerror+dragnet@gmail.com>
 *
 * Drag:net -- slow an application's internet connection to a crawl
 * Useful for testing/simulating network connections worse than yours
 *
 * Build:
 *   make
 *
 * Usage:
 *   LD_PRELOAD=./dragnet.so foo
 *
 * Examples:
 *   LD_PRELOAD=./dragnet.so wget http://www.google.com/ -O - 2>/dev/null
 *   LD_PRELOAD=./dragnet.so wget http://www.google.com/ -O - 1>/dev/null
 *   LD_PRELOAD=./dragnet.so curl http://www.google.com/ -o - 2>/dev/null
 *   LD_PRELOAD=./dragnet.so curl http://www.google.com/ -o - 1>/dev/null
 *
 * Status:
 *  - wget works
 *  - curl works
 *
 * TODO:
 *  - separate send/recv rate limiting
 */

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <poll.h>

static int Initialized = 0;
/*
 * Rate Limiting : maximum bytes/sec we'll allow through; the rest is cached for future calls
 * 0 means unlimited
 */
static unsigned long MaxBytesPerSec = 256;

static void do_dragnet_init(void)
{
    char *c;
    if ((c = getenv("DRAGNET_BPS")))
    {
        MaxBytesPerSec = strtoul(c, NULL, 10);
    }
    Initialized = 1;
}

/*
 * per-trackedsocket ratelimiting
 */
struct ratelim {
    struct timeval sec; /* last second we've seen action */
    size_t secbytes;    /* how many bytes we've passed through during 'sec' second */
    size_t pos;
    size_t len;
    struct ratelim *next;
    unsigned char data[0];
} ratelim;

/*
 * remember which fds are socket()s and which aren't
 */
static struct trackedsocket {
    int domain;
    int type;
    unsigned nonblock:1;
    struct ratelim *rd;
    struct ratelim *wr;
} Socket[4096]; /* FIXME: base on getrlimit(RLIMIT_NOFILE) */

static void ratelim_init(struct ratelim *r)
{
    r->sec.tv_sec = 0;
    r->sec.tv_usec = 0;
    r->secbytes = 0;
    r->pos = 0;
    r->len = 0;
    r->next = 0;
}

static void ratelim_destroy(struct ratelim **r)
{
    if (*r)
        free(*r), *r = 0;
}

struct trackedsocket * trackedsocket_byfd(int fd)
{
    return Socket + fd;
}

static void trackedsocket_init(int fd, int domain, int type, int protocol)
{
    struct trackedsocket *t = trackedsocket_byfd(fd);
    t->domain = domain;
    t->type = type;
    ratelim_destroy(&t->rd);
    ratelim_destroy(&t->wr);
}

static void trackedsocket_destroy(int fd)
{
    trackedsocket_init(fd, 0, 0, 0);
}

static void dn_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void) vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#define MIN(x,y) ((x) < (y) ? (x) : (y))

/*
 * return buffered bytes, if we have any, based on our ratelimiting configuration
 */
static ssize_t ratelim_get(struct trackedsocket *t, struct ratelim **rl,
                           unsigned char **ptr, size_t len, int recvflags)
{
    struct ratelim *r = *rl;
    ssize_t bytes = 0;
    unsigned peek = (recvflags & MSG_PEEK);
    dn_log("        >> %s(%p, %p, %zu, %d)...\n", __func__, rl, ptr, len, recvflags);
    if (r && r->pos < r->len)
    {
        struct timeval now;
        (void)gettimeofday(&now, 0);
        if (now.tv_sec > r->sec.tv_sec)
            r->secbytes = 0; /* reset per-second bytecount if we're in a different second */
        if (!peek)
        {
            if (now.tv_sec > r->sec.tv_sec)
                r->sec = now; /* only update latest second if we're not peeking */
            if (MaxBytesPerSec && r->secbytes == MaxBytesPerSec)
            {
                if (t->nonblock)
                {
                    usleep(20000); /* artificially introduce 20msec delay to reduce call count... */
                    errno = EAGAIN;
                    return 0;
                } else {
                    unsigned long usec = 1000 * 1000 - r->sec.tv_usec;
                    dn_log("      >> sleeping for %lu microseconds on blocking socket...\n", usec);
                    usleep(usec);
                    r->secbytes = 0;
                }
            }
        }
        /* return as many bytes as limiting allows us, and not more than
         * we have to read, and not more than the space we have to write */
        bytes = MIN(r->len - r->pos, len);
        if (MaxBytesPerSec)
            bytes = MIN(bytes, MaxBytesPerSec - r->secbytes);
        *ptr = r->data + r->pos;
        if (!peek)
        {
            r->secbytes += bytes;
            r->pos += bytes;
            if (r->pos == r->len)
            {
                /* done with this buffer, move to next and nuke old space */
                *rl = r->next;
                if (*rl)
                    (*rl)->sec = now;
                free(r);
            }
        }
    }
    dn_log("            >> %s(...) = %zd {r=%p r->pos=%zu r->len=%zu}\n",
        __func__, bytes, r, r ? r->pos : 0, r ? r->len : 0);
    return bytes;
}

/*
 * when we do a real recv/recvfrom/read and receive data, we put it into our ratelim
 */
static size_t ratelim_put(struct ratelim **rl, const unsigned char *buf, size_t len)
{
    dn_log("      >> %s(len=%zu)\n", __func__, len);
    if (len)
    {
        /* TODO: instead of realloc, use a linked list of buffers */
        struct ratelim *last = malloc(len + sizeof *last);
        if (last)
        {
            ratelim_init(last);
            if (*rl)
            {
                (*rl)->next = last;
            } else {
                *rl = last;
            }
            memcpy(last->data, buf, len);
            last->len = len;
        }
    }
    return len;
}

static ssize_t do_write(int fd, const void *buf, size_t count);
static ssize_t do_read (int fd,       void *buf, size_t count, int recvflags);

/*********************** intercepted calls follow *******************/

int socket(int domain, int type, int protocol)
{
    int fd;
    /*
     * HACK: since our lib doesn't have a real initializer (since the client program doesn't even know about us)
     * we take this opportunity to check if we're initialized
     */
    if (!Initialized)
        do_dragnet_init();

    fd = syscall(SYS_socket, domain, type, protocol);
    dn_log("    >> intercepted socket(%d, %d, %d) = %d\n",
        domain, type, protocol, fd);
    if (fd >= 0 && (domain == AF_INET || domain == AF_INET6))
    {
        dn_log("        >> tracking socket %d\n", fd);
        trackedsocket_init(fd, domain, type, protocol);
    } else {
        dn_log("domain = %d\n", domain);
    }
    return fd;
}

/*
 * a lot of wasted space necessary to catch O_NONBLOCK, but var args makes it that way...
 */
int fcntl(int fd, int cmd, ... /* arg */ )
{
    va_list ap;
    va_start(ap, cmd);
    switch (cmd)
    {
    case F_GETFL:
        /* arg is void */
        dn_log("    >> intercepted fcntl(%d, %d)\n", fd, cmd);
        return syscall(SYS_fcntl, fd, cmd);
    case F_GETFD:
    case F_DUPFD:
    case F_SETFL:
        /* arg is long */
        {
            long l = va_arg(ap, long);
            dn_log("    >> intercepted fcntl(%d, %d, %ld)\n", fd, cmd, l);
            if (cmd == F_SETFL && (l & O_NONBLOCK))
            {
                struct trackedsocket *t = trackedsocket_byfd(fd);
                t->nonblock = 1;
                dn_log("      >> fcntl(%d, F_SETFL, &O_NONBLOCK)\n", fd);
            }
            return syscall(SYS_fcntl, fd, cmd, l);
        }
    default:
        /* arg is pointer */
        {
            void *p = va_arg(ap, void*);
            dn_log("    >> intercepted fcntl(%d, %d, %p)\n", fd, cmd, p);
            return syscall(SYS_fcntl, fd, cmd, p);
        }
    }
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t rf;
    dn_log("    >> intercepted recv(%d, %p, %zu, %d(",
        sockfd, buf, len, flags);
    if (flags & MSG_PEEK) dn_log("MSG_PEEK,");
    if (flags & MSG_DONTWAIT) dn_log("MSG_DONTWAIT,");
    dn_log(")\n");
    rf = do_read(sockfd, buf, len, flags);
    if (rf >= 0 || errno != EAGAIN)
        dn_log("recv()ed %zd bytes: %.*s\n", rf, rf > 0 ? (int)rf : 0, (const char *)buf);
    return rf;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    dn_log("    >> intercepted send(%d, %p, %zu, %d)\n%.*s\n",
        sockfd, buf, len, flags, (int)len, (const char*)buf);
    /* TODO: return do_write(sockfd, buf, len); */
    return syscall(SYS_sendto, sockfd, buf, len, flags, 0, 0);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                 const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ssize_t st;
    dn_log("    >> intercepted sendto(%d, %p, %zu, %d, %p, %lu)\n",
        sockfd, buf, len, flags, dest_addr, (unsigned long)addrlen);
    st = syscall(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
    dn_log("sendto()ed %zu bytes: %.*s\n", st, (int)st, (const char *)buf);
    return st;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t rf;
    dn_log("    >> intercepted recvfrom(%d, %p, %zu, %d, %p, %p)\n",
        sockfd, buf, len, flags, src_addr, addrlen);
    rf = syscall(SYS_recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
    dn_log("recvfrom()ed %zd bytes: ...\n", rf);
    return rf;
}

ssize_t read(int fd, void *buf, size_t count)
{
    ssize_t dr;
    dn_log("    >> intercepted read(%d, %p, %zu)\n", fd, buf, count);
    dr = do_read(fd, buf, count, 0);
    dn_log("%.*s\n", (int)dr, (const char*)buf);
    dn_log("    << done with read()...\n");
    return dr;
}

static ssize_t do_read(int fd, void *buf, size_t count, int recvflags)
{
    ssize_t rd;
    struct trackedsocket *t = trackedsocket_byfd(fd);
    if (!t->domain)
    {
        /* not tracked, pass it through */
        rd = syscall(SYS_read, fd, buf, count);
    } else {
        unsigned char *ptr;
        /* try local cache first... */
        rd = ratelim_get(t, &t->rd, &ptr, count, recvflags);
        if (!rd && errno == EAGAIN) {
            return -1;
        } else if (rd > 0) {
            memcpy(buf, ptr, rd);
        } else if (!rd) {
            /* if local cache is empty, do the real read()... */
            dn_log("        >> syscall(SYS_READ, %d, %p, %zu)\n", fd, buf, count);
            rd = syscall(SYS_read, fd, buf, count);
            if (rd < 0) {
                dn_log("read returned %zd, errno=%d (EAGAIN=%d)\n", rd, errno, EAGAIN);
            } else if (rd > 0) {
                /* if data's returned, cache it... */
                (void)ratelim_put(&t->rd, buf, rd);
                /* and read it out again... */
                rd = ratelim_get(t, &t->rd, &ptr, count, recvflags);
                memcpy(buf, ptr, rd);
            }
        }
    }
    return rd;
}

static ssize_t do_write(int fd, const void *buf, size_t count)
{
    struct trackedsocket *t = trackedsocket_byfd(fd);
    ssize_t wr;
    if (!t->domain)
    {
        /* not tracked, pass it through */
        wr = syscall(SYS_write, fd, buf, count);
    } else {
        unsigned char *ptr;
        (void)ratelim_put(&t->wr, buf, count);
        wr = ratelim_get(t, &t->wr, &ptr, count, 0);
        if (wr)
        {
            /* if local cache is empty, do actual call... */
            wr = syscall(SYS_write, fd, ptr, wr);
        }
    }
    return wr;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    dn_log("    >> intercepted write(%d, %p, %zu)\n%.*s\n", fd, buf, count, (int)count, (const char*)buf);
    return do_write(fd, buf, count);
}

int close(int fd)
{
    struct trackedsocket *t = trackedsocket_byfd(fd);
    dn_log("    >> intercepted close(%d)\n", fd);
    if (t->domain)
    {
        dn_log("        >> it's a socket\n");
        trackedsocket_destroy(fd);
    }
    return syscall(SYS_close, fd);
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout)
{
    dn_log("    >> intercepted select(%d, %p, %p, %p, %p)\n", nfds, readfds, writefds, exceptfds, timeout);
    return syscall(SYS_select, nfds, readfds, writefds, exceptfds, timeout);
}

static int do_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int cnt = 0;
    nfds_t i;
    if (timeout >= 1000)
    {
        /* if we're allowed a second or more, sleep for 1 second to make rate-limited
         * data available */
        dn_log("        >> %s sleeping for %lu milliseconds\n", __func__, timeout);
        usleep(1000 * 1000);
    }
    for (i = 0; i < nfds; i++)
    {
        struct trackedsocket *t = trackedsocket_byfd(fds[i].fd);
        if (t->domain && (fds[i].events & POLLIN))
        {
            unsigned char *ptr;
            ssize_t rd;
            /* just figure out if there's anything to read */
            rd = ratelim_get(t, &t->rd, &ptr, 1, MSG_PEEK); /* FIXME: abusing MSG_PEEK for our own use... */
            if (rd)
            {
                fds[i].revents |= POLLIN;
                fds[i].revents |= (fds[i].events & POLLIN);
                cnt++;
            }
        }
    }
    dn_log("      >> %s(%p, %u, %d) = %d\n", __func__, fds, nfds, timeout);
    return cnt;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int p;
    dn_log("    >> intercepted poll(%p, %d, %d)\n", fds, nfds, timeout);
    p = do_poll(fds, nfds, timeout);
    if (!p)
    {
        /* if we don't find anything, run actual poll */
        if (timeout >= 1000)
            timeout -= 1000;
        p = syscall(SYS_poll, fds, nfds, timeout);
        dn_log("      >> poll(%p, %d, %d) = %d\n", fds, nfds, timeout, p);
    }
    return p;
}
