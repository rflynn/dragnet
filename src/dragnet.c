/* ex: set ts=4 et: */
/*
 * Copyright 2012 Ryan Flynn <parseerror+dragnet@gmail.com>
 *
 * Drag:net -- slow an application's internet connection to a crawl
 * Useful for testing/simulating network connections worse than yours
 *
 * Build: $ make
 * Usage: $ LD_PRELOAD=./dragnet.so curl http://www.google.com/ -o -
 *
 * TODO: make curl work
 * TODO: detect non-blocking socket option and set EWOULDBLOCK instead of sleep()ing
 * TODO: make options set-able from env?
 */

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Rate Limiting : maximum bytes/sec we'll allow through; the rest is cached for future calls
 * 0 means unlimited
 */
static size_t MaxBytesPerSec = 1024;

/* limit the number of bytes returned by a single call;
 * sometimes applications calling recv(..., N) assume they always receive N bytes,
 * whereas they may receive 1..N
 */
#if 0
static ssize_t MinByteCount = 0; // TODO
static ssize_t MaxByteCount = 0; // TODO
static int     RandomizeByteCount = 0; // TODO
#endif

/*
 * per-Socket ratelimiting
 */
struct ratelim {
    time_t sec;        /* last second we've seen action */
    size_t secbytes;   /* how many bytes we've passed through during 'prev' second */
    size_t pos;
    size_t len;
    unsigned char *data;
    struct ratelim *next;
} ratelim;

/*
 * remember which fds are socket()s and which aren't;
 * only fuck with socket()s
 */
static struct trackedsocket {
    int domain;
    int type;
    struct ratelim *rd;
    struct ratelim *wr;
} Socket[4096]; /* FIXME: base on getrlimit(RLIMIT_NOFILE) */

static void ratelim_init(struct ratelim *r)
{
    r->sec = 0;
    r->secbytes = 0;
    r->pos = 0;
    r->len = 0;
    r->data = 0;
    r->next = 0;
}

static void ratelim_destroy(struct ratelim **r)
{
    if (*r)
    {
        free((*r)->data);
        free(*r);
        *r = 0;
    }
}

static void trackedsocket_init(int fd, int domain, int type, int protocol)
{
    struct trackedsocket *t = Socket + fd;
    t->domain = domain;
    t->type = type;
    ratelim_destroy(&t->rd);
    ratelim_destroy(&t->wr);
}

static void trackedsocket_destroy(int fd)
{
    trackedsocket_init(fd, 0, 0, 0);
}

#define MIN(x,y) ((x) < (y) ? (x) : (y))

/*
 * if we have bytes buffered, hand them out based on the configuration
 */
static ssize_t ratelim_get(struct ratelim **rl, unsigned char **ptr, size_t len)
{
    struct ratelim *r = *rl;
    ssize_t bytes = 0;
    if (r && r->len > r->pos)
    {
        time_t now = time(NULL);
        if (now > r->sec)
            r->sec = now, r->secbytes = 0;
        if (MaxBytesPerSec && r->secbytes == MaxBytesPerSec)
        {
            /* FIXME: only do this for blocking sockets... */
            /* TODO: keep track of usec so I can sleep more appropriate fraction... */
            usleep(1000 * 1000);
            r->secbytes = 0;
        }
        /* return as many bytes as limiting allows us, and not more than
         * we have to read, and not more than the space we have to write */
        bytes = MIN(r->len - r->pos, len);
        if (MaxBytesPerSec)
            bytes = MIN(bytes, MaxBytesPerSec - r->secbytes);
        r->secbytes += bytes;
        *ptr = r->data + r->pos;
        r->pos += bytes;
        if (r->pos == r->len)
        {
            /* done with this buffer, move to next and nuke old space */
            *rl = r->next;
            if (*rl)
                (*rl)->sec = now;
            free(r->data);
            free(r);
        }
    }
    printf("%s(...) = %zd {r->pos=%zu r->len=%zu}\n",
        __func__, bytes, r ? r->pos : 0, r ? r->len : 0);
    return bytes;
}

/*
 * when we do a real recv/recvfrom/read and receive data, we put it into our ratelim
 */
static size_t ratelim_put(struct ratelim **rl, const unsigned char *buf, size_t len)
{
    printf("%s(len=%zu)\n", __func__, len);
    if (len)
    {
        /* TODO: instead of realloc, use a linked list of buffers */
        struct ratelim *last = malloc(sizeof *last);
        if (last)
        {
            ratelim_init(last);
            last->data = malloc(len);
            if (!last->data)
            {
                free(last);
                return 0;
            }
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
static ssize_t do_read (int fd,       void *buf, size_t count);

/*********************** intercepted calls follow *******************/

int socket(int domain, int type, int protocol)
{
    int fd;
    fd = syscall(SYS_socket, domain, type, protocol);
    printf("    >> intercepted socket(%d, %d, %d) = %d\n",
        domain, type, protocol, fd);
    if (fd >= 0 && (domain == AF_INET || domain == AF_INET6))
    {
        printf("        >> tracking socket %d\n", fd);
        trackedsocket_init(fd, domain, type, protocol);
    } else {
        printf("domain = %d\n", domain);
    }
    return fd;
}

#if 0
// FIXME: need this for O_NONBLOCK
int fcntl(int fd, int cmd, ... /* arg */ );
{
    printf("    >> intercepted fcntl(%d, %d, ...)\n", fd, cmd);
    return syscall(SYS_recvfrom, sockfd, buf, len, flags, 0, 0);
}
#endif

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t rf;
    printf("    >> intercepted recv(%d, %p, %zu, %d)\n",
        sockfd, buf, len, flags);
    rf = do_read(sockfd, buf, len);
    printf("recv()ed %zd bytes: %.*s\n", rf, (int)rf, (const char *)buf);
    return rf;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    printf("    >> intercepted send(%d, %p, %zu, %d)\n%.*s\n",
        sockfd, buf, len, flags, (int)len, (const char*)buf);
    //return do_write(sockfd, buf, len);
    return syscall(SYS_sendto, sockfd, buf, len, flags, 0, 0);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                 const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ssize_t st;
    printf("    >> intercepted sendto(%d, %p, %zu, %d, %p, %lu)\n",
        sockfd, buf, len, flags, dest_addr, (unsigned long)addrlen);
    st = syscall(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
    printf("sendto()ed %zu bytes: %.*s\n", st, (int)st, (const char *)buf);
    return st;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t rf;
    printf("    >> intercepted recvfrom(%d, %p, %zu, %d, %p, %p)\n",
        sockfd, buf, len, flags, src_addr, addrlen);
    rf = syscall(SYS_recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
    printf("recvfrom()ed %zd bytes: %.*s\n", rf, (int)rf, (const char *)buf);
    return rf;
}

ssize_t read(int fd, void *buf, size_t count)
{
    printf("    >> intercepted read(%d, %p, %zu)\n%.*s\n",
        fd, buf, count, (int)count, (const char*)buf);
    return do_read(fd, buf, count);
}

static ssize_t do_read(int fd, void *buf, size_t count)
{
    ssize_t rd;
    if (!Socket[fd].domain)
    {
        /* not tracked, pass it through */
        rd = syscall(SYS_read, fd, buf, count);
    } else {
        struct trackedsocket *t = Socket+fd;
        unsigned char *ptr;
        /* try local cache first... */
        rd = ratelim_get(&t->rd, &ptr, count);
        if (rd > 0)
        {
            memcpy(buf, ptr, rd);
        } else if (!rd) {
            /* if local cache is empty, do the real read()... */
            rd = syscall(SYS_read, fd, buf, count);
            if (rd >= 0) /* success */
            {
                if (rd > 0)
                {
                    /* if data's returned, cache it... */
                    (void)ratelim_put(&t->rd, buf, count);
                    /* and read it out again... */
                    rd = ratelim_get(&t->rd, &ptr, count);
                    memcpy(buf, ptr, rd);
                }
            }
        }
    }
    return rd;
}

static ssize_t do_write(int fd, const void *buf, size_t count)
{
    struct trackedsocket *t = Socket+fd;
    ssize_t wr;
    if (!t->domain)
    {
        /* not tracked, pass it through */
        wr = syscall(SYS_write, fd, buf, count);
    } else {
        unsigned char *ptr;
        (void)ratelim_put(&t->wr, buf, count);
        wr = ratelim_get(&t->wr, &ptr, count);
        if (wr)
        {
            /* if local cache is empty, do actual call... */
            wr = syscall(SYS_write, fd, ptr, wr);
            if (wr >= 0) /* success */
            {
                if (wr > 0)
                {
                }
            }
        }
    }
    return wr;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    printf("    >> intercepted write(%d, %p, %zu)\n", fd, buf, count);
    return do_write(fd, buf, count);
}

int close(int fd)
{
    printf("    >> intercepted close(%d)\n", fd);
    if (Socket[fd].domain)
    {
        printf("        >> it's a socket\n");
        trackedsocket_destroy(fd);
    }
    return syscall(SYS_close, fd);
}

