#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "basic_defs.h"
#include "util.h"
#include "netasync.h"
#include "poll.h"

#define LGPFX "ANET:"

static bool verbose = 0;

static void netasync_receive_cb(void *clientData);
static void netasync_send_ready_cb(void *clientData);

#define CTX_MAGIC       0xcafebabe
#define SOCK_MAGIC      0xdeadbeef

struct netasync_send_ctx {
   uint64                    magic;
   const void               *buf_orig;
   const void               *buf;
   size_t                    len;
   netasync_callback        *callback;
   void                     *clientData;
   struct netasync_send_ctx *next;
};


struct netasync_socket {
   uint64                     magic;
   int                        fd;
   int                        err;
   char                      *hostname;

   netasync_callback         *connectCb;
   void                      *connectCbData;
   time_t                     connectTS;
   bool                       connect_timeout;
   bool                       connect_async;

   netasync_callback         *errorCb;
   void                      *errorCbData;

   uint8                     *recvBuf;
   size_t                     recvBufLen;
   size_t                     recvBufIdx;
   netasync_recv_callback    *recvCb;
   void                      *recvCbData;
   bool                       recvPartial;

   struct netasync_send_ctx  *sendCtxList;
   struct netasync_send_ctx **sendCtxTail;
};


static struct {
   struct poll_loop *poll;
   uint64            received;
   uint64            sent;
   uint32            sockets;
} netasync;


static void netasync_connected(void *clientData);
static void netasync_connect_timeout_cb(void *clientData);


/*
 *-------------------------------------------------------------------------
 *
 * netasync_exit --
 *
 *-------------------------------------------------------------------------
 */

void
netasync_exit(void)
{
   char *s0 = print_size(netasync.received);
   char *s1 = print_size(netasync.sent);

   if (netasync.sockets > 0) {
      Log(LGPFX" %u socks -- %llu / %s received -- %llu / %s sent.\n",
          netasync.sockets, netasync.received, s0, netasync.sent, s1);
   }
   free(s0);
   free(s1);
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_get_connect_ts --
 *
 *-------------------------------------------------------------------------
 */

time_t
netasync_get_connect_ts(const struct netasync_socket *sock)
{
   return sock->connectTS;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_init --
 *
 *-------------------------------------------------------------------------
 */

void
netasync_init(struct poll_loop *poll)
{
   netasync.poll     = poll;
   netasync.received = 0;
   netasync.sent     = 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_timeout_stop --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_timeout_stop(struct netasync_socket *sock)
{
   bool s;

   ASSERT(sock->connect_timeout);

   s = poll_callback_time_remove(netasync.poll, 0 /* !permanent */,
                                 netasync_connect_timeout_cb, sock);
   ASSERT(s);
   sock->connect_timeout = 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_connect_stop --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_connect_stop(struct netasync_socket *sock)
{
   bool s;

   LOG(2, (LGPFX" stop connect on %p -- %s\n", sock, sock->hostname));

   s = poll_callback_device_remove(netasync.poll, sock->fd,
                                   0,  /* read */
                                   1,  /* write */
                                   0,  /* permanent */
                                   netasync_connected, sock);
   ASSERT(s);
   sock->connect_async = 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_send_stop --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_send_stop(struct netasync_socket *sock)
{
   LOG(2, (LGPFX" stop send on %p -- %s\n", sock, sock->hostname));

   poll_callback_device_remove(netasync.poll, sock->fd,
                               0,  /* read */
                               1,  /* write */
                               0,  /* permanent */
                               netasync_send_ready_cb, sock);
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_receive_stop --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_receive_stop(struct netasync_socket *sock)
{
   LOG(2, (LGPFX" stop receiving on %p -- %s\n", sock, sock->hostname));

   poll_callback_device_remove(netasync.poll, sock->fd,
                               1 /* read */,
                               0 /* write */,
                               1 /* permanent */,
                               netasync_receive_cb, sock);
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_receive_reset --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_receive_reset(struct netasync_socket *sock)
{
   sock->recvBuf     = NULL;
   sock->recvBufLen  = 0;
   sock->recvBufIdx  = 0;
   sock->recvCb      = NULL;
   sock->recvCbData  = 0;
   sock->recvPartial = 0; // XXX
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_addr2str --
 *
 *-------------------------------------------------------------------------
 */

char *
netasync_addr2str(const struct sockaddr_in *addr)
{
   uint32 ip = ntohl(addr->sin_addr.s_addr);

   return safe_asprintf("%u.%u.%u.%u",
                        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                        (ip >> 8) & 0xFF, ip & 0xFF);
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_create --
 *
 *-------------------------------------------------------------------------
 */

struct netasync_socket *
netasync_create(void)
{
   struct netasync_socket *sock;

   sock = calloc(1, sizeof *sock);
   if (sock == NULL) {
      return NULL;
   }

   sock->sendCtxTail = &sock->sendCtxList;
   sock->magic       = SOCK_MAGIC;
   sock->fd          = -1;

   netasync.sockets++;

   return sock;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_hostname --
 *
 *-------------------------------------------------------------------------
 */

const char *
netasync_hostname(const struct netasync_socket *sock)
{
   ASSERT(sock->hostname);
   return sock->hostname;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_getsocket_errno --
 *
 *-------------------------------------------------------------------------
 */

static int
netasync_getsocket_errno(const struct netasync_socket *sock)
{
   socklen_t len;
   int err = 0;
   int res;

   ASSERT(sock->fd > 0);

   len = sizeof err;

   res = getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &len);
   if (res < 0 || err != 0) {
      Log(LGPFX" socket status: failure: %s (%d)\n", strerror(err), err);
   }
   return err;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_connected --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_connected(void *clientData)
{
   struct netasync_socket *sock = clientData;

   ASSERT(sock->magic == SOCK_MAGIC);

   LOG(1, (LGPFX" %s -- %s: fd=%d err = %d\n", __FUNCTION__, sock->hostname,
           sock->fd, sock->err));

   sock->connect_async = 0;

   if (sock->connect_timeout) {
      netasync_timeout_stop(sock);
   }

   if (sock->err == 0) {
      char *latStr;
      time_t lat;

      sock->err = netasync_getsocket_errno(sock);
      lat = time_get() - sock->connectTS;
      latStr = print_latency(lat);

      if (sock->err != 0) {
         Log(LGPFX" failed to connect fd=%d to %s (%s) - %s (%d)\n",
                 sock->fd, sock->hostname, latStr,
                 strerror(sock->err), sock->err);
      } else {
         Log(LGPFX" connected to %s fd=%d (%s)\n",
             sock->hostname, sock->fd, latStr);
      }
      free(latStr);
   }

   if (sock->connectCb) {
      sock->connectCb(sock, sock->connectCbData, sock->err);
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_resolve --
 *
 *-------------------------------------------------------------------------
 */

int
netasync_resolve(const char *hostname,
                 uint16 port,
                 struct sockaddr_in *addr)
{
   struct addrinfo hints;
   struct addrinfo *addrs;
   struct addrinfo *iter;
   char service[10];
   int err;

   LOG(1, (LGPFX" %s host='%s' port=%u\n", __FUNCTION__, hostname, port));

   snprintf(service, sizeof service, "%u", port);

   memset(&hints, 0, sizeof hints);
   hints.ai_family   = AF_INET;
   hints.ai_socktype = SOCK_STREAM; /* only */

   err = getaddrinfo(hostname, service, &hints, &addrs);
   if (err != 0) {
      Log(LGPFX" Failed to resolve %s:%d : %s (%d)\n",
          hostname, port, gai_strerror(err), err);
      return err;
   }
   for (iter = addrs; iter != NULL; iter = iter->ai_next) {
      if (iter->ai_family == AF_INET) {
         memcpy(addr, iter->ai_addr, sizeof *addr);
         break;
      }
   }
   freeaddrinfo(addrs);

   return 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_set_socket_options --
 *
 *-------------------------------------------------------------------------
 */

static int
netasync_socket_nonblock(const struct netasync_socket *sock)
{
   int flags;
   int res;

   flags = fcntl(sock->fd, F_GETFL, 0);
   if (flags < 0) {
      return flags;
   }

   res = fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK);
   if (res < 0) {
      return res;
   }

   res = 1;

   return setsockopt(sock->fd, SOL_SOCKET, SO_KEEPALIVE, &res, sizeof res);
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_connect_timeout_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_connect_timeout_cb(void *clientData)
{
   struct netasync_socket *sock = (struct netasync_socket *)clientData;

   LOG(1, (LGPFX" connect-timeout on fd=%d -- %s\n", sock->fd, sock->hostname));

   ASSERT(sock->magic == SOCK_MAGIC);
   ASSERT(sock->connect_timeout);
   ASSERT(sock->connect_async);

   sock->connect_timeout = 0;
   sock->err = ETIMEDOUT;

   netasync_connect_stop(sock);
   netasync_connected(sock);
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_connect --
 *
 *-------------------------------------------------------------------------
 */

int
netasync_connect(struct netasync_socket *sock,
                 const struct sockaddr_in *addr,
                 int timeout_sec,
                 netasync_callback *cb,
                 void *clientData)
{
   int res;

   sock->hostname        = netasync_addr2str(addr);
   sock->connectCb       = cb;
   sock->connectCbData   = clientData;
   sock->connectTS       = time_get();
   sock->connect_timeout = 0;
   sock->connect_async   = 0;
   ASSERT(sock->fd < 0);

   LOG(1, (LGPFX" %s: Connecting to %s\n", __FUNCTION__, sock->hostname));

   sock->fd = socket(AF_INET, SOCK_STREAM, 0);
   if (sock->fd < 0) {
      sock->err = errno;
      if (sock->err == EMFILE || sock->err == ENFILE) {
         Warning(LGPFX" Failed to create socket: EMNFILE: not more fd available.\n");
         Panic("EMNFILE.\n");
      } else {
         Log(LGPFX" Failed to create socket: %s (%u)\n",
             strerror(sock->err), sock->err);
      }
      goto exit;
   }

   sock->err = netasync_socket_nonblock(sock);
   if (sock->err) {
      goto exit;
   }

   res = connect(sock->fd, (struct sockaddr *)addr, sizeof *addr);
   if (res == 0) {
      goto exit;
   }
   if (!cb || errno != EINPROGRESS) {
      sock->err = errno;
      Log(LGPFX" Failed to connect: %s (%d)\n", strerror(sock->err), sock->err);
      goto exit;
   }

   if (timeout_sec > 0) {
      sock->connect_timeout = 1;
      poll_callback_time(netasync.poll, timeout_sec * 1000 * 1000ULL,
                         0 /* !permanent */,
                         netasync_connect_timeout_cb, sock);
   }

   sock->connect_async = 1;
   poll_callback_device(netasync.poll, sock->fd,
                        0, /* read */
                        1, /* writable */
                        0, /* !permanent => one shot */
                        netasync_connected, sock);

   return 0;

exit:

   res = cb ? 0 : sock->err;
   netasync_connected(sock);
   /*
    * Do not use 'sock' here.
    */
   return res;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_fire_errorhandler --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_fire_errorhandler(struct netasync_socket *sock)
{
   ASSERT(sock);
   ASSERT(sock->errorCb);

   sock->errorCb(sock, sock->errorCbData, sock->err);
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_set_errorhandler --
 *
 *-------------------------------------------------------------------------
 */

void
netasync_set_errorhandler(struct netasync_socket *sock,
                          netasync_callback *callback,
                          void *clientData)
{
   ASSERT(sock);

   sock->errorCb     = callback;
   sock->errorCbData = clientData;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_receive_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_receive_cb(void *clientData)
{
   struct netasync_socket *sock = clientData;
   size_t numRead = 0;

   ASSERT(sock->magic == SOCK_MAGIC);
   ASSERT(sock->recvBuf);

   while (TRUE) {
      size_t numBytesToRead = sock->recvBufLen - sock->recvBufIdx;
      ssize_t len;

      len = read(sock->fd, sock->recvBuf + sock->recvBufIdx, numBytesToRead);
      if (len < 0) {
         int res = errno;
         if (res == EAGAIN) {
            break;
         }
         sock->err = res;
         Log(LGPFX" %s: failed to read: %s (%d) -- numRead=%zu\n",
             sock->hostname, strerror(res), res, numRead);
         netasync_fire_errorhandler(sock);
         return;
      }
      if (len == 0) {
         int err = netasync_getsocket_errno(sock);
         Log(LGPFX" %s: socket closed by peer: %s (%d)\n",
             sock->hostname, strerror(err), err);
         netasync_fire_errorhandler(sock);
         return;
      }
      sock->recvBufIdx  += len;
      numRead           += len;
      netasync.received += len;
      if (sock->recvBufIdx == sock->recvBufLen) {
         break;
      }
   }
   LOG(1, (LGPFX" %s: numRead=%zu (idx=%zu vs len=%zu)\n",
       __FUNCTION__, numRead, sock->recvBufIdx, sock->recvBufLen));

   ASSERT(sock->recvPartial == 0);

   if (sock->recvBufIdx == sock->recvBufLen) {
      netasync_recv_callback *recvCb = sock->recvCb;
      void *recvCbData = sock->recvCbData;
      void *buf = sock->recvBuf + sock->recvBufIdx - numRead;

      netasync_receive_stop(sock);
      netasync_receive_reset(sock);

      recvCb(sock, buf, numRead, recvCbData);
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_receive --
 *
 *-------------------------------------------------------------------------
 */

int
netasync_receive(struct netasync_socket *sock,
                 void *buf,
                 size_t len,
                 bool partial,
                 netasync_recv_callback *cb,
                 void *clientData)
{
   ASSERT(sock->magic == SOCK_MAGIC);

   LOG(1, (LGPFX" Receiving on s=%p fd=%d -- buf %p:%zu\n",
       sock, sock->fd, buf, len));

   ASSERT(sock->recvBuf == NULL);
   ASSERT(sock->recvBufLen == 0);
   ASSERT(buf);
   ASSERT(len > 0);

   sock->recvBuf     = buf;
   sock->recvBufLen  = len;
   sock->recvBufIdx  = 0;
   sock->recvCb      = cb;
   sock->recvCbData  = clientData;
   sock->recvPartial = partial;

   poll_callback_device(netasync.poll, sock->fd,
                        1,  /* read */
                        0,  /* !write */
                        1,  /* permanent */
                        netasync_receive_cb, sock);
   return 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_send_ctx --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_send_ctx(struct netasync_socket   *sock,
                  struct netasync_send_ctx *ctx)
{
   ssize_t res;

   ASSERT(sock->magic == SOCK_MAGIC);
   ASSERT(ctx);
   ASSERT(sock->err == 0);

   static int count;
   count++;
   if ((count % 37) == 0) {
      NOT_TESTED_ONCE();
      res = 0;
      goto next;
   }

   res = write(sock->fd, ctx->buf, ctx->len);
   if (res == -1 && errno == EAGAIN) {
      NOT_TESTED_ONCE();
      res = 0;
   }
next:
   if (res < 0) {
      sock->err = errno;
      Warning(LGPFX" %s: write(2) failed: %s (%d).\n",
              sock->hostname, strerror(sock->err), sock->err);
      print_backtrace();
      ASSERT(sock->err != EBADF);
      netasync_fire_errorhandler(sock);
      return;
   } else {
      ctx->buf = (uint8*)ctx->buf + res;
      ctx->len -= res;
      netasync.sent += res;
   }

   if (ctx->len == 0 || sock->err != 0) {
      netasync_callback *callback   = ctx->callback;
      void              *clientData = ctx->clientData;

      ASSERT(ctx->callback);

      sock->sendCtxList = ctx->next;
      ctx->magic = -1;
      free((void*)ctx->buf_orig);
      free(ctx);
      if (sock->sendCtxList == NULL) {
         sock->sendCtxTail = &sock->sendCtxList;
      }

      ctx = sock->sendCtxList;
      callback(sock, clientData, sock->err);
   }

   ASSERT(sock->err == 0);
   if (ctx) {
      ASSERT(ctx->magic == CTX_MAGIC);
      poll_callback_device(netasync.poll, sock->fd,
                           0,  /* read */
                           1,  /* write */
                           0,  /* permanent */
                           netasync_send_ready_cb, sock);
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_send_ready_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
netasync_send_ready_cb(void *clientData)
{
   struct netasync_socket *sock = (struct netasync_socket*) clientData;

   ASSERT(sock->sendCtxList->magic == CTX_MAGIC);
   ASSERT(sock->magic == SOCK_MAGIC);

   netasync_send_ctx(sock, sock->sendCtxList);
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_create --
 *
 *-------------------------------------------------------------------------
 */

int
netasync_send(struct netasync_socket *sock,
              const void *buf,
              size_t len,
              netasync_callback *callback,
              void *clientData)
{
   struct netasync_send_ctx *ctx;
   bool newSend;

   ASSERT(sock);
   ASSERT(sock->connect_async == 0);
   ASSERT(sock->magic == SOCK_MAGIC);
   ASSERT(sock->err == 0);

   LOG(1, (LGPFX" %s: sending on %p:%d -- buf %p:%zu\n",
           sock->hostname, sock, sock->fd, buf, len));

   ctx = safe_malloc(sizeof *ctx);
   ctx->magic      = CTX_MAGIC;
   ctx->buf_orig   = buf;
   ctx->buf        = buf;
   ctx->len        = len;
   ctx->clientData = clientData;
   ctx->callback   = callback;
   ctx->next       = NULL;

   ASSERT(sock->sendCtxTail);

   newSend = sock->sendCtxList == NULL;

   *sock->sendCtxTail = ctx;
   sock->sendCtxTail = &ctx->next;

   if (newSend) {
      /*
       * Yeah, not exactly ideal, but this avoids having to implement some sort
       * of ref-counting scheme so that'll have to do for now.
       */
      //netasync_send_ctx(sock, ctx);
      poll_callback_device(netasync.poll, sock->fd,
                           0,  /* read */
                           1,  /* write */
                           0,  /* permanent */
                           netasync_send_ready_cb, sock);
   }

   return sock->err;
}


/*
 *-------------------------------------------------------------------------
 *
 * netasync_close --
 *
 *-------------------------------------------------------------------------
 */

void
netasync_close(struct netasync_socket *sock)
{
   ASSERT(sock->magic == SOCK_MAGIC);

   if (sock->fd > 0) {
      LOG(1, (LGPFX" closing socket %p: %s @ fd=%d\n",
              sock, sock->hostname,  sock->fd));
   } else {
      LOG(1, (LGPFX" destroying socket %p (%s).\n", sock, sock->hostname));
   }

   if (sock == NULL) {
      return;
   }

   if (sock->sendCtxList) {
      struct netasync_send_ctx *ctx = sock->sendCtxList;

      while (ctx) {
         struct netasync_send_ctx *next = ctx->next;

         free((void*)ctx->buf_orig);
         memset(ctx, 0xff, sizeof *ctx);
         free(ctx);
         ctx = next;
      }

      netasync_send_stop(sock);
   }
   if (sock->connect_timeout) {
      netasync_timeout_stop(sock);
   }
   if (sock->connect_async) {
      netasync_connect_stop(sock);
   }
   if (sock->recvCb) {
      netasync_receive_stop(sock);
      netasync_receive_reset(sock);
   }
   if (sock->fd > 0) {
      close(sock->fd);
      sock->fd = -1;
   }
   free(sock->hostname);
   memset(sock, 0xff, sizeof *sock);
   free(sock);
}
