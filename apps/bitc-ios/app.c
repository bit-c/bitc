#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include "basic_defs.h"

#include "block-store.h"
#include "peergroup.h"
#include "util.h"
#include "wallet.h"
#include "config.h"
#include "poll.h"
#include "netasync.h"
#include "key.h"
#include "addrbook.h"
#include "file.h"
#include "bitc.h"
#include "base58.h"
#include "rpc.h"
#include "bitc_ui.h"

#include "TargetConditionals.h"


#define LGPFX "BITC:"


enum btc_req_type {
   BTC_REQ_STOP,
   BTC_REQ_TX,
};

struct btc_req {
   struct circlist_item  item;
   enum btc_req_type     type;
   void                 *clientData;
};

static void bitc_sigint_handler(int sig);

static struct BITCApp theBitcApp;
struct BITCApp *btc = &theBitcApp;
bool bitc_testing = 0;

static char *basePath = NULL;


/*
 *---------------------------------------------------------------------
 *
 * bitc_signal_handler --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_signal_handler(int sig)
{
   Panic("Unexpected signal %u received.\n", sig);
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_signal_install --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_signal_install(void)
{
   signal(SIGINT, bitc_sigint_handler);

   signal(SIGSEGV, bitc_signal_handler);
   signal(SIGBUS,  bitc_signal_handler);
   signal(SIGILL,  bitc_signal_handler);

   signal(SIGPIPE, SIG_IGN);
   signal(SIGHUP,  SIG_IGN);
}


/*
 *----------------------------------------------------------------
 *
 * bitc_req_notify --
 *
 *----------------------------------------------------------------
 */

static void
bitc_req_notify(void)
{
   uint8 val = 1;
   ssize_t res;

   res = write(btc->notifyFd, &val, sizeof val);
   ASSERT(res == 1);
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_sigint_handler --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_sigint_handler(int sig)
{
   if (sig == SIGINT) {
      Warning("CTRL-C received. Exiting..\n");
   } else {
      Warning("Signal %u received. Exiting..\n", sig);
   }
   btc->stop = 2;
   bitc_req_notify();
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_openssl_lock_fun --
 *
 *---------------------------------------------------------------------
 */

static pthread_mutex_t *ssl_mutex_array;

static void
bitc_openssl_lock_fun(int mode,
                      int n,
                      const char *file,
                      int line)
{
   pthread_mutex_t *lock = &ssl_mutex_array[n];

   if (mode & CRYPTO_LOCK) {
      pthread_mutex_lock(lock);
   } else {
      pthread_mutex_unlock(lock);
   }
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_openssl_thread_id_fun --
 *
 *---------------------------------------------------------------------
 */

static unsigned long
bitc_openssl_thread_id_fun(void)
{
   return (unsigned long)pthread_self();
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_openssl_init --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_openssl_init(void)
{
   const char *sslVersion = SSLeay_version(SSLEAY_VERSION);
   int i;

   Log(LGPFX" using %s -- %u locks\n", sslVersion, CRYPTO_num_locks());

   SSL_library_init();
   ssl_mutex_array = OPENSSL_malloc(CRYPTO_num_locks() *
                                    sizeof *ssl_mutex_array);
   ASSERT(ssl_mutex_array);

   for (i = 0; i < CRYPTO_num_locks(); i++ ){
      pthread_mutex_init(&ssl_mutex_array[i], NULL);
   }
   CRYPTO_set_id_callback(bitc_openssl_thread_id_fun);
   CRYPTO_set_locking_callback(bitc_openssl_lock_fun);
}


/*
 *------------------------------------------------------------------------
 *
 * bitc_openssl_exit --
 *
 *------------------------------------------------------------------------
 */
#if 0
static void
bitc_openssl_exit(void)
{
   int i;

   CRYPTO_set_id_callback(NULL);
   CRYPTO_set_locking_callback(NULL);
   for (i = 0; i < CRYPTO_num_locks(); i++) {
      pthread_mutex_destroy(&ssl_mutex_array[i]);
   }
   OPENSSL_free(ssl_mutex_array);
}
#endif


/*
 *------------------------------------------------------------------------
 *
 * bitc_check_create_file --
 *
 *------------------------------------------------------------------------
 */

static int
bitc_check_create_file(const char *filename,
                       const char *label)
{
   int res;

   if (file_exists(filename)) {
      return 0;
   }

   Log(LGPFX" creating %s file: %s\n", label, filename);
   res = file_create(filename);
   if (res) {
      printf("Failed to create %s file '%s': %s\n",
             label, filename, strerror(res));
      return res;
   }
   res = file_chmod(filename, 0600);
   if (res) {
      printf("Failed to chmod 0600 %s file '%s': %s\n",
             label, filename, strerror(res));
   }
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * bitc_get_directory --
 *
 *------------------------------------------------------------------------
 */

char *
bitc_get_directory(void)
{
   ASSERT(basePath);

   return safe_asprintf("%s/Library", basePath);
}


/*
 *------------------------------------------------------------------------
 *
 * bitc_check_config --
 *
 *------------------------------------------------------------------------
 */

static int
bitc_check_config(void)
{
   char *cfgPath;
   char *ctcPath;
   char *txPath;
   char *dir;
   int res = 0;

   dir = bitc_get_directory();
   cfgPath = safe_asprintf("%s/main.cfg",      dir);
   ctcPath = safe_asprintf("%s/contacts.cfg",  dir);
   txPath  = safe_asprintf("%s/tx-labels.cfg", dir);

   if (!file_exists(dir) || !file_exists(cfgPath)) {
      printf("\nIt looks like you're a new user. Welcome!\n"
             "\n"
             "Note that bitc uses the directory: ~/.bitc to store:\n"
             " - block headers:        ~/.bitc/headers.dat     -- ~ 20 MB\n"
             " - peer IP addresses:    ~/.bitc/peers.dat       --  ~ 2 MB\n"
             " - transaction database: ~/.bitc/txdb            --  < 1 MB\n"
             " - wallet keys:          ~/.bitc/wallet.cfg      --  < 1 KB\n"
             " - main config file:     ~/.bitc/main.cfg        --  < 1 KB\n"
             " - a contacts file:      ~/.bitc/contacts.cfg    --  < 1 KB\n"
             " - a tx-label file:      ~/.bitc/tx-labels.cfg   --  < 1 KB\n\n");
   }

   if (!file_exists(dir)) {
      Log(LGPFX" creating directory: %s\n", dir);
      res = file_mkdir(dir);
      if (res) {
         printf("Failed to create directory '%s': %s\n",
                dir, strerror(res));
         goto exit;
      }
      res = file_chmod(dir, 0700);
      if (res) {
         printf("Failed to chmod 0600 directory '%s': %s\n",
                dir, strerror(res));
         goto exit;
      }
   }
   bitc_check_create_file(cfgPath, "config");
   bitc_check_create_file(txPath, "tx-labels");

   if (!file_exists(ctcPath)) {
      struct config *cfg;

      bitc_check_create_file(ctcPath, "contacts");

      cfg = config_create();
      config_setstring(cfg, "1PBP4S44b1ro3kD6LQhBYnsF3fAp1HYPf2", "contact0.addr");
      config_setstring(cfg, "Support bitc development -- https://bit-c.github.com",
                       "contact0.label");

      config_setstring(cfg, "1PC9aZC4hNX2rmmrt7uHTfYAS3hRbph4UN", "contact1.addr");
      config_setstring(cfg, "Free Software Foundation -- https://fsf.org/donate/",
                       "contact1.label");
      config_setstring(cfg, "1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW", "contact2.addr");
      config_setstring(cfg, "Bitcoin Foundation -- https://bitcoinfoundation.org/donate",
                       "contact2.label");

      config_setstring(cfg, "3", "contacts.numEntries");

      res = config_write(cfg, ctcPath);
      if (res) {
         printf("Failed to save contacts file: %s\n", strerror(res));
      }
   }

exit:
   free(txPath);
   free(cfgPath);
   free(ctcPath);
   free(dir);

   return res;
}


/*
 *----------------------------------------------------------------
 *
 * bitc_load_misc_config --
 *
 *----------------------------------------------------------------
 */

static void
bitc_load_misc_config(void)
{
   char *defaultPath;
   char *dir;
   char *path;
   int res;

   btc->resolve_peers = config_getbool(btc->config, 1, "resolve.peers");

   dir = bitc_get_directory();

   /*
    * contacts.
    */
   defaultPath = safe_asprintf("%s/contacts.cfg", dir);
   path = config_getstring(btc->config, defaultPath, "contacts.filename");
   res = config_load(path, &btc->contactsCfg);
   if (res) {
      Warning("Please create a minimal config: %s\n", path);
   }
   free(defaultPath);
   free(path);

   /*
    * tx-label.
    */
   defaultPath = safe_asprintf("%s/tx-labels.cfg", dir);
   path = config_getstring(btc->config, defaultPath, "tx-labels.filename");
   res = config_load(path, &btc->txLabelsCfg);
   if (res) {
      Warning("Please create a minimal config: %s\n", path);
   }
   free(defaultPath);
   free(path);

   free(dir);
}


/*
 *----------------------------------------------------------------
 *
 * bitc_load_config --
 *
 *----------------------------------------------------------------
 */

static int
bitc_load_config(struct config **config,
                 const char     *configPath)
{
   char *defaultPath = NULL;
   const char *path;
   int res;

   if (configPath == NULL) {
      char *dir = bitc_get_directory();
      defaultPath = safe_asprintf("%s/main.cfg", dir);
      free(dir);
      path = defaultPath;
   } else {
      path = configPath;
   }
   res = config_load(path, config);
   if (res) {
      Warning("Please create a minimal config: %s\n", path);
   }
   free(defaultPath);
   return res;
}


/*
 *----------------------------------------------------------------
 *
 * bitc_poll_exit --
 *
 *----------------------------------------------------------------
 */

static void
bitc_poll_exit(void)
{
   poll_destroy(btc->poll);
   btc->poll = NULL;
}


/*
 *----------------------------------------------------------------
 *
 * bitc_poll_init --
 *
 *----------------------------------------------------------------
 */

static void
bitc_poll_init(void)
{
   btc->poll = poll_create();
}


/*
 *----------------------------------------------------------------
 *
 * bitc_req_enqueue --
 *
 *----------------------------------------------------------------
 */

static void
bitc_req_enqueue(struct btc_req *req)
{
   ASSERT(req);
   ASSERT(btc->lock);

   mutex_lock(btc->lock);
   circlist_queue_item(&btc->reqList, &req->item);
   mutex_unlock(btc->lock);

   bitc_req_notify();
}


/*
 *----------------------------------------------------------------
 *
 * bitc_req_alloc --
 *
 *----------------------------------------------------------------
 */

static struct btc_req *
bitc_req_alloc(enum btc_req_type type)
{
   struct btc_req*req;

   req = safe_malloc(sizeof *req);
   circlist_init_item(&req->item);
   req->clientData = NULL;
   req->type       = type;

   return req;
}


/*
 *----------------------------------------------------------------
 *
 * bitc_req_tx --
 *
 *----------------------------------------------------------------
 */

void
bitc_req_tx(struct btc_tx_desc *tx)
{
   struct btc_req *req;

   Log(LGPFX" requesting tx: %.8f BTC to %s.\n",
       tx->total_value / ONE_BTC, tx->dst[0].addr);
   req = bitc_req_alloc(BTC_REQ_TX);
   req->clientData = tx;
   bitc_req_enqueue(req);
}


/*
 *----------------------------------------------------------------
 *
 * bitc_req_stop --
 *
 *----------------------------------------------------------------
 */

void
bitc_req_stop(void)
{
   struct btc_req *req;

   Log(LGPFX" requesting exit.\n");
   /*
    * A bit of a hack. Let's set 'btc->stop' from the UI possibly, that way
    * lengthy functions can check this value if they need to abort their
    * processing. Cf blockstore_load_etc.
    */
   btc->stop = 1;
   req = bitc_req_alloc(BTC_REQ_STOP);
   bitc_req_enqueue(req);
}


/*
 *----------------------------------------------------------------
 *
 * bitc_transmit_tx --
 *
 *----------------------------------------------------------------
 */

static void
bitc_transmit_tx(struct btc_tx_desc *tx_desc)
{
   struct btc_msg_tx tx;
   int res;

   ASSERT(tx_desc);
   btc_msg_tx_init(&tx);

   Log(LGPFX" sending %.8f BTC to %s\n",
       tx_desc->total_value / ONE_BTC, tx_desc->dst[0].addr);

   if (tx_desc->fee == -1) {
      tx_desc->fee = config_getint64(btc->config, 10000, "wallet.fee");
   }

   /*
    * Let's prevent stupid mistakes.
    */
   ASSERT(tx_desc->fee <= 100000);

   res = wallet_craft_tx(btc->wallet, tx_desc, &tx);
   if (res) {
      bitcui_set_status("TX failed: insufficient funds");
   }

   btc_msg_tx_free(&tx);
}


/*
 *----------------------------------------------------------------
 *
 * bitc_process_events --
 *
 *----------------------------------------------------------------
 */

static void
bitc_process_events(void)
{
   /*
    * If we got a CTRL-C, btc->stop is set to 2. We transition automatically to
    * BITC_STATE_EXITING.
    */
   if (btc->stop == 2) {
      Log(LGPFX" %s -- BITC_STATE_EXITING (CTRL-C)\n", __FUNCTION__);
      btc->state = BITC_STATE_EXITING;
   }

   while (!circlist_empty(btc->reqList)) {
      struct circlist_item *li = btc->reqList;
      struct btc_req *req;

      req = CIRCLIST_CONTAINER(li, struct btc_req, item);
      circlist_delete_item(&btc->reqList, li);
      Log(LGPFX" handling msg %d\n", req->type);

      switch (req->type) {
      case BTC_REQ_STOP:
         Log(LGPFX" %s -- BITC_STATE_EXITING.\n", __FUNCTION__);
         btc->stop = 1;
         btc->state = BITC_STATE_EXITING;
         break;
      case BTC_REQ_TX:
         Log(LGPFX" %s -- initiating tx.\n", __FUNCTION__);
         struct btc_tx_desc *tx_desc = req->clientData;
         bitc_transmit_tx(tx_desc);
         free(tx_desc);
         break;
      default:
         Warning(LGPFX" unhandled btc msg %d\n", req->type);
         break;
      }

      free(req);
   }
}


/*
 *----------------------------------------------------------------
 *
 * bitc_req_cb --
 *
 *----------------------------------------------------------------
 */

static void
bitc_req_cb(void *clientData)
{
   ssize_t res;

   do {
      uint8 val;

      res = read(btc->eventFd, &val, sizeof val);
   } while (res > 0);

   ASSERT(res == 0 || errno == EAGAIN);

   mutex_lock(btc->lock);
   bitc_process_events();
   mutex_unlock(btc->lock);
}


/*
 *----------------------------------------------------------------
 *
 * bitc_req_exit --
 *
 *----------------------------------------------------------------
 */

static void
bitc_req_exit(void)
{
   bool s;

   if (btc->notifyInit == 0) {
      return;
   }

   s = poll_callback_device_remove(btc->poll, btc->eventFd, 1, 0, 1,
                                   bitc_req_cb, NULL);
   ASSERT(s);

   close(btc->eventFd);
   close(btc->notifyFd);

   btc->eventFd = -1;
   btc->notifyFd = -1;
}


/*
 *----------------------------------------------------------------
 *
 * bitc_req_init --
 *
 *----------------------------------------------------------------
 */

static int
bitc_req_init(void)
{
   int fd[2];
   int flags;
   int res;

   res = pipe(fd);
   if (res != 0) {
      res = errno;
      Log(LGPFX" Failed to create pipe: %s\n", strerror(res));
      return res;
   }
   btc->eventFd  = fd[0];
   btc->notifyFd = fd[1];

   flags = fcntl(btc->eventFd, F_GETFL, 0);
   if (flags < 0) {
      NOT_TESTED();
      return flags;
   }

   res = fcntl(btc->eventFd, F_SETFL, flags | O_NONBLOCK);
   if (res < 0) {
      NOT_TESTED();
      return res;
   }
   poll_callback_device(btc->poll, btc->eventFd, 1, 0, 1, bitc_req_cb, NULL);
   btc->notifyInit = 1;

   return 0;
}


/*
 *----------------------------------------------------------------
 *
 * bitc_init --
 *
 *----------------------------------------------------------------
 */

static int
bitc_init(struct secure_area *passphrase,
          bool                updateAndExit,
          int                 maxPeers,
          int                 minPeersInit,
          char              **errStr)
{
   int res;

   Log(LGPFX" %s -- BITC_STATE_STARTING.\n", __FUNCTION__);
   btc->state = BITC_STATE_STARTING;
   btc->wallet_state = WALLET_UNKNOWN;
   btc->updateAndExit = updateAndExit;

   bitcui_set_status("starting..");
   util_bumpnofds();
   bitc_poll_init();
   bitc_req_init();
   netasync_init(btc->poll);

   if (config_getbool(btc->config, FALSE, "network.useSocks5")) {
      btc->socks5_proxy = config_getstring(btc->config, "localhost", "socks5.hostname");
      btc->socks5_port  = config_getint64(btc->config,
#ifdef linux
                                          9050,
#else
                                          9150,
#endif
                                          "socks5.port");
      Log(LGPFX" Using SOCKS5 proxy %s:%u.\n",
          btc->socks5_proxy, btc->socks5_port);
   }

   bitcui_set_status("loading addrbook..");
   addrbook_open(btc->config, &btc->book);

   bitcui_set_status("opening blockstore..");
   res = blockstore_init(btc->config, &btc->blockStore);
   if (res) {
      *errStr = "Failed to open block-store.";
      return res;
   }

   peergroup_init(btc->config, maxPeers, minPeersInit, 15 * 1000 * 1000); // 15 sec

   bitcui_set_status("loading wallet..");
   res = wallet_open(btc->config, passphrase, errStr, &btc->wallet);
   if (res != 0) {
      return res;
   }

   bitcui_set_status("adding peers..");
   peergroup_seed();

   return rpc_init();
}


/*
 *----------------------------------------------------------------
 *
 * bitc_exit --
 *
 *----------------------------------------------------------------
 */

void
bitc_exit(void)
{
   Log(LGPFX" %s\n", __FUNCTION__);
   rpc_exit();
   peergroup_exit(btc->peerGroup);
   btc->peerGroup = NULL;
   addrbook_close(btc->book);
   btc->book = NULL;
   wallet_close(btc->wallet);
   btc->wallet = NULL;
   blockstore_exit(btc->blockStore);
   btc->blockStore = NULL;
   bitc_req_exit();
   netasync_exit();
   bitc_poll_exit();

   config_free(btc->txLabelsCfg);
   config_free(btc->contactsCfg);
   config_free(btc->config);
   free(btc->socks5_proxy);
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_daemon --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_daemon(bool updateAndExit,
            int maxPeers)
{
   Warning(LGPFX" daemon running.\n");
   bitcui_set_status("connecting to peers..");
   peergroup_refill(TRUE /* init */);

   while (btc->stop == 0) {
      poll_runloop(btc->poll, &btc->stop);
   }
   Warning(LGPFX" daemon stopped.\n");
}

static void *
bitc_daemon_thread(void *ptr)
{
   char *errStr = NULL;
   int res;

   res = bitc_init(NULL, FALSE /*updateAndExit*/, 5, 10, &errStr);
   if (res) {
      printf("failed to bitc_init\n");
      goto exit;
   }
   bitc_daemon(FALSE, 5);

exit:
   while (btc->stop == 0) {
      usleep(10);
   }
   printf("core thread gone\n");
   return NULL;
}

static void
bitc_daemonize(void)
{
   pthread_attr_t  attr;
   pthread_t th;

   pthread_attr_init(&attr);
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
   pthread_attr_setstacksize(&attr, 65536 * 128);

   pthread_create(&th, &attr, &bitc_daemon_thread, NULL);

   pthread_attr_destroy(&attr);
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_app_exit --
 *
 *---------------------------------------------------------------------
 */

void
bitc_app_exit(void)
{
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_app_init --
 *
 *---------------------------------------------------------------------
 */

int
bitc_app_init(const char *path)
{
   char *configPath = NULL;
   int res;

   basePath = safe_strdup(path);
   Log("path: '%s'\n", basePath);

   bitc_signal_install();
   Log_SetLevel(1);
   {
      char *login = safe_strdup("ios");
      char *logFile;
      logFile = safe_asprintf("%s/tmp/bitc-%s%s.log",
                              basePath,
                              login ? login : "foo",
                              btc->testnet ? "-testnet" : "");
      Log_Init(logFile);
      free(logFile);
      free(login);
   }
   util_bumpcoresize();
   bitc_check_config();

   res = bitc_load_config(&btc->config, configPath);
   if (res != 0) {
      return res;
   }
   bitc_load_misc_config();

#if 0
   if (bitc_check_wallet()) {
      return 1;
   }
#endif

   if (!wallet_verify(NULL, &btc->wallet_state)) {
      return 1;
   }

   btc->lock = mutex_alloc();
   btc->pw = NULL; //poolworker_create(10);
   bitc_openssl_init();

   btcui->inuse = 1;
   btcui->lock  = mutex_alloc();
   btcui->cv    = condvar_alloc();
   btcui->blockConsIdx = -1;
   btcui->blockProdIdx = -1;

   bitcui_init();
   condvar_signal(btcui->cv);

   bitc_daemonize();

   return 0;
}
