### KNOWN ISSUES
* if at the time the client is shutdown the current block is later orphaned,
  the next time we launch the app, the app will resync from the wallet's birth
  day. Need to resync the synchronization phase.

---

### CORE

#### features
* develop workflow and code for multisig,
* stealth address,
* coinjoin ability,
* BIP32 deterministic wallet,
* TOR support.

#### P0
* in case of chain re-org: make sure that only the tx on the 'best chain' are
  included in the calculation of the balance,
* improve the algorithm used to download filtered blocks: we currently use a
  sliding window that is very wasteful in that it doesn't benefit from the
  parallelism that multiple-peers can offer. We should instead identify all
  the block-hash that need to be fetched via (getdata + filtered), then proceed
  to ask each of our connected peers for a set of merkleblocks. Once we receive
  a block from a peer, we send another request until all the blocks have been
  handled.  Use a bitmap to keep track of blocks.
* keep track of how long a tx we initiated is outstanding and ABORT it after
  some time: make sure the coins it used are back to 'unspent' afterwards.
* implement daemon mode with hooks to send email/run script when a new payment
  is received/initiated.
* make it easy to import existing keys (i.e. no full rescan needed).
* make it easy to export existing keys: --export
* connect to testnet
* beef-up the regression suite
* misc synchronization issues: struct config accessed from both ui & main
  threads?
* add ability to sign/verify a text message.

#### P1
* better fee computation: right now, 0.0001 for everything.
    https://en.bitcoin.it/wiki/Transaction_fees
* refresh bloom filter used when it becomes too permissive,
* use a lock file: dummy file + pid written in it?
* implement init-table routine,
* populate addr in version msg,
* accept JSON-formatted arbitrary TX as input (sign & broadcast),

#### P2
* check & warn when running out of disk space,
* full chain client.

---

### WALLET

#### P0
* add ability to manage specific wallet (from command line option?)

#### P1
* add watch-only addresses,
* add possibility to display the available balance per address,
* add a wallet name,
* add ability to manage multiple wallet,
* handle cold wallets,
* offline transactions.
* somehow prune txos: only keep around unspent ones.

---

### UI

#### P0
* add a ncurses panel object that can be used to store and select arbitrary
   lines, use this to implement:
* panel block: ability to select block and display detailed info,
* panel tx: ability to select tx and display detailed info,
* panel contacts: show ascii qr code,

#### P1
* other UIs: Cocoa, Qt, Gtk?
* panel peers: average ping time
* add about dialog: version, contact info, web site, btc address,
* improve the color scheme: make it use the colors from the theme solarized:  
    http://ethanschoonover.com/solarized

#### P2
* add panel to display more stats: cmd counters, kb/sec, uptime, etc.
* panel contacts: display ASCII QR code for bitcoin address,
* panel wallet: add wallet name,
* add panel to chart BTC/USD,
* add getopt-style options to retrieve & dump a tx, block, header.
* use readline(3) to handle commands typed,
* add a way to hook commands/actions via the keyboard (cf kbdInputCB in
   ncui.c), use a vim-like syntax,

---

### MISC

* sign binaries,
* package as a .deb for debian/ubuntu,
* test on diverse platform: arm, big-endian ones, etc.
* translation.
