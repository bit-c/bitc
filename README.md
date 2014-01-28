### BITC

bitc is a *thin* SPV bitcoin client.
* 100% C code,
* support for linux and mac platforms,
* console based: uses ncurses,
* home grown async network i/o stack,
* home grown poll loop,
* home grown bitcoin engine,
* supports encrypted wallet,
* multi-threaded,
* valgrind clean.

**WARNING:** this app is under development and may contain critical bugs.

---

#### Screenshots

![dashboard](https://i.imgur.com/IJJU14s.png)

---

#### Dependencies

 - cJSON: a C library to parse JSON objects. It's released under MIT license.
        http://sourceforge.net/projects/cjson/
 - libcurl: an http library. It's released under a MIT/X derivate license.  
	http://curl.haxx.se/libcurl/
 - LevelDB: Google's key value store, released under the BSD 3-Clause License.  
	https://code.google.com/p/leveldb/
 - openSSL: crypto library.  
        https://www.openssl.org/

---

#### Install

##### Ubuntu 13.10, Saucy Salamander

You first need to install the libraries this app uses:
```
   # sudo apt-get install git make clang libssl-dev
   # sudo apt-get install libcurl4-openssl-dev libncurses5-dev
   # sudo apt-get install libleveldb-dev libsnappy-dev
   # sudo apt-get install libstdc++-4.8-dev
```

then clone the git repository:
```
   # git clone https://github.com/bit-c/bitc.git
```

finally build and launch:
```
   # cd bitc && make
   # ./bitc
```

##### Mac OS

  You need to install libcurl, leveldb, libsnappy and ncurses via `port` or `brew`.

---

#### Usage

The first time you launch the app, a message will notify you
of the list of files & directory it uses.

bitc uses the folder `~/.bitc` to store various items:

|    what              |    where                | avg size |
|:---------------------|:------------------------|:--------:|
| block headers        | ~/.bitc/headers.dat     | ~ 20MB   |
| peer IP addresses    | ~/.bitc/peers.dat       |  ~ 2MB   |
| transaction database | ~/.bitc/txdb            |  < 1MB   |
| config file          | ~/.bitc/main.cfg        |  < 1KB   |
| wallet keys          | ~/.bitc/wallet.cfg      |  < 1KB   |
| tx-label file        | ~/.bitc/tx-labels.cfg   |  < 1KB   |
| contacts file        | ~/.bitc/contacts.cfg    |  < 1KB   |


A log file is generated in `/tmp/bitc-$USER.log`.

To navigate the UI:
 - `<left>` and `<right>` allow you to change panel,
 - `<CTRL>` + T to initiate a transaction,
 - type `q` or `back quote` to exit.

---

#### Encrypted wallet

bitc has support for encrypted wallets. The first time you launch the app, it will
automatically generate a new bitcoin address for you, and the wallet file will
have private key **unencrypted**.

To turn on encryption, or to change the encryption password:
```
  # ./bitc -e
```

The next time you launch the app, you may or may not specify `-p` on
the command line. If you do, you will be able to initiate transactions. If you
do not the dashboard will still be functional but you won't be able to
initiate transactions.

Note that bitc encrypts each private key separately.

**WARNING:** please remember to make back-ups.

---

#### Importing existing keys

You need to modify your `~/.bitc/wallet.cfg` so that it contains the private
key as exported by `bitcoin-qt` with the command `dumpprivkey`. More on that
later.

---

#### Problem?

There are still a variety of things that need to be fixed or implemented (cf [TODO
file](TODO.md)), and some of these may explain the behavior you're seeing.  If bitc
crashes, please collect the log file along with the core dump and open a ticket
on github:  
	https://github.com/bit-c/bitc/issues

---

#### Feedback, comments?

Please feel free to reach out to me if you have any feedback, or if you're
planning to use this code in interesting ways.
