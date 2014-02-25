
OS=$(shell uname -s)
ARCH=$(shell uname -m)

ifeq ($(ARCH), armv6l)
CC = gcc
else
CC = clang
endif
ASAN = 0

###
### CFLAGS
###

CFLAGS  = -O1 -MMD -g
CFLAGS += -Wall -Werror
ifneq ($(ARCH), armv6l)
CFLAGS += -Wshadow -Wextra
endif
CFLAGS += -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers

CFLAGS += -fno-omit-frame-pointer
CFLAGS += -fstack-protector
ifeq ($(ASAN), 1)
ifneq ($(OS), Darwin)
CFLAGS += -fsanitize=address
endif
endif

ifeq ($(OS), OpenBSD)
CFLAGS += -I/usr/local/include
endif

###
### LDOPTS
###

LDOPTS =
ifneq ($(OS), Darwin)
ifeq ($(ASAN), 1)
LDOPTS += -fsanitize=address
endif
LDOPTS += -rdynamic
endif

ifdef P
CFLAGS += -pg
LDOPTS += -pg
endif


###
### the rest
###

LIBS  = -lpthread -lssl -lcrypto -lm -lncurses -lpanel -lform -lcurl
LIBS += -lleveldb -lsnappy -lstdc++

ifeq ($(OS), OpenBSD)
LIBS += -L/usr/local/lib -lexecinfo
LIBS := $(subst -lsnappy,,$(LIBS))
endif

VGRND  = valgrind --log-file=/tmp/valgrind.log --leak-check=full --error-exitcode=255
SRCDIR = src
BLDDIR = bld
MKBLDDIR = @mkdir -p $(BLDDIR)
BTC_BIN  = bitc
ALLTARGETS = bitc

ifndef V
  QUIET_CC   = @echo ' CC   ' $<;
  QUIET_LINK = @echo ' LINK ' $@;
  QUIET_TEST = >/dev/null 2>&1
endif

BTC_FILES  = btc-message.c
BTC_FILES += ncui.c
BTC_FILES += script.c
BTC_FILES += bitc_ui.c
BTC_FILES += peer.c
BTC_FILES += peergroup.c
BTC_FILES += addrbook.c
BTC_FILES += block-store.c
BTC_FILES += hash.c
BTC_FILES += fx.c
BTC_FILES += base58.c
BTC_FILES += bloom.c
BTC_FILES += key.c
BTC_FILES += txdb.c
BTC_FILES += wallet.c
BTC_FILES += test.c
BTC_FILES += serialize.c
BTC_FILES += hashtable.c
BTC_FILES += MurmurHash3.c
BTC_FILES += util.c
BTC_FILES += file.c
BTC_FILES += poolworker.c
BTC_FILES += config.c
BTC_FILES += poll.c
BTC_FILES += netasync.c
BTC_FILES += main.c
BTC_FILES += cJSON.c
BTC_FILES += ip_info.c
BTC_FILES += crypt.c
BTC_FILES += rpc.c

BTC_SRC  := $(patsubst %,$(SRCDIR)/%,$(BTC_FILES))
BTC_SRC  := $(sort $(BTC_SRC))
BTC_OBJ  := $(patsubst $(SRCDIR)/%.c,$(BLDDIR)/%.o,$(BTC_SRC))
BTC_DEPS := $(patsubst $(SRCDIR)/%.c,$(BLDDIR)/%.d,$(BTC_SRC))

$(BLDDIR)/%.o: $(SRCDIR)/%.c
	$(MKBLDDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) -c $< -o $@

bitc: $(BTC_OBJ)
	$(QUIET_LINK)$(CC) $(LDOPTS) -o $(BTC_BIN) $(BTC_OBJ) $(LIBS)

# do not move the following line:
-include $(BTC_DEPS)

inocuoustest:
	$(eval VGRND :=)

test: bitc inocuoustest
	./bitc -t 0

vg-test: bitc inocuoustest
	$(VGRND) ./bitc -t 0

vg-run:
	valgrind --log-file=log --leak-check=full --gen-suppressions=all --suppressions=./valgrind.supp ./bitc

###
###  Common
###

all: $(ALLTARGETS)

lldb: src/lldb.c
	 $(CC) -o ./lldb src/lldb.c -lleveldb

lines:
	 find . -name '*.[ch]'|xargs cat|wc -l

clean:
	rm -f $(ALLTARGETS) *~ gmon*
	rm -rf $(BLDDIR)

tags:
	rm -f tags
	find . -follow \( -name '*.[ch]' \) -a -print | ctags -L -

cscope:
	rm -f cscope*
	find . -name '*.[ch]' -print | xargs cscope -b -q

.PHONY: clean tags cscope

