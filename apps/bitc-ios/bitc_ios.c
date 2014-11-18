//
//  bitc_ios.c
//  bitc-ios
//
//  Created by Maxime Austruy on 11/11/14.
//  Copyright (c) 2014 Maxime Austruy. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>

#include "bitc_ios.h"
#include "bitc_ui.h"
#include "util.h"
#include "bitc.h"
#include "block-store.h"


/*
 *-------------------------------------------------------------------
 *
 * bitc_ios_log --
 *
 *-------------------------------------------------------------------
 */

void
bitc_ios_log(const char *pfx,
             const char *line)
{
   LogViewAppend(pfx, line);
}


/*
 *-------------------------------------------------------------------
 *
 * bitc_ios_dashboard_update --
 *
 *-------------------------------------------------------------------
 */

void
bitc_ios_dashboard_update(void)
{
   btc_block_header hdr;
   char hashStr[80];
   char *ts = NULL;
   uint256 hash;
   int height;
   bool s;

   if (btc->blockStore == NULL) {
      return;
   }

   height = blockstore_get_height(btc->blockStore);
   if (height == 0) {
      return;
   }

   s = blockstore_get_block_at_height(btc->blockStore, height, &hash, &hdr);

   ASSERT(mutex_islocked(btcui->lock));

   uint256_snprintf_reverse(hashStr, sizeof hashStr, &hash);
   ts = print_time_local(hdr.timestamp, "%c");

   DashboardUpdate(height, hashStr,
                   btcui->num_peers_active,
                   btcui->num_peers_alive,
                   btcui->num_addrs,
                   ts ? ts : "");
   free(ts);
}


/*
 *-------------------------------------------------------------------
 *
 * bitc_ios_blocklist_update --
 *
 *-------------------------------------------------------------------
 */

void
bitc_ios_blocklist_update(void)
{
   int height;

   ASSERT(mutex_islocked(btcui->lock));

   height = blockstore_get_height(btc->blockStore);
   BlockListAddBlock(height);
}


/*
 *-------------------------------------------------------------------
 *
 * bitc_ios_info_update --
 *
 *-------------------------------------------------------------------
 */

void
bitc_ios_info_update(void)
{
   mutex_lock(btcui->lock);

   bitc_ios_dashboard_update();
   bitc_ios_blocklist_update();

   mutex_unlock(btcui->lock);
}
