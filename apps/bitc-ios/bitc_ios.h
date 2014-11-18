//
//  bitc_ios.h
//  bitc-ios
//
//  Created by Maxime Austruy on 11/11/14.
//  Copyright (c) 2014 Maxime Austruy. All rights reserved.
//

#ifndef __bitc_ios__bitc_ios__
#define __bitc_ios__bitc_ios__

#include <stdio.h>

void
LogViewAppend(const char *pfx,
              const char *line);

void
DashboardUpdate(int height,
                const char *hash,
                int connected,
                int total, int numAddrs,
                const char *date);

void BlockListAddBlock(int height);


void bitc_ios_log(const char *pfx, const char *line);
void bitc_ios_info_update(void);

#endif /* defined(__bitc_ios__bitc_ios__) */
