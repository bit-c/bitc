//
//  AppDelegate.m
//  SimpleTest
//
//  Created by Maxime Austruy on 05/11/14.
//  Copyright (c) 2014 Maxime Austruy. All rights reserved.
//

#import "AppDelegate.h"
#import "app.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

#include "bitc_ui.h"

@interface AppDelegate ()

@end

@implementation AppDelegate

/*
 *------------------------------------------------------------------------------
 *
 * ReadEventCB --
 *
 *------------------------------------------------------------------------------
 */

static void
ReadEventCB(CFFileDescriptorRef fdref,
            CFOptionFlags callBackTypes,
            void *info)
{
   int data = 0;
   int res;
   int fd;
   
   fd = CFFileDescriptorGetNativeDescriptor(fdref);
   res = read(fd, &data, 1);
   if (res < 0) {
      printf("Failed to read ui fd: %d\n", errno);
   
   }
   
   bitcui_process_update();
   
   CFFileDescriptorEnableCallBacks(fdref, kCFFileDescriptorReadCallBack);
}


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
   CFFileDescriptorRef fdref;
   CFRunLoopSourceRef source;
   NSString *path;
   int res;
   
   /* make sure cocoa knows we're multithreaded */
   [[NSThread new] start];

   path = [ NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject ];
   path = [NSString stringWithFormat:@"%@/../", path ];
   path = [path stringByStandardizingPath];
   
   NSLog(@"%@", path);
 
   res = bitc_app_init([ path UTF8String]);
   if (res) {
      NSLog(@"bitc_app_init: %d\n", res);
   }

   fdref = CFFileDescriptorCreate(kCFAllocatorDefault, btcui->eventFd, false, ReadEventCB, NULL);
   CFFileDescriptorEnableCallBacks(fdref, kCFFileDescriptorReadCallBack);
   
   source = CFFileDescriptorCreateRunLoopSource(kCFAllocatorDefault, fdref, 0);
   CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopDefaultMode);
    
   return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
   NSLog(@"%s", __FUNCTION__);
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
   NSLog(@"%s", __FUNCTION__);
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
   NSLog(@"%s", __FUNCTION__);
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
   NSLog(@"%s", __FUNCTION__);
}

- (void)applicationWillTerminate:(UIApplication *)application {
   NSLog(@"%s", __FUNCTION__);
}

@end
