//
//  BlockListController.m
//  SimpleTest
//
//  Created by Maxime Austruy on 05/11/14.
//  Copyright (c) 2014 Maxime Austruy. All rights reserved.
//

#import "BlockListController.h"
#import "BlockDetailViewController.h"

#include "util.h"
#include "block-store.h"
#include "bitc.h"

@interface BlockListController ()

@end

@implementation BlockListController

static UITableView *blockList;
static int maxHeight;

void
BlockListAddBlock(int height)
{
   if (height == 0 || height == maxHeight) {
      return;
   }
   NSMutableArray *indexPaths = [NSMutableArray array];
   
   if (height - maxHeight > 100) {
      [blockList reloadData];
      maxHeight = height;
      return;
   }
 
   for (int i = 0; i < height - maxHeight; i++) {
      [indexPaths addObject:[NSIndexPath indexPathForRow:i inSection:0]];
   }
   
   maxHeight = MAX(maxHeight, height);
   
   [ blockList beginUpdates];
   [ blockList insertRowsAtIndexPaths:indexPaths
                         withRowAnimation:UITableViewRowAnimationRight];
   [ blockList endUpdates];
}

- (void)viewDidLoad {
   [super viewDidLoad];
   blockList = _BlockList;
}

- (void)didReceiveMemoryWarning {
   [super didReceiveMemoryWarning];
}

#pragma mark - Table view data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
   return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
   return maxHeight;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
   UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"BlockCell"];
   int height = maxHeight - (long) indexPath.row;
   btc_block_header hdr;
   uint256 hash;
   bool s;
   
   s = blockstore_get_block_at_height(btc->blockStore, height, &hash, &hdr);
   if (s) {
      char hashStr[80];
      char *ts;
      
      ts = print_time_local_short(hdr.timestamp);
      uint256_snprintf_reverse(hashStr, sizeof hashStr, &hash);

      cell.textLabel.text = [NSString stringWithFormat:@"%u -- %s", height, ts];
      cell.detailTextLabel.text = [NSString stringWithFormat:@"%s", hashStr];
      free(ts);
   } else {
      NSLog(@"not found");
   }
   
   return cell;
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return NO;
}

- (BOOL)tableView:(UITableView *)tableView canMoveRowAtIndexPath:(NSIndexPath *)indexPath {
    return NO;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    NSString *segueString = [ NSString stringWithFormat:@"ShowBlockDetail" ];
    
    [self performSegueWithIdentifier:segueString sender:self];
}


#pragma mark - Navigation

-(void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
{
   if ([[segue identifier] isEqualToString:@"ShowBlockDetail"]) {
      BlockDetailViewController *detailViewController = [segue destinationViewController];
      NSIndexPath *indexPath = [self.tableView indexPathForSelectedRow];
      int height = maxHeight - (long) indexPath.row;

      NSLog(@"%s: %@ (height=%u)", __FUNCTION__, [segue identifier], height);
      
      detailViewController.blockNumber = @(height);
   }
}

@end
