//
//  SecondViewController.m
//  SimpleTest
//
//  Created by Maxime Austruy on 05/11/14.
//  Copyright (c) 2014 Maxime Austruy. All rights reserved.
//

#import "DashboardController.h"

@interface DashboardController ()

@end

static UILabel *addrsLbl;
static UILabel *peersLbl;
static UILabel *heightLbl;
static UILabel *dateLbl;
static UILabel *hashLbl;

void
DashboardUpdate(int height,
                const char *hash,
                int total,
                int connected,
                int numAddrs,
                const char *date)
{
   heightLbl.text = [ NSString stringWithFormat:@"%u", height ];
   dateLbl.text   = [ NSString stringWithFormat:@"%s", date ];
   peersLbl.text  = [ NSString stringWithFormat:@"%u / %u", connected, total ];
   hashLbl.text   = [ NSString stringWithFormat:@"%s", hash ];
   addrsLbl.text  = [ NSString stringWithFormat:@"%u", numAddrs ];
}


@implementation DashboardController

@synthesize addrsLabel = _addrsLabel;

- (void)viewDidLoad {
   [super viewDidLoad];
   NSLog(@"%s", __FUNCTION__);
   addrsLbl = _addrsLabel;
   peersLbl = _peersLabel;
   heightLbl = _heightLabel;
   dateLbl = _dateLabel;
   hashLbl = _hashLabel;
   NSLog(@"%s", __FUNCTION__);
}

- (void)didReceiveMemoryWarning {
   [super didReceiveMemoryWarning];
}

@end
