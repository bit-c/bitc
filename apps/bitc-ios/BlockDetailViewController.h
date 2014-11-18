//
//  BlockDetailViewController.h
//  bitc-ios
//
//  Created by Maxime Austruy on 11/7/14.
//  Copyright (c) 2014 Maxime Austruy. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface BlockDetailViewController : UITableViewController

@property (weak, nonatomic) IBOutlet UILabel *nonceLabel;
@property (weak, nonatomic) IBOutlet UILabel *bitsLabel;
@property (weak, nonatomic) IBOutlet UILabel *blockVersionLabel;
@property (weak, nonatomic) IBOutlet UILabel *timestampLabel;

@property (strong, nonatomic) NSNumber         *blockNumber;
@property (strong, nonatomic) IBOutlet UILabel *blockNumberLabel;
@property (strong, nonatomic) NSString         *hashStr;

@end
