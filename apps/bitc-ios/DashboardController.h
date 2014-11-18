//
//  SecondViewController.h
//  SimpleTest
//
//  Created by Maxime Austruy on 05/11/14.
//  Copyright (c) 2014 Maxime Austruy. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface DashboardController : UIViewController

@property (weak, nonatomic) IBOutlet UILabel *addrsLabel;
@property (weak, nonatomic) IBOutlet UILabel *peersLabel;
@property (weak, nonatomic) IBOutlet UILabel *heightLabel;
@property (weak, nonatomic) IBOutlet UILabel *dateLabel;
@property (weak, nonatomic) IBOutlet UILabel *hashLabel;

@end

