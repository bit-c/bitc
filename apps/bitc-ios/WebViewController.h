//
//  WebViewController.h
//  bitc-ios
//
//  Created by Maxime Austruy on 13/11/14.
//  Copyright (c) 2014 Maxime Austruy. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface WebViewController : UIViewController
@property (weak, nonatomic) IBOutlet UIWebView *webView;

@property (strong, nonatomic) NSString *hashStr;

@end
