//
//  VirgilSDKPFS.h
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/12/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "TargetConditionals.h"

#if TARGET_OS_IPHONE
    #import <UIKit/UIKit.h>
#else
    #import <Cocoa/Cocoa.h>
#endif

//! Project version number for VirgilSDKPFS.
FOUNDATION_EXPORT double VirgilSDKPFSVersionNumber;

//! Project version string for VirgilSDKPFS.
FOUNDATION_EXPORT const unsigned char VirgilSDKPFSVersionString[];

#import "VSPCreateEphemeralCardRequest.h"
