//
//  VSPTestUtils.h
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/16/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSPTestsConst.h"

@import VirgilSDK;

@interface VSPTestUtils : NSObject

@property (nonatomic) VSSCrypto * __nonnull crypto;
@property (nonatomic) VSPTestsConst * __nonnull consts;

- (VSSCreateCardRequest * __nonnull)instantiateCreateCardRequestWithKeyPair:(VSSKeyPair * __nullable)keyPair;

@end
