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

@property (nonatomic) id<VSSCrypto> __nonnull crypto;
@property (nonatomic) VSPTestsConst * __nonnull consts;

- (VSSCreateUserCardRequest * __nonnull)instantiateCreateCardRequestWithKeyPair:(VSSKeyPair * __nullable)keyPair;

- (instancetype __nonnull)initWith NS_UNAVAILABLE;

- (instancetype __nonnull)initWithCrypto:(id<VSSCrypto> __nonnull)crypto consts:(VSPTestsConst * __nonnull)consts;

@end
