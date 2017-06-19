//
//  VSPTestUtils.h
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/16/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSPTestsConst.h"

@import VirgilSDK;
@import VirgilSDKPFS;

@interface VSPTestUtils : NSObject

@property (nonatomic) VSSCrypto * __nonnull crypto;
@property (nonatomic) VSPTestsConst * __nonnull consts;

- (VSPCreateEphemeralCardRequest * __nonnull)instantiateEphemeralCreateCardRequestsWithKeyPair:(VSSKeyPair * __nullable)keyPair ltc:(BOOL)ltc identityCardId:(NSString * __nonnull)identityCardId identityPrivateKey:(VSSPrivateKey * __nonnull)identityPrivateKey;
- (NSArray<VSPCreateEphemeralCardRequest *> * __nonnull)instantiateMultipleEphemeralCreateCardRequestsForNumber:(NSUInteger)number identityCardId:(NSString * __nonnull)identityCardId identityPrivateKey:(VSSPrivateKey * __nonnull)identityPrivateKey;;

- (VSSCreateUserCardRequest * __nonnull)instantiateCreateCardRequestWithKeyPair:(VSSKeyPair * __nullable)keyPair;

@end
