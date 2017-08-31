//
//  VSPPfsTestUtils.h
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/29/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSPTestsConst.h"

@import VirgilSDK;
@import VirgilSDKPFS;

@interface VSPPfsTestUtils : NSObject

@property (nonatomic) id<VSSCrypto> __nonnull crypto;
@property (nonatomic) VSPTestsConst * __nonnull consts;

- (VSPCreateEphemeralCardRequest * __nonnull)instantiateEphemeralCreateCardRequestsWithKeyPair:(VSSKeyPair * __nullable)keyPair identityCardId:(NSString * __nonnull)identityCardId identityPrivateKey:(VSSPrivateKey * __nonnull)identityPrivateKey;
- (NSArray<VSPCreateEphemeralCardRequest *> * __nonnull)instantiateMultipleEphemeralCreateCardRequestsForNumber:(NSUInteger)number identityCardId:(NSString * __nonnull)identityCardId identityPrivateKey:(VSSPrivateKey * __nonnull)identityPrivateKey;;

- (instancetype __nonnull)initWith NS_UNAVAILABLE;

- (instancetype __nonnull)initWithCrypto:(id<VSSCrypto> __nonnull)crypto consts:(VSPTestsConst * __nonnull)consts;

@end
