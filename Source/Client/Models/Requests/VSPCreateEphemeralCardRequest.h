//
//  VSPCreateEphemeralCardRequest.h
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

@import VirgilSDK;

@interface VSPCreateEphemeralCardRequest : VSSCreateCardRequest

+ (instancetype __nonnull)createEphemeralCardRequestWithIdentity:(NSString * __nonnull)identity identityType:(NSString * __nonnull)identityType publicKeyData:(NSData * __nonnull)publicKeyData data:(NSDictionary<NSString *, NSString *> * __nullable)data;

+ (instancetype __nonnull)createEphemeralCardRequestWithIdentity:(NSString * __nonnull)identity identityType:(NSString * __nonnull)identityType publicKeyData:(NSData * __nonnull)publicKeyData data:(NSDictionary<NSString *, NSString *> * __nullable)data device:(NSString * __nonnull)device deviceName:(NSString * __nonnull)deviceName;

+ (instancetype __nonnull)createEphemeralCardRequestWithIdentity:(NSString * __nonnull)identity identityType:(NSString * __nonnull)identityType publicKeyData:(NSData * __nonnull)publicKeyData;

@end
