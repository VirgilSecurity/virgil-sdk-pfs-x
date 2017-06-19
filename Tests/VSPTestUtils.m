//
//  VSPTestUtils.m
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/16/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSPTestUtils.h"

@implementation VSPTestUtils

- (instancetype)init
{
    self = [super init];
    if (self) {
        _consts = [[VSPTestsConst alloc] init];
        _crypto = [[VSSCrypto alloc] init];
    }
    return self;
}

- (VSPCreateEphemeralCardRequest *)instantiateEphemeralCreateCardRequestsWithKeyPair:(VSSKeyPair *)keyPair ltc:(BOOL)ltc identityCardId:(NSString *)identityCardId identityPrivateKey:(VSSPrivateKey *)identityPrivateKey {
    VSSKeyPair *kp = keyPair != nil ? keyPair : [self.crypto generateKeyPair];
    NSData *exportedPublicKey = [self.crypto exportPublicKey:kp.publicKey];
    
    NSString *identityValue = [[NSUUID alloc] init].UUIDString;
    NSString *identityType = self.consts.applicationIdentityType;
    VSPCreateEphemeralCardRequest * request = [VSPCreateEphemeralCardRequest createEphemeralCardRequestWithIdentity:identityValue identityType:ltc ? @"ltc" : @"otc" publicKeyData:exportedPublicKey];
    
    VSSRequestSigner *signer = [[VSSRequestSigner alloc] initWithCrypto:self.crypto];
    
    [signer selfSignRequest:request withPrivateKey:kp.privateKey error:nil];
    [signer authoritySignRequest:request forAppId:identityCardId withPrivateKey:identityPrivateKey error:nil];
    
    return request;
}

- (NSArray<VSPCreateEphemeralCardRequest *> *)instantiateMultipleEphemeralCreateCardRequestsForNumber:(NSUInteger)number identityCardId:(NSString *)identityCardId identityPrivateKey:(VSSPrivateKey *)identityPrivateKey {
    NSMutableArray<VSPCreateEphemeralCardRequest *> *arr = [[NSMutableArray alloc] initWithCapacity:number];
    for (int i = 0; i < number; i++) {
        [arr addObject:[self instantiateEphemeralCreateCardRequestsWithKeyPair:nil ltc:NO identityCardId:identityCardId identityPrivateKey:identityPrivateKey]];
    }
    
    return arr;
}

- (VSSCreateUserCardRequest *)instantiateCreateCardRequestWithKeyPair:(VSSKeyPair *)keyPair {
    VSSKeyPair *kp = keyPair != nil ? keyPair : [self.crypto generateKeyPair];
    NSData *exportedPublicKey = [self.crypto exportPublicKey:kp.publicKey];
    
    NSString *identityValue = [[NSUUID alloc] init].UUIDString;
    NSString *identityType = self.consts.applicationIdentityType;
    VSSCreateUserCardRequest *request = [VSSCreateUserCardRequest createUserCardRequestWithIdentity:identityValue identityType:identityType publicKeyData:exportedPublicKey];
    
    NSData *privateAppKeyData = [[NSData alloc] initWithBase64EncodedString:self.consts.applicationPrivateKeyBase64 options:0];
    VSSPrivateKey *appPrivateKey = [self.crypto importPrivateKeyFromData:privateAppKeyData withPassword:self.consts.applicationPrivateKeyPassword];
    
    VSSRequestSigner *signer = [[VSSRequestSigner alloc] initWithCrypto:self.crypto];
    
    [signer selfSignRequest:request withPrivateKey:kp.privateKey error:nil];
    [signer authoritySignRequest:request forAppId:self.consts.applicationId withPrivateKey:appPrivateKey error:nil];
    
    return request;
}

@end
