//
//  VSPPfsTestUtils.m
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/29/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSPPfsTestUtils.h"

@implementation VSPPfsTestUtils

- (instancetype __nonnull)initWithCrypto:(id<VSSCrypto>)crypto consts:(VSPTestsConst *)consts {
    self = [super init];
    if (self) {
        _consts = consts;
        _crypto = crypto;
    }
    return self;
}

- (VSPCreateEphemeralCardRequest *)instantiateEphemeralCreateCardRequestsWithKeyPair:(VSSKeyPair *)keyPair identityCardId:(NSString *)identityCardId identityPrivateKey:(VSSPrivateKey *)identityPrivateKey {
    VSSKeyPair *kp = keyPair != nil ? keyPair : [self.crypto generateKeyPair];
    NSData *exportedPublicKey = [self.crypto exportPublicKey:kp.publicKey];
    
    NSString *identityValue = [[NSUUID alloc] init].UUIDString;
    NSString *identityType = self.consts.applicationIdentityType;
    VSPCreateEphemeralCardRequest * request = [VSPCreateEphemeralCardRequest createEphemeralCardRequestWithIdentity:identityValue identityType:identityType publicKeyData:exportedPublicKey];
    
    VSSRequestSigner *signer = [[VSSRequestSigner alloc] initWithCrypto:self.crypto];
    
    [signer authoritySignRequest:request forAppId:identityCardId withPrivateKey:identityPrivateKey error:nil];
    
    return request;
}

- (NSArray<VSPCreateEphemeralCardRequest *> *)instantiateMultipleEphemeralCreateCardRequestsForNumber:(NSUInteger)number identityCardId:(NSString *)identityCardId identityPrivateKey:(VSSPrivateKey *)identityPrivateKey {
    NSMutableArray<VSPCreateEphemeralCardRequest *> *arr = [[NSMutableArray alloc] initWithCapacity:number];
    for (int i = 0; i < number; i++) {
        [arr addObject:[self instantiateEphemeralCreateCardRequestsWithKeyPair:nil identityCardId:identityCardId identityPrivateKey:identityPrivateKey]];
    }
    
    return arr;
}

@end
