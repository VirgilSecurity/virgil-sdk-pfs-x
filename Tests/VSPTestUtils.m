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

- (instancetype __nonnull)initWithCrypto:(id<VSSCrypto>)crypto consts:(VSPTestsConst *)consts {
    self = [super init];
    if (self) {
        _consts = consts;
        _crypto = crypto;
    }
    return self;
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
