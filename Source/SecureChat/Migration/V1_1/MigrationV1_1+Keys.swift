//
//  MigrationV1_1+Keys.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/31/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

extension MigrationV1_1 {
    func extractCardId(fromLtKeyEntryName LtkeyEntryName: String) -> String {
        return LtkeyEntryName.replacingOccurrences(of: "VIRGIL.OWNER=\(self.identityCard.identifier).LT_KEY.", with: "")
    }
    
    func extractCardId(fromOtKeyEntryName OtkeyEntryName: String) -> String {
        return OtkeyEntryName.replacingOccurrences(of: "VIRGIL.OWNER=\(self.identityCard.identifier).OT_KEY.", with: "")
    }
    
    func getEphPrivateKey(name: String) throws -> KeyEntry {
        return try self.keyStorage.loadKeyEntry(withName: name)
    }
    
    func removeEphPrivateKey(name: String) throws {
        try self.keyStorage.deleteKeyEntry(withName: name)
    }
    
    private func getServiceInfoEntryName() -> String {
        return "VIRGIL.SERVICE.INFO.\(self.identityCard.identifier)"
    }
    
    func removeServiceInfoEntry() throws {
        try self.keyStorage.deleteKeyEntry(withName: self.getServiceInfoEntryName())
    }
}
