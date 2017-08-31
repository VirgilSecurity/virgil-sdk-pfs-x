//
//  MigrationV1_1+Sessions.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/31/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

public protocol UserDefaultsProtocol: class {
    init?(suiteName suitename: String?)
    
    func dictionaryRepresentation() -> [String : Any]
    
    func removePersistentDomain(forName domainName: String)
}

extension UserDefaults: UserDefaultsProtocol { }

extension MigrationV1_1 {
    func getAllSessions() throws -> ([String : InitiatorSessionState], [String : ResponderSessionState]) {
        let dict = userDefaults.dictionaryRepresentation()
        
        var initiators: [String : InitiatorSessionState] = [:]
        var responders: [String : ResponderSessionState] = [:]
        for val in dict {
            guard let cardId = self.extractCardId(fromSessionName: val.key) else {
                continue
            }
            
            if let state = InitiatorSessionState(dictionary: val.value) {
                initiators[cardId] = state
            }
            else if let state = ResponderSessionState(dictionary: val.value) {
                responders[cardId] = state
            }
            else {
                throw SecureChat.makeError(withCode: .migrationV1_1UnknownSessionState, description: "Found unknown session state while migration to v1.1")
            }
        }
        
        return (initiators, responders)
    }
    
    private func extractCardId(fromSessionName sessionName: String) -> String? {
        let newSessionName = sessionName.replacingOccurrences(of: "VIRGIL.SESSION.", with: "")
        return newSessionName == sessionName ? nil : newSessionName
    }
    
    func removeAllSessions() throws {
        self.userDefaults.removePersistentDomain(forName: MigrationV1_1.getSuiteName(cardId: self.identityCard.identifier))
    }
}
