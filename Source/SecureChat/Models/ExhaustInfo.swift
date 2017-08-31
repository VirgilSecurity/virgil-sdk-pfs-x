//
//  ExhaustInfo.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct ExhaustInfo {
    let otc: [ExhaustInfoEntry]
    let ltc: [ExhaustInfoEntry]
    let sessions: [SessionExhaustInfo]
}

extension ExhaustInfo {
    private enum Keys: String {
        case otc = "otc"
        case ltc = "ltc"
        case sessions = "sessions"
    }
    
    func encode() -> [String : Any] {
        let dict: [String : Any] = [
            Keys.otc.rawValue: self.otc.map({ $0.encode() }),
            Keys.ltc.rawValue: self.ltc.map({ $0.encode() }),
            Keys.sessions.rawValue: self.sessions.map({ $0.encode() })
        ]
        
        return dict
    }
    
    init?(dict: [String : Any]) {
        guard let otcArrDict = dict[Keys.otc.rawValue] as? [[String : Any]],
            let ltcArrDict = dict[Keys.ltc.rawValue] as? [[String : Any]],
            let sessionsArrDict = dict[Keys.sessions.rawValue] as? [[String : Any]] else {
                return nil
        }
        
        let otc = otcArrDict.flatMap({ ExhaustInfoEntry(dict: $0) })
        let ltc = ltcArrDict.flatMap({ ExhaustInfoEntry(dict: $0) })
        let sessions = sessionsArrDict.flatMap({ SessionExhaustInfo(dict: $0) })
        
        guard otc.count == otcArrDict.count,
            ltc.count == ltcArrDict.count,
            sessions.count == sessionsArrDict.count else {
                return nil
        }
        
        self.init(otc: otc, ltc: ltc, sessions: sessions)
    }
}

struct ExhaustInfoEntry {
    let identifier: String
    let exhaustDate: Date
}

extension ExhaustInfoEntry {
    private enum Keys: String {
        case identifier = "identifier"
        case exhaustDate = "exhaust_date"
    }
    
    func encode() -> [String : Any] {
        let dict: [String : Any] = [
            Keys.identifier.rawValue: self.identifier,
            Keys.exhaustDate.rawValue: self.exhaustDate
        ]
        
        return dict
    }
    
    init?(dict: [String : Any]) {
        guard let identifier = dict[Keys.identifier.rawValue] as? String,
            let exhaustDate = dict[Keys.exhaustDate.rawValue] as? Date else {
                return nil
        }
        
        self.init(identifier: identifier, exhaustDate: exhaustDate)
    }
}

extension ExhaustInfoEntry: Equatable {
    static func ==(lhs: ExhaustInfoEntry, rhs: ExhaustInfoEntry) -> Bool {
        return lhs.identifier == rhs.identifier
            && lhs.exhaustDate == rhs.exhaustDate
    }
}

struct SessionExhaustInfo {
    let identifier: Data
    let cardId: String
    let exhaustDate: Date
}

extension SessionExhaustInfo {
    private enum Keys: String {
        case identifier = "identifier"
        case cardId = "card_id"
        case exhaustDate = "exhaust_date"
    }
    
    func encode() -> [String : Any] {
        let dict: [String : Any] = [
            Keys.identifier.rawValue: self.identifier.base64EncodedString(),
            Keys.cardId.rawValue: self.cardId,
            Keys.exhaustDate.rawValue: self.exhaustDate
        ]
        
        return dict
    }
    
    init?(dict: [String : Any]) {
        guard let identifierStr = dict[Keys.identifier.rawValue] as? String,
            let identifier = Data(base64Encoded: identifierStr),
            let cardId = dict[Keys.cardId.rawValue] as? String,
            let exhaustDate = dict[Keys.exhaustDate.rawValue] as? Date else {
                return nil
        }
        
        self.init(identifier: identifier, cardId: cardId, exhaustDate: exhaustDate)
    }
}

extension SessionExhaustInfo: Equatable {
    static func ==(lhs: SessionExhaustInfo, rhs: SessionExhaustInfo) -> Bool {
        return lhs.identifier == rhs.identifier
            && lhs.exhaustDate == rhs.exhaustDate
            && lhs.cardId == rhs.cardId
    }
}

