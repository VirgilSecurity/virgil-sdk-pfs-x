//
//  Dictionary+Pairs.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

extension Dictionary {
    init(_ pairs: [Element]) {
        self.init()
        for (k, v) in pairs {
            self[k] = v
        }
    }
    
    func mapPairs<Key: Hashable, Value>(_ transform: (Element) throws -> (Key, Value)) rethrows -> [Key: Value] {
        return Dictionary<Key, Value>(try self.map(transform))
    }
}
