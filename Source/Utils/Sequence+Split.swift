//
//  Sequence+Split.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

extension Sequence {
    func splitIntoTwoArrays(_ include: (Self.Iterator.Element) throws -> (Bool, Bool)) rethrows -> ([Self.Iterator.Element], [Self.Iterator.Element]) {
        var firstTypeElemets = Array<Self.Iterator.Element>()
        var secondTypeElemets = Array<Self.Iterator.Element>()
    
        try self.forEach({
            let (includeToFirst, includeToSecond) = try include($0)
            
            if (includeToFirst) {
                firstTypeElemets.append($0)
            }
            if (includeToSecond) {
                secondTypeElemets.append($0)
            }
        })
        
        return (firstTypeElemets, secondTypeElemets)
    }
}
