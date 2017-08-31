//
//  UserDefaultsMock.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/31/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDKPFS

final class UserDefaultsMock: UserDefaultsProtocol {
    let dict: NSDictionary
    
    init?(suiteName suitename: String?) {
        let bundle = Bundle(for: UserDefaultsMock.self)
        let path = bundle.path(forResource: suitename!, ofType: "plist")!
        let data = FileManager().contents(atPath: path)!
        
        let dict = try! PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        self.dict = dict as! NSDictionary
    }
    
    func dictionaryRepresentation() -> [String : Any] {
        return self.dict as! [String : Any]
    }
    
    func removePersistentDomain(forName domainName: String) {
        
    }
}
