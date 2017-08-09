//
//  Mutex.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/9/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class Mutex {
    private var mutex = pthread_mutex_t()
    
    init() {
        pthread_mutex_init(&self.mutex, nil)
    }
    
    deinit {
        pthread_mutex_destroy(&self.mutex)
    }
    
    func trylock() -> Bool {
        return pthread_mutex_trylock(&self.mutex) == 0
    }
    
    func lock() {
        pthread_mutex_lock(&self.mutex)
    }
    
    func unlock() {
        pthread_mutex_unlock(&self.mutex)
    }
    
    func lock(closure: ()->()) {
        self.lock()
        
        closure()
        
        defer {
            self.unlock()
        }
    }
    
    func lock(closure: () throws -> ()) throws {
        self.lock()
        
        try closure()
        
        defer {
            self.unlock()
        }
    }
}
