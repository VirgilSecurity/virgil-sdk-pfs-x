//
//  AsyncOperation.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/9/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

protocol FailableOperation: class {
    var isFailed: Bool { get }
}

extension Operation: FailableOperation {
    open var isFailed: Bool { return false }
    open var error: Error? { return .none }
}

extension Operation {
    func findDependency<T: Operation>() -> T? {
        for dependency in self.dependencies {
            if let typeDependency = dependency as? T {
                return typeDependency
            }
        }
        
        return .none
    }
}

class AsyncOperation: Operation {
    override var isAsynchronous: Bool { return true }
    
    override var isExecuting: Bool { return self._executing }
    private var _executing = false {
        willSet {
            self.willChangeValue(forKey: "isExecuting")
        }
        didSet {
            self.didChangeValue(forKey: "isExecuting")
        }
    }
    
    override var isFinished: Bool { return self._finished }
    private var _finished = false {
        willSet {
            self.willChangeValue(forKey: "isFinished")
        }
        
        didSet {
            self.didChangeValue(forKey: "isFinished")
        }
    }
    
    override func start() {
        guard !self.isCancelled else {
            return
        }
        
        for dependency in self.dependencies {
            guard !dependency.isFailed else {
                self.fail(withError: dependency.error)
                return
            }
        }
        
        self._executing = true
        self.execute()
    }
    
    func execute() {
        // Execute your async task here.
    }
    
    func finish() {
        // Notify the completion of async task and hence the completion of the operation
        
        self._executing = false
        self._finished = true
    }
    
    override var isFailed: Bool { return self._failed }
    private var _failed = false
    
    func fail() {
        self._failed = true
        
        self.finish()
    }
    
    func fail(withError error: Error?) {
        self._error = error
        
        self.fail()
    }
    
    private var _error: Error?
    override var error: Error? { return self._error }
}
