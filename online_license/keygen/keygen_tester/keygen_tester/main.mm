//
//  main.m
//  keygen_tester
//
//  Created by my_anonymous on 2022/7/20.
//

#import <Foundation/Foundation.h>
#import "keygen_tester.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        NSString* key = @"JcWKEcLPCmCNOoFoCDQDFqEgAqAPEqFoLDQDFDGoFmATEMAqOoGoFoQPEPArAMIMENAcETITAMEqAmEgIgATATETEMEMEqArArWMGN";
        NSString* iv = @"1658294783";
        KeyGenTester(key.UTF8String, iv.UTF8String);
        NSLog(@"Hello, World!");
    }
    return 0;
}
