
#include "TurboModuleUtils.h"
#include "Logging.h"

#import "AriesAskar.h"
#import "react-native-aries-askar.h"
#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import <ReactCommon/RCTTurboModuleManager.h>
#import <jsi/jsi.h>
#import <memory>

using namespace facebook;

@implementation AriesAskar 

@synthesize bridge=_bridge;
@synthesize methodQueue = _methodQueue;

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup {
  return YES;
}

// Entry point for registering this module
- (void)setBridge:(RCTBridge *)bridge {
  _bridge = bridge;
  [self installLibrary];
}

- (void)installLibrary {
    LOG("Installing library...");
    RCTCxxBridge *cxxBridge = (RCTCxxBridge *)self.bridge;

    if (!cxxBridge.runtime) {
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.001 * NSEC_PER_SEC),
                     dispatch_get_main_queue(), ^{
          /** Hack Warning
           When refreshing the app while debugging, the setBridge
           method is called too soon. The runtime is not ready yet
           quite often. We need to install library as soon as runtime
           becomes available.
           */
          [self installLibrary];
      });
      return;
    }
    
    // get the jsCallinvoker
    jsi::Runtime* jsiRuntime = (jsi::Runtime *)cxxBridge.runtime;
    auto callInvoker = _bridge.jsCallInvoker;
    
    // installs the turbomodule
    TurboModuleUtils::installTurboModule(*jsiRuntime, callInvoker);
}

@end
