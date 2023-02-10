import Foundation
import AskarFramework

public class Logger {
    public static func setDefaultLogger() throws {
        let err = askar_set_default_logger()
        if err != Success {
            throw AskarError.nativeError(code: err.rawValue)
        }
    }
}
