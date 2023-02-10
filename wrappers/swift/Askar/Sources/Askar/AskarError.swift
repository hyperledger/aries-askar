import Foundation

public enum AskarErrorCode: Int32 {
    case Success = 0
    case Backend = 1
    case Busy = 2
    case Duplicate = 3
    case Encryption = 4
    case Input = 5
    case NotFound = 6
    case Unexpected = 7
    case Unsupported = 8
    case Custom = 100
}

public enum AskarError: LocalizedError {
    case nativeError(code: UInt32)
    case wrapperError(message: String)

    public var errorDescription: String? {
        switch self {
        case .nativeError(let code):
            return "Askar error code: \(code)"
        case .wrapperError(let message):
            return message
        }
    }
}
