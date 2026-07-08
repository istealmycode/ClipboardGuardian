import Foundation

public struct JWTDetectionRule: DetectionRule {
    public init() {}

    public func detect(in content: String) -> [Finding] {
        let pattern = #"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return []
        }

        let range = NSRange(content.startIndex..<content.endIndex, in: content)
        let matches = regex.matches(in: content, range: range)

        for match in matches {
            guard let tokenRange = Range(match.range, in: content) else {
                continue
            }
            let token = String(content[tokenRange])
            if isLikelyJWT(token) {
                return [
                    Finding(
                        severity: .high,
                        category: "credential",
                        message: "A JWT-like token was detected."
                    )
                ]
            }
        }

        return []
    }

    private func isLikelyJWT(_ token: String) -> Bool {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else {
            return false
        }

        guard let headerData = decodeBase64URL(String(parts[0])),
              let headerText = String(data: headerData, encoding: .utf8) else {
            return false
        }

        return headerText.contains("\"alg\"")
    }

    private func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }
}
