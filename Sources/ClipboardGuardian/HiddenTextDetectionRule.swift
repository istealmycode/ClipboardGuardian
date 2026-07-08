import Foundation

public struct HiddenTextDetectionRule: DetectionRule {
    public init() {}

    public func detect(in content: String) -> [Finding] {
        guard !content.isEmpty else {
            return []
        }

        if containsZeroWidthOrBidiControls(content) {
            return [
                Finding(
                    severity: .high,
                    category: "hidden text",
                    message: "Invisible or bidirectional control characters were detected."
                )
            ]
        }

        if hasSuspiciousControlCharacterRatio(content) {
            return [
                Finding(
                    severity: .high,
                    category: "hidden text",
                    message: "A high ratio of non-printable control characters was detected."
                )
            ]
        }

        return []
    }

    private func containsZeroWidthOrBidiControls(_ content: String) -> Bool {
        for scalar in content.unicodeScalars {
            if isZeroWidthOrBidiControl(scalar.value) {
                return true
            }
        }
        return false
    }

    private func hasSuspiciousControlCharacterRatio(_ content: String) -> Bool {
        let scalars = Array(content.unicodeScalars)
        guard scalars.count >= 12 else {
            return false
        }

        let suspicious = scalars.filter { isSuspiciousControl($0.value) }.count
        let ratio = Double(suspicious) / Double(scalars.count)
        return suspicious >= 4 && ratio >= 0.15
    }

    private func isZeroWidthOrBidiControl(_ value: UInt32) -> Bool {
        switch value {
        case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF:
            return true
        case 0x202A...0x202E, 0x2066...0x2069:
            return true
        default:
            return false
        }
    }

    private func isSuspiciousControl(_ value: UInt32) -> Bool {
        if value == 0x09 || value == 0x0A || value == 0x0D {
            return false
        }

        return (0x00...0x1F).contains(value) || (0x7F...0x9F).contains(value)
    }
}
