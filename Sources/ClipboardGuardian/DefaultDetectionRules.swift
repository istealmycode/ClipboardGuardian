public func defaultDetectionRules() -> [any DetectionRule] {
    [
        PrivateKeyDetectionRule(),
        AWSCredentialDetectionRule(),
        GitHubTokenDetectionRule(),
        GenericCredentialDetectionRule(),
        JWTDetectionRule(),
        EncodedPayloadDetectionRule(),
        MaliciousJavaScriptDetectionRule(),
        HiddenTextDetectionRule()
    ]
}
