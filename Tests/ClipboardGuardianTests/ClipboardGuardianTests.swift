import Testing
@testable import ClipboardGuardian

@Suite("Clipboard Guardian Analyzer")
struct ClipboardGuardianTests {
    @Test("returns no findings for safe content when no rules are configured")
    func testAnalyzerWithNoRulesReturnsNoFindings() {
        let analyzer = Analyzer()

        let findings = analyzer.analyze("safe clipboard content")

        #expect(findings.isEmpty)
    }

    @Test("allows custom detection rules to surface findings")
    func testAnalyzerCanUseMockDetectionRule() {
        struct MockDetectionRule: DetectionRule {
            func detect(in content: String) -> [Finding] {
                guard content.contains("secret") else {
                    return []
                }

                return [
                    Finding(
                        severity: .high,
                        category: "mock",
                        message: "Mock rule detected a secret"
                    )
                ]
            }
        }

        let analyzer = Analyzer(rules: [MockDetectionRule()])

        let findings = analyzer.analyze("contains secret")

        #expect(findings.count == 1)
        #expect(findings.first?.severity == .high)
        #expect(findings.first?.category == "mock")
    }

    @Test("preserves finding severity, category, and message")
    func testSeverityAndMessagesArePreserved() {
        let finding = Finding(
            severity: .critical,
            category: "credential",
            message: "A credential-like value was found"
        )

        #expect(finding.severity == .critical)
        #expect(finding.category == "credential")
        #expect(finding.message == "A credential-like value was found")
    }

    @Test("detects PEM private key content")
    func testAnalyzerDetectsPrivateKeyContent() {
        let analyzer = Analyzer(rules: [PrivateKeyDetectionRule()])
        let content = """
        -----BEGIN PRIVATE KEY-----
        some fake key data
        -----END PRIVATE KEY-----
        """

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "private key")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("private key") == true)
    }

    @Test("detects private key boundaries even with loose formatting")
    func testAnalyzerDetectsPrivateKeyWithLooseBoundaryFormatting() {
        let analyzer = Analyzer(rules: [PrivateKeyDetectionRule()])
        let content = """
        --BEGIN PRIVATE KEY-
        some fake key data
        -END PRIVATE KEY--
        """

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "private key")
    }

    @Test("does not flag a normal sentence that mentions private key")
    func testAnalyzerDoesNotFlagNormalPrivateKeySentence() {
        let analyzer = Analyzer(rules: [PrivateKeyDetectionRule()])
        let content = "This sentence mentions a private key in a normal conversation."

        let findings = analyzer.analyze(content)

        #expect(findings.isEmpty)
    }

    @Test("detects AWS access key ID patterns")
    func testAnalyzerDetectsAWSAccessKeyID() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "AKIAIOSFODNN7EXAMPLE"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("AWS access key") == true)
    }

    @Test("detects AWS secret access key style assignments")
    func testAnalyzerDetectsAWSSecretAccessKeyFormat() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "aws_secret_access_key = exampleSecretValue"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("AWS") == true)
    }

    @Test("does not flag normal prose that mentions AWS terms")
    func testAnalyzerDoesNotFlagNormalAWSText() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "This text mentions AWS, access, and key in a normal sentence."

        let findings = analyzer.analyze(content)

        #expect(findings.isEmpty)
    }

    @Test("does not flag random identifiers")
    func testAnalyzerDoesNotFlagRandomIdentifier() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "randomIdentifier123"

        let findings = analyzer.analyze(content)

        #expect(findings.isEmpty)
    }

    @Test("formats findings for UI display")
    func testFindingDisplayFormatterFormatsFindingsForUI() {
        let formatter = FindingDisplayFormatter()
        let finding = Finding(
            severity: .critical,
            category: "credential",
            message: "An AWS access key was detected."
        )

        let output = formatter.format([finding])

        #expect(output == "[CRITICAL] credential: An AWS access key was detected.")
    }

    @Test("detects generic AWS secret-shaped tokens")
    func testAnalyzerDetectsGenericAWSSecretShape() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("AWS") == true)
    }

    @Test("detects GitHub personal access token patterns")
    func testAnalyzerDetectsGitHubToken() {
        let analyzer = Analyzer(rules: [GitHubTokenDetectionRule()])
        let content = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("GitHub") == true)
    }

    @Test("detects generic credential token formats")
    func testAnalyzerDetectsGenericCredential() {
        let analyzer = Analyzer(rules: [GenericCredentialDetectionRule()])
        let content = "sk" + "_live_" + "1234567890abcdefghijklmnopqrst"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
    }

    @Test("detects JWT token structure")
    func testAnalyzerDetectsJWT() {
        let analyzer = Analyzer(rules: [JWTDetectionRule()])
        let content = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .high)
    }

    @Test("detects high-entropy encoded payloads")
    func testAnalyzerDetectsEncodedPayload() {
        let analyzer = Analyzer(rules: [EncodedPayloadDetectionRule()])
        let content = String(repeating: "QUJD", count: 120)

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "encoded payload")
        #expect(findings.first?.severity == .high)
    }

    @Test("detects suspicious JavaScript execution patterns")
    func testAnalyzerDetectsMaliciousJavaScript() {
        let analyzer = Analyzer(rules: [MaliciousJavaScriptDetectionRule()])
        let content = "eval(atob('YWxlcnQoMSk='));"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "malicious script")
        #expect(findings.first?.severity == .high)
    }

    @Test("detects hidden text via zero-width characters")
    func testAnalyzerDetectsHiddenTextWithZeroWidthChars() {
        let analyzer = Analyzer(rules: [HiddenTextDetectionRule()])
        let content = "safe\u{200B}text"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "hidden text")
        #expect(findings.first?.severity == .high)
    }

    @Test("detects hidden text via bidirectional control characters")
    func testAnalyzerDetectsHiddenTextWithBidiControls() {
        let analyzer = Analyzer(rules: [HiddenTextDetectionRule()])
        let content = "abc\u{202E}txt"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "hidden text")
    }

    @Test("detects hidden text via abnormal control-character ratio")
    func testAnalyzerDetectsHiddenTextWithControlCharRatio() {
        let analyzer = Analyzer(rules: [HiddenTextDetectionRule()])
        let content = "ok\u{0001}\u{0002}\u{0003}\u{0004}stilltext"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "hidden text")
    }

    @Test("does not flag normal multiline text as hidden")
    func testAnalyzerDoesNotFlagNormalMultilineTextAsHidden() {
        let analyzer = Analyzer(rules: [HiddenTextDetectionRule()])
        let content = "line one\nline two\twith tab"

        let findings = analyzer.analyze(content)

        #expect(findings.isEmpty)
    }

    @Test("default detection rules include expanded local rule set")
    func testDefaultDetectionRulesIncludeExpandedLocalRules() {
        let analyzer = Analyzer(rules: defaultDetectionRules())
        let findings = analyzer.analyze("eval(atob('YWxlcnQoMSk='));")

        #expect(!findings.isEmpty)
        #expect(findings.contains(where: { $0.category == "malicious script" }))
    }
}
