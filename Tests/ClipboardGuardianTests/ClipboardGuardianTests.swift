import Testing
@testable import ClipboardGuardian

struct ClipboardGuardianTests {
    @Test
    func testAnalyzerWithNoRulesReturnsNoFindings() {
        let analyzer = Analyzer()

        let findings = analyzer.analyze("safe clipboard content")

        #expect(findings.isEmpty)
    }

    @Test
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

    @Test
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

    @Test
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

    @Test
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

    @Test
    func testAnalyzerDoesNotFlagNormalPrivateKeySentence() {
        let analyzer = Analyzer(rules: [PrivateKeyDetectionRule()])
        let content = "This sentence mentions a private key in a normal conversation."

        let findings = analyzer.analyze(content)

        #expect(findings.isEmpty)
    }

    @Test
    func testAnalyzerDetectsAWSAccessKeyID() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "AKIAIOSFODNN7EXAMPLE"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("AWS access key") == true)
    }

    @Test
    func testAnalyzerDetectsAWSSecretAccessKeyFormat() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "aws_secret_access_key = exampleSecretValue"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("AWS") == true)
    }

    @Test
    func testAnalyzerDoesNotFlagNormalAWSText() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "This text mentions AWS, access, and key in a normal sentence."

        let findings = analyzer.analyze(content)

        #expect(findings.isEmpty)
    }

    @Test
    func testAnalyzerDoesNotFlagRandomIdentifier() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "randomIdentifier123"

        let findings = analyzer.analyze(content)

        #expect(findings.isEmpty)
    }

    @Test
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

    @Test
    func testAnalyzerDetectsGenericAWSSecretShape() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("AWS") == true)
    }

    @Test
    func testAnalyzerDetectsGitHubToken() {
        let analyzer = Analyzer(rules: [GitHubTokenDetectionRule()])
        let content = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
        #expect(findings.first?.message.contains("GitHub") == true)
    }

    @Test
    func testAnalyzerDetectsGenericCredential() {
        let analyzer = Analyzer(rules: [GenericCredentialDetectionRule()])
        let content = "sk" + "_live_" + "1234567890abcdefghijklmnopqrst"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .critical)
    }

    @Test
    func testAnalyzerDetectsJWT() {
        let analyzer = Analyzer(rules: [JWTDetectionRule()])
        let content = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "credential")
        #expect(findings.first?.severity == .high)
    }

    @Test
    func testAnalyzerDetectsEncodedPayload() {
        let analyzer = Analyzer(rules: [EncodedPayloadDetectionRule()])
        let content = String(repeating: "QUJD", count: 120)

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "encoded payload")
        #expect(findings.first?.severity == .high)
    }

    @Test
    func testAnalyzerDetectsMaliciousJavaScript() {
        let analyzer = Analyzer(rules: [MaliciousJavaScriptDetectionRule()])
        let content = "eval(atob('YWxlcnQoMSk='));"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "malicious script")
        #expect(findings.first?.severity == .high)
    }

    @Test
    func testAnalyzerDetectsHiddenTextWithZeroWidthChars() {
        let analyzer = Analyzer(rules: [HiddenTextDetectionRule()])
        let content = "safe\u{200B}text"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "hidden text")
        #expect(findings.first?.severity == .high)
    }

    @Test
    func testAnalyzerDetectsHiddenTextWithBidiControls() {
        let analyzer = Analyzer(rules: [HiddenTextDetectionRule()])
        let content = "abc\u{202E}txt"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "hidden text")
    }

    @Test
    func testAnalyzerDetectsHiddenTextWithControlCharRatio() {
        let analyzer = Analyzer(rules: [HiddenTextDetectionRule()])
        let content = "ok\u{0001}\u{0002}\u{0003}\u{0004}stilltext"

        let findings = analyzer.analyze(content)

        #expect(findings.count == 1)
        #expect(findings.first?.category == "hidden text")
    }

    @Test
    func testAnalyzerDoesNotFlagNormalMultilineTextAsHidden() {
        let analyzer = Analyzer(rules: [HiddenTextDetectionRule()])
        let content = "line one\nline two\twith tab"

        let findings = analyzer.analyze(content)

        #expect(findings.isEmpty)
    }

    @Test
    func testDefaultDetectionRulesIncludeExpandedLocalRules() {
        let analyzer = Analyzer(rules: defaultDetectionRules())
        let findings = analyzer.analyze("eval(atob('YWxlcnQoMSk='));")

        #expect(!findings.isEmpty)
        #expect(findings.contains(where: { $0.category == "malicious script" }))
    }
}
