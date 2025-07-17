import * as vscode from 'vscode';

interface SecurityIssue {
    type: 'vulnerability' | 'error' | 'warning';
    severity: vscode.DiagnosticSeverity;
    message: string;
    description: string;
    range: vscode.Range;
    source: string;
    suggestion?: string;
    confidence: number;
    cveReference?: string;
}

interface AIAnalysisResult {
    issues: Array<{
        type: 'vulnerability' | 'error' | 'warning';
        severity: 'error' | 'warning' | 'info';
        message: string;
        description: string;
        suggestion: string;
        lineNumber: number;
        columnStart: number;
        columnEnd: number;
        confidence: number;
        cveReference?: string;
    }>;
    summary: string;
}

class AISecurityAnalyzer {
    private static readonly API_ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';
    private static analysisCache = new Map<string, { result: SecurityIssue[], timestamp: number }>();
    private static readonly CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
    
    private static getApiKey(): string | undefined {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        return config.get<string>('apiKey') || process.env.OPENAI_API_KEY;
    }

    private static createAnalysisPrompt(code: string, language: string): string {
        const languageSpecificFocus = this.getLanguageSpecificFocus(language);
        
        return `You are an expert code security analyzer with deep knowledge of ${language} security patterns and best practices. Perform a comprehensive security analysis of the provided code.

**ANALYSIS REQUIREMENTS:**
Return ONLY valid JSON in this exact format (no markdown, no explanations):
{
  "issues": [
    {
      "type": "vulnerability|error|warning",
      "severity": "error|warning|info", 
      "message": "Brief, specific issue description",
      "description": "Detailed technical explanation of the security risk and potential impact",
      "suggestion": "Concrete, implementable fix with code examples when possible",
      "lineNumber": number,
      "columnStart": number,
      "columnEnd": number,
      "confidence": number (60-100),
      "cveReference": "CVE-XXXX-XXXX or applicable security standard reference"
    }
  ],
  "summary": "Professional security assessment summary with risk level"
}

**SECURITY ANALYSIS FOCUS:**

**Universal Security Issues:**
1. SQL Injection (parameterized queries, ORM usage)
2. Cross-Site Scripting (XSS) - reflected, stored, DOM-based
3. Authentication bypasses and session management flaws
4. Authorization issues and privilege escalation
5. Input validation vulnerabilities (buffer overflows, format strings)
6. Cryptographic weaknesses (weak algorithms, poor key management)
7. Insecure deserialization and object injection
8. Path traversal and file inclusion vulnerabilities
9. Command injection and code execution flaws
10. Information disclosure through error messages/logs
11. Race conditions and time-of-check-time-of-use bugs
12. Business logic flaws and workflow bypasses
13. Hardcoded secrets, API keys, and credentials
14. Insecure network communications (HTTP vs HTTPS)
15. XML External Entity (XXE) injection
16. Server-Side Request Forgery (SSRF)
17. Insecure direct object references
18. Security misconfigurations

${languageSpecificFocus}

**CODE QUALITY & BEST PRACTICES:**
- Resource management (memory leaks, file handles)
- Error handling patterns and information leakage
- Logging security (sensitive data exposure)
- Dependency vulnerabilities and outdated packages
- Code complexity and maintainability issues
- Performance anti-patterns that could lead to DoS
- Threading and concurrency safety
- API design security (rate limiting, validation)

**SUGGESTION REQUIREMENTS:**
- Provide specific code examples in fixes
- Reference official documentation when applicable
- Include security library recommendations
- Mention relevant security standards (OWASP, CWE)
- Suggest automated tools for detection
- Include testing recommendations

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

Be thorough but precise. Focus on exploitable vulnerabilities and provide actionable remediation steps.`;
    }

    static async analyzeDocument(document: vscode.TextDocument): Promise<SecurityIssue[]> {
        try {
            const cacheKey = `${document.uri.toString()}_${document.version}`;
            const cached = this.analysisCache.get(cacheKey);
            
            // Check cache first
            if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
                return cached.result;
            }

            // Always run basic analysis for immediate feedback
            const basicIssues = this.runBasicAnalysis(document);
            
            // Only run AI analysis if API key is configured and file is not too large
            const apiKey = this.getApiKey();
            const code = document.getText();
            let aiIssues: SecurityIssue[] = [];
            
            if (apiKey && code.length <= 8000) {
                try {
                    aiIssues = await this.runAIAnalysis(document);
                } catch (error) {
                    console.error('AI analysis failed, using basic analysis only:', error);
                    // Don't show error to user, just use basic analysis
                }
            }
            
            // Combine and deduplicate results
            const result = this.combineAndDeduplicateIssues(basicIssues, aiIssues);
            
            // Cache the result
            this.analysisCache.set(cacheKey, { result, timestamp: Date.now() });
            
            return result;
        } catch (error) {
            console.error('Error in analysis:', error);
            // Always return basic analysis as fallback
            return this.runBasicAnalysis(document);
        }
    }

    private static runBasicAnalysis(document: vscode.TextDocument): SecurityIssue[] {
        const basicPatterns = [
            // SQL Injection patterns
            {
                pattern: /(?:query|execute|exec|prepare)\s*\(\s*['"`].*?\$\{.*?\}.*?['"`]/gi,
                type: 'vulnerability' as const,
                severity: vscode.DiagnosticSeverity.Error,
                message: 'SQL Injection vulnerability detected',
                description: 'String interpolation in SQL queries can lead to SQL injection attacks allowing attackers to manipulate database queries.',
                suggestion: 'Use parameterized queries, prepared statements, or ORM methods like: db.query("SELECT * FROM users WHERE id = ?", [userId])'
            },
            {
                pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?(\+|concat).*?(?:input|request|params|req\.)/gi,
                type: 'vulnerability' as const,
                severity: vscode.DiagnosticSeverity.Error,
                message: 'SQL injection risk through string concatenation',
                description: 'Concatenating user input directly into SQL queries creates injection vulnerabilities.',
                suggestion: 'Replace string concatenation with parameterized queries: db.execute("SELECT * FROM users WHERE name = %s", (username,))'
            },

            // XSS patterns
            {
                pattern: /innerHTML\s*=\s*(?:.*?\+.*?(?:input|request|params)|.*?(?:req\.|request\.)|.*?\$\{.*?\})/gi,
                type: 'vulnerability' as const,
                severity: vscode.DiagnosticSeverity.Error,
                message: 'Cross-Site Scripting (XSS) vulnerability',
                description: 'Setting innerHTML with unsanitized user input allows attackers to inject malicious scripts.',
                suggestion: 'Sanitize input with DOMPurify.sanitize() or use textContent instead: element.textContent = userInput'
            },
            {
                pattern: /document\.write\s*\(.*?(?:input|request|params)/gi,
                type: 'vulnerability' as const,
                severity: vscode.DiagnosticSeverity.Error,
                message: 'XSS vulnerability in document.write',
                description: 'Using document.write with user input can lead to script injection.',
                suggestion: 'Use DOM manipulation methods with proper sanitization instead of document.write'
            },

            // Hardcoded credentials
            {
                pattern: /(password|pwd|secret|token|key|api_key|apikey)\s*[:=]\s*['"`][^'"`\s]{8,}['"`]/gi,
                type: 'vulnerability' as const,
                severity: vscode.DiagnosticSeverity.Warning,
                message: 'Hardcoded credentials detected',
                description: 'Hardcoded passwords, tokens, or API keys in source code pose security risks and can be exposed in version control.',
                suggestion: 'Move sensitive data to environment variables: process.env.API_KEY or use secure configuration management tools like HashiCorp Vault'
            },

            // Dangerous functions
            {
                pattern: /\beval\s*\(/gi,
                type: 'vulnerability' as const,
                severity: vscode.DiagnosticSeverity.Error,
                message: 'Use of eval() function creates code injection risk',
                description: 'The eval() function can execute arbitrary code and is a major security vulnerability.',
                suggestion: 'Replace eval() with safer alternatives: JSON.parse() for data, Function constructor for controlled code execution, or use a proper parser'
            },

            // Insecure network communications
            {
                pattern: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi,
                type: 'warning' as const,
                severity: vscode.DiagnosticSeverity.Warning,
                message: 'Insecure HTTP protocol detected',
                description: 'Using HTTP instead of HTTPS exposes data to man-in-the-middle attacks and eavesdropping.',
                suggestion: 'Use HTTPS for all external communications: https://api.example.com'
            },

            // Weak cryptography
            {
                pattern: /(?:MD5|SHA1|DES|RC4)\s*\(/gi,
                type: 'warning' as const,
                severity: vscode.DiagnosticSeverity.Warning,
                message: 'Weak cryptographic algorithm detected',
                description: 'MD5, SHA1, DES, and RC4 are cryptographically broken and should not be used for security purposes.',
                suggestion: 'Use strong algorithms: SHA-256, SHA-3, AES-256, or bcrypt for password hashing'
            },

            // Insecure random
            {
                pattern: /Math\.random\(\)/gi,
                type: 'warning' as const,
                severity: vscode.DiagnosticSeverity.Information,
                message: 'Insecure random number generation',
                description: 'Math.random() is not cryptographically secure and predictable for security-sensitive operations.',
                suggestion: 'Use crypto.getRandomValues() for cryptographically secure randomness: crypto.getRandomValues(new Uint32Array(1))[0]'
            }
        ];

        const issues: SecurityIssue[] = [];
        const text = document.getText();
        const lines = text.split('\n');

        for (const pattern of basicPatterns) {
            let match;
            pattern.pattern.lastIndex = 0; // Reset regex
            
            while ((match = pattern.pattern.exec(text)) !== null) {
                const startPos = document.positionAt(match.index);
                const endPos = document.positionAt(match.index + match[0].length);
                const range = new vscode.Range(startPos, endPos);

                // Skip if line is a comment
                const lineText = lines[startPos.line];
                if (lineText.trim().startsWith('//') || lineText.trim().startsWith('/*') || lineText.trim().startsWith('*')) {
                    continue;
                }

                issues.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    message: pattern.message,
                    description: pattern.description,
                    suggestion: pattern.suggestion,
                    range,
                    source: 'Basic Pattern Analysis',
                    confidence: 75
                });
            }
        }

        return issues;
    }

    private static async runAIAnalysis(document: vscode.TextDocument): Promise<SecurityIssue[]> {
        const apiKey = this.getApiKey();
        if (!apiKey) {
            return [];
        }

        const code = document.getText();
        const language = document.languageId;
        
        // Skip AI analysis for very large files
        if (code.length > 8000) {
            return [];
        }

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

            const response = await fetch(this.API_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify({
                    model: 'deepseek/deepseek-chat-v3-0324:free',
                    messages: [
                        {
                            role: 'system',
                            content: 'You are an expert code security analyzer. Provide precise, actionable security analysis in the specified JSON format.'
                        },
                        {
                            role: 'user',
                            content: this.createAnalysisPrompt(code, language)
                        }
                    ],
                    temperature: 0.1,
                    max_tokens: 2000
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`API request failed: ${response.status} ${response.statusText}`);
            }

            const data = await response.json() as any;
            const content = data.choices?.[0]?.message?.content;
            
            if (!content) {
                throw new Error('Invalid API response format');
            }
            
            // Clean the response and try to parse JSON
            const cleanContent = content.replace(/```json|```/g, '').trim();
            const aiResult: AIAnalysisResult = JSON.parse(cleanContent);
            
            // Convert AI results to SecurityIssue format
            const issues: SecurityIssue[] = aiResult.issues.map(issue => {
                const line = Math.max(0, Math.min(issue.lineNumber - 1, document.lineCount - 1));
                const lineText = document.lineAt(line).text;
                const startCol = Math.max(0, Math.min(issue.columnStart, lineText.length));
                const endCol = Math.max(startCol, Math.min(issue.columnEnd, lineText.length));
                
                const startPos = new vscode.Position(line, startCol);
                const endPos = new vscode.Position(line, endCol);
                const range = new vscode.Range(startPos, endPos);

                const severity = issue.severity === 'error' ? vscode.DiagnosticSeverity.Error :
                                issue.severity === 'warning' ? vscode.DiagnosticSeverity.Warning :
                                vscode.DiagnosticSeverity.Information;

                return {
                    type: issue.type,
                    severity,
                    message: issue.message,
                    description: issue.description,
                    suggestion: issue.suggestion,
                    range,
                    source: 'AI Security Analysis',
                    confidence: issue.confidence,
                    cveReference: issue.cveReference
                };
            });

            return issues;
        } catch (error) {
            console.error('AI analysis failed:', error);
            throw error;
        }
    }

    private static combineAndDeduplicateIssues(basicIssues: SecurityIssue[], aiIssues: SecurityIssue[]): SecurityIssue[] {
        const allIssues = [...basicIssues, ...aiIssues];
        const deduplicatedIssues: SecurityIssue[] = [];

        for (const issue of allIssues) {
            // Check if this issue is similar to an existing one
            const isDuplicate = deduplicatedIssues.some(existing => 
                existing.range.intersection(issue.range) &&
                existing.type === issue.type &&
                this.isSimilarMessage(existing.message, issue.message)
            );

            if (!isDuplicate) {
                deduplicatedIssues.push(issue);
            } else {
                // If duplicate, keep the one with higher confidence
                const existingIndex = deduplicatedIssues.findIndex(existing => 
                    existing.range.intersection(issue.range) &&
                    existing.type === issue.type &&
                    this.isSimilarMessage(existing.message, issue.message)
                );
                
                if (existingIndex !== -1 && issue.confidence > deduplicatedIssues[existingIndex].confidence) {
                    deduplicatedIssues[existingIndex] = issue;
                }
            }
        }

        return deduplicatedIssues;
    }

    private static isSimilarMessage(msg1: string, msg2: string): boolean {
        const normalize = (msg: string) => msg.toLowerCase().replace(/[^a-z0-9]/g, '');
        const norm1 = normalize(msg1);
        const norm2 = normalize(msg2);
        
        return norm1.includes(norm2.substring(0, Math.min(norm2.length, 10))) ||
               norm2.includes(norm1.substring(0, Math.min(norm1.length, 10)));
    }

    private static getLanguageSpecificFocus(language: string): string {
        const languageFocus: Record<string, string> = {
            'javascript': `
**JavaScript/Node.js Specific Issues:**
- Prototype pollution attacks
- Event loop blocking and DoS vulnerabilities
- NPM package security (malicious dependencies)
- Client-side template injection
- Insecure regular expressions (ReDoS)
- Improper error handling exposing stack traces
- Insecure cookie settings (httpOnly, secure, sameSite)
- CSRF vulnerabilities in Express apps
- JWT implementation flaws
- Insecure direct eval() or Function() usage`,

            'typescript': `
**TypeScript Specific Issues:**
- Type assertion bypassing security checks (as any)
- Unsafe type guards
- Missing strict null checks
- Improper use of unknown vs any types
- Type pollution in generic functions`,

            'python': `
**Python Specific Issues:**
- Pickle deserialization vulnerabilities
- YAML/XML unsafe loading
- Path traversal with os.path.join
- SQL injection in raw queries
- Command injection via subprocess
- Template injection in Jinja2/Django
- Insecure random number generation
- Django/Flask security misconfigurations
- Regex DoS (catastrophic backtracking)`,

            'java': `
**Java Specific Issues:**
- Deserialization vulnerabilities (readObject)
- XML External Entity (XXE) attacks
- Path traversal vulnerabilities
- LDAP injection
- Weak cryptographic algorithms
- Insecure random number generation
- SQL injection in JDBC
- Session fixation attacks
- Unsafe reflection usage`
        };

        return languageFocus[language] || languageFocus['javascript'];
    }
}

class SecurityCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

    async provideCodeLenses(document: vscode.TextDocument): Promise<vscode.CodeLens[]> {
        try {
            const issues = await AISecurityAnalyzer.analyzeDocument(document);
            const codeLenses: vscode.CodeLens[] = [];

            for (const issue of issues) {
                const confidence = issue.confidence >= 80 ? '🟢' : 
                                  issue.confidence >= 60 ? '🟡' : '🟠';
                
                const lens = new vscode.CodeLens(issue.range, {
                    title: `${confidence} 🔍 ${issue.message}`,
                    command: 'codeSecurityAnalyzer.showIssueDetails',
                    arguments: [issue]
                });
                codeLenses.push(lens);
            }

            return codeLenses;
        } catch (error) {
            console.error('Error providing code lenses:', error);
            return [];
        }
    }

    public refresh(): void {
        this._onDidChangeCodeLenses.fire();
    }
}

class SecurityHoverProvider implements vscode.HoverProvider {
    async provideHover(document: vscode.TextDocument, position: vscode.Position): Promise<vscode.Hover | undefined> {
        try {
            const issues = await AISecurityAnalyzer.analyzeDocument(document);
            
            for (const issue of issues) {
                if (issue.range.contains(position)) {
                    const severity = issue.severity === vscode.DiagnosticSeverity.Error ? '🚨' : 
                                    issue.severity === vscode.DiagnosticSeverity.Warning ? '⚠️' : 'ℹ️';
                    
                    const confidence = issue.confidence >= 80 ? '🟢 High' : 
                                      issue.confidence >= 60 ? '🟡 Medium' : '🟠 Low';
                    
                    const markdown = new vscode.MarkdownString();
                    markdown.appendMarkdown(`${severity} **${issue.message}**\n\n`);
                    markdown.appendMarkdown(`**Description:** ${issue.description}\n\n`);
                    
                    if (issue.suggestion) {
                        markdown.appendMarkdown(`**💡 Suggestion:** ${issue.suggestion}\n\n`);
                    }
                    
                    markdown.appendMarkdown(`**Confidence:** ${confidence} (${issue.confidence}%)\n\n`);
                    markdown.appendMarkdown(`*Source: ${issue.source}*`);
                    
                    return new vscode.Hover(markdown, issue.range);
                }
            }
        } catch (error) {
            console.error('Error providing hover:', error);
        }
        
        return undefined;
    }
}

// Global timeout reference
let analysisTimeout: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext) {
    console.log('Code Security Analyzer is now active!');

    // Create diagnostic collection
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('codeSecurityAnalyzer');
    context.subscriptions.push(diagnosticCollection);

    // Create providers
    const codeLensProvider = new SecurityCodeLensProvider();
    const hoverProvider = new SecurityHoverProvider();

    // Register providers for multiple languages
    const languageSelectors = [
        'javascript',
        'typescript', 
        'python',
        'java',
        'csharp',
        'php',
        'go',
        'rust',
        'cpp',
        'c'
    ];

    for (const language of languageSelectors) {
        context.subscriptions.push(
            vscode.languages.registerCodeLensProvider(language, codeLensProvider)
        );
        context.subscriptions.push(
            vscode.languages.registerHoverProvider(language, hoverProvider)
        );
    }

    // Function to analyze and update diagnostics
    const analyzeDocument = async (document: vscode.TextDocument) => {
        try {
            // Show progress for user feedback
            const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
            statusBarItem.text = "$(sync~spin) Analyzing security...";
            statusBarItem.show();

            const issues = await AISecurityAnalyzer.analyzeDocument(document);
            
            const diagnostics: vscode.Diagnostic[] = issues.map((issue: SecurityIssue) => {
                const diagnostic = new vscode.Diagnostic(
                    issue.range,
                    issue.message,
                    issue.severity
                );
                diagnostic.source = issue.source;
                return diagnostic;
            });
            
            diagnosticCollection.set(document.uri, diagnostics);
            codeLensProvider.refresh();
            
            statusBarItem.text = `$(check) Security analysis complete (${issues.length} issues found)`;
            setTimeout(() => statusBarItem.dispose(), 3000);
            
        } catch (error) {
            console.error('Analysis failed:', error);
            vscode.window.showErrorMessage(`Security analysis failed: ${error}`);
        }
    };

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.analyzeActiveFile', async () => {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor) {
                await analyzeDocument(activeEditor.document);
                vscode.window.showInformationMessage(
                    `Security analysis completed for ${activeEditor.document.fileName}`
                );
            } else {
                vscode.window.showWarningMessage('No active file to analyze');
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.showIssueDetails', (issue: SecurityIssue) => {
            const panel = vscode.window.createWebviewPanel(
                'securityIssueDetails',
                'Security Issue Details',
                vscode.ViewColumn.Beside,
                {
                    enableScripts: true
                }
            );

            const severity = issue.severity === vscode.DiagnosticSeverity.Error ? 'Error' : 
                            issue.severity === vscode.DiagnosticSeverity.Warning ? 'Warning' : 'Info';
            
            const confidence = issue.confidence >= 80 ? 'High' : 
                              issue.confidence >= 60 ? 'Medium' : 'Low';
            
            panel.webview.html = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Security Issue Details</title>
                    <style>
                        body { 
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                            padding: 20px; 
                            background-color: var(--vscode-editor-background);
                            color: var(--vscode-editor-foreground);
                        }
                        .header { 
                            border-bottom: 1px solid var(--vscode-panel-border); 
                            padding-bottom: 15px; 
                            margin-bottom: 20px; 
                        }
                        .severity { 
                            font-weight: bold; 
                            padding: 5px 10px; 
                            border-radius: 3px; 
                            display: inline-block; 
                            margin-right: 10px;
                        }
                        .error { background-color: #f8d7da; color: #721c24; }
                        .warning { background-color: #fff3cd; color: #856404; }
                        .info { background-color: #d1ecf1; color: #0c5460; }
                        .confidence {
                            font-size: 0.9em;
                            padding: 3px 8px;
                            border-radius: 3px;
                            background-color: var(--vscode-badge-background);
                            color: var(--vscode-badge-foreground);
                        }
                        .section { margin-bottom: 20px; }
                        .section h3 { 
                            color: var(--vscode-foreground); 
                            margin-bottom: 10px;
                            font-size: 1.1em;
                        }
                        .description, .suggestion { 
                            line-height: 1.6; 
                            background-color: var(--vscode-textBlockQuote-background);
                            padding: 15px;
                            border-left: 4px solid var(--vscode-textBlockQuote-border);
                            border-radius: 4px;
                        }
                        .suggestion {
                            border-left-color: #28a745;
                        }
                        .suggestion::before {
                            content: "💡 ";
                            font-size: 1.2em;
                        }
                        .cve-reference {
                            background-color: var(--vscode-textBlockQuote-background);
                            padding: 15px;
                            border-left: 4px solid #007acc;
                            border-radius: 4px;
                        }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h2>${issue.message}</h2>
                        <span class="severity ${severity.toLowerCase()}">${severity}</span>
                        <span class="confidence">Confidence: ${confidence} (${issue.confidence}%)</span>
                    </div>
                    
                    <div class="section">
                        <h3>Description</h3>
                        <div class="description">${issue.description}</div>
                    </div>
                    
                    ${issue.suggestion ? `
                    <div class="section">
                        <h3>💡 Recommended Solution</h3>
                        <div class="suggestion">${issue.suggestion}</div>
                    </div>
                    ` : ''}
                    
                    ${issue.cveReference ? `
                    <div class="section">
                        <h3>🔗 Security Reference</h3>
                        <div class="cve-reference">
                            <strong>${issue.cveReference}</strong>
                        </div>
                    </div>
                    ` : ''}
                </body>
                </html>
            `;
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.configureApiKey', async () => {
            const apiKey = await vscode.window.showInputBox({
                prompt: 'Enter your OpenAI API key',
                password: true,
                placeHolder: 'sk-...'
            });
            
            if (apiKey) {
                await vscode.workspace.getConfiguration('codeSecurityAnalyzer').update('apiKey', apiKey, vscode.ConfigurationTarget.Global);
                vscode.window.showInformationMessage('API key configured successfully!');
            }
        })
    );

    // Analyze active document on activation (but don't block activation)
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor) {
        // Run analysis in background without blocking extension activation
        setTimeout(() => {
            analyzeDocument(activeEditor.document);
        }, 1000);
    }

    // Listen for document changes with debouncing
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            if (vscode.window.activeTextEditor?.document === event.document) {
                // Clear existing timeout
                if (analysisTimeout) {
                    clearTimeout(analysisTimeout);
                }
                
                // Set new timeout for analysis
                analysisTimeout = setTimeout(() => {
                    analyzeDocument(event.document);
                }, 3000); // Wait 3 seconds after last change
            }
        })
    );

    // Listen for active editor changes
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) {
                // Clear existing timeout
                if (analysisTimeout) {
                    clearTimeout(analysisTimeout);
                }
                
                // Analyze after short delay
                analysisTimeout = setTimeout(() => {
                    analyzeDocument(editor.document);
                }, 500);
            }
        })
    );
}

export function deactivate() {
    // Clear any pending analysis timeout
    if (analysisTimeout) {
        clearTimeout(analysisTimeout);
    }
}