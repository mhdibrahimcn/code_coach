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
			// First, run basic pattern-based analysis for immediate feedback
			const basicIssues = this.runBasicAnalysis(document);
			
			// Then run AI analysis for more sophisticated detection
			const aiIssues = await this.runAIAnalysis(document);
			
			// Combine and deduplicate results
			return this.combineAndDeduplicateIssues(basicIssues, aiIssues);
		} catch (error) {
			console.error('Error in AI analysis:', error);
			// Fallback to basic analysis if AI fails
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
			{
				pattern: /new\s+Function\s*\(.*?(?:input|request|params)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'Dynamic function creation with user input',
				description: 'Creating functions with user input can lead to code injection attacks.',
				suggestion: 'Avoid dynamic function creation with user input. Use predefined functions or safe parsing methods'
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
			{
				pattern: /Math\.random\(\)/gi,
				type: 'warning' as const,
				severity: vscode.DiagnosticSeverity.Information,
				message: 'Insecure random number generation',
				description: 'Math.random() is not cryptographically secure and predictable for security-sensitive operations.',
				suggestion: 'Use crypto.getRandomValues() for cryptographically secure randomness: crypto.getRandomValues(new Uint32Array(1))[0]'
			},

			// File system vulnerabilities
			{
				pattern: /(?:readFile|writeFile|open)\s*\(.*?(?:\+|concat).*?(?:input|request|params)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'Path traversal vulnerability',
				description: 'Concatenating user input to file paths can allow attackers to access unauthorized files.',
				suggestion: 'Validate and sanitize file paths, use path.resolve() and check if result is within allowed directory'
			},

			// Command injection
			{
				pattern: /(?:exec|spawn|system)\s*\(.*?(?:\+|concat|\$\{).*?(?:input|request|params)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'Command injection vulnerability',
				description: 'Executing system commands with user input can allow attackers to run arbitrary commands.',
				suggestion: 'Use parameterized command execution or validate input against a whitelist of allowed values'
			},

			// Insecure deserialization
			{
				pattern: /(?:pickle\.loads|yaml\.load|JSON\.parse).*?(?:input|request|params)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Potentially unsafe deserialization',
				description: 'Deserializing untrusted data can lead to code execution or other attacks.',
				suggestion: 'Use safe deserialization methods: yaml.safe_load(), validate input schema, or use trusted data sources only'
			},

			// Information disclosure
			{
				pattern: /console\.log\s*\(.*?(?:password|secret|token|key)/gi,
				type: 'warning' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Sensitive information in logs',
				description: 'Logging sensitive information can lead to data exposure in log files.',
				suggestion: 'Remove sensitive data from logs or use structured logging with field redaction'
			},

			// Unsafe redirects
			{
				pattern: /(?:redirect|location\.href|window\.location)\s*=.*?(?:input|request|params)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Open redirect vulnerability',
				description: 'Redirecting to user-controlled URLs can be used in phishing attacks.',
				suggestion: 'Validate redirect URLs against a whitelist of allowed domains or use relative URLs only'
			}
		];

		const issues: SecurityIssue[] = [];
		const text = document.getText();

		for (const pattern of basicPatterns) {
			let match;
			while ((match = pattern.pattern.exec(text)) !== null) {
				const startPos = document.positionAt(match.index);
				const endPos = document.positionAt(match.index + match[0].length);
				const range = new vscode.Range(startPos, endPos);

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
			pattern.pattern.lastIndex = 0;
		}

		return issues;
	}

	private static async runAIAnalysis(document: vscode.TextDocument): Promise<SecurityIssue[]> {
		const apiKey = this.getApiKey();
		if (!apiKey) {
			vscode.window.showWarningMessage('OpenAI API key not configured. Using basic analysis only.');
			return [];
		}

		const code = document.getText();
		const language = document.languageId;
		
		// Skip AI analysis for very large files to avoid API limits
		if (code.length > 8000) {
			vscode.window.showInformationMessage('File too large for AI analysis. Using basic analysis only.');
			return [];
		}

		try {
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
				})
			});

			if (!response.ok) {
				throw new Error(`API request failed: ${response.statusText}`);
			}

			const data = await response.json() as any;
			const content = data.choices?.[0]?.message?.content;
			
			if (!content) {
				throw new Error('Invalid API response format');
			}
			
			// Parse the JSON response
			const aiResult: AIAnalysisResult = JSON.parse(content);
			
			// Convert AI results to SecurityIssue format
			const issues: SecurityIssue[] = aiResult.issues.map(issue => {
				const line = Math.max(0, issue.lineNumber - 1);
				const startPos = new vscode.Position(line, issue.columnStart);
				const endPos = new vscode.Position(line, issue.columnEnd);
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
			vscode.window.showErrorMessage(`AI analysis failed: ${error}`);
			return [];
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
		
		// Simple similarity check - could be improved with more sophisticated algorithms
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
- Insecure direct eval() or Function() usage

**Best Practices:**
- Use helmet.js for security headers
- Implement proper CORS policies
- Use bcrypt for password hashing
- Validate input with joi or similar libraries
- Use ESLint security rules
- Implement rate limiting with express-rate-limit`,

			'typescript': `
**TypeScript Specific Issues:**
- Type assertion bypassing security checks (as any)
- Unsafe type guards
- Missing strict null checks
- Improper use of unknown vs any types
- Type pollution in generic functions

**Best Practices:**
- Enable strict mode in tsconfig.json
- Use branded types for sensitive data
- Implement proper type guards
- Use readonly modifiers for immutable data
- Avoid type assertions with any`,

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
- Regex DoS (catastrophic backtracking)

**Best Practices:**
- Use parameterized queries with SQLAlchemy/Django ORM
- Validate input with marshmallow or pydantic
- Use secrets module for cryptographic randomness
- Implement proper logging without sensitive data
- Use bandit for security linting
- Follow OWASP Python security guidelines`,

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
- Unsafe reflection usage

**Best Practices:**
- Use PreparedStatement for database queries
- Implement proper exception handling
- Use SecureRandom for cryptographic operations
- Validate input with JSR-303/Bean Validation
- Use OWASP Java Encoder for output encoding
- Implement CSRF protection in Spring`,

			'csharp': `
**C# Specific Issues:**
- SQL injection in Entity Framework raw queries
- XXE vulnerabilities in XML parsing
- Insecure deserialization
- Path traversal vulnerabilities
- Weak encryption implementations
- Missing input validation
- Improper exception handling
- LDAP injection vulnerabilities

**Best Practices:**
- Use parameterized queries with Entity Framework
- Implement proper input validation with Data Annotations
- Use System.Security.Cryptography for encryption
- Follow OWASP .NET security guidelines
- Use security analysis tools like SonarQube`,

			'php': `
**PHP Specific Issues:**
- SQL injection vulnerabilities
- File inclusion vulnerabilities (LFI/RFI)
- PHP object injection
- Command injection
- Cross-site scripting (XSS)
- Session hijacking
- Insecure file uploads
- Directory traversal
- Weak password hashing

**Best Practices:**
- Use PDO with prepared statements
- Validate and sanitize all input
- Use password_hash() for password storage
- Implement proper session management
- Use HTTPS for all sensitive operations
- Keep PHP version updated`,

			'go': `
**Go Specific Issues:**
- SQL injection in database/sql
- Command injection via exec.Command
- Path traversal vulnerabilities
- Improper error handling exposing information
- Race conditions in goroutines
- Insecure random number generation
- Template injection vulnerabilities

**Best Practices:**
- Use parameterized queries
- Validate input with validator libraries
- Use crypto/rand for secure randomness
- Implement proper mutex usage for concurrency
- Use gosec for security analysis
- Follow Go security best practices`,

			'rust': `
**Rust Specific Issues:**
- Unsafe code blocks bypassing memory safety
- Integer overflow vulnerabilities
- Improper use of unsafe transmute
- Race conditions in unsafe code
- Buffer overflow in unsafe operations

**Best Practices:**
- Minimize use of unsafe code
- Use checked arithmetic operations
- Implement proper error handling with Result<T, E>
- Use cargo-audit for dependency vulnerabilities
- Follow Rust security guidelines`,

			'cpp': `
**C++ Specific Issues:**
- Buffer overflow vulnerabilities
- Use-after-free vulnerabilities
- Memory leaks and double-free errors
- Integer overflow/underflow
- Format string vulnerabilities
- Race conditions in multithreaded code
- Null pointer dereferences

**Best Practices:**
- Use smart pointers (unique_ptr, shared_ptr)
- Implement RAII for resource management
- Use bounds-checking containers
- Enable compiler security flags (-fstack-protector)
- Use static analysis tools like Clang Static Analyzer`,

			'c': `
**C Specific Issues:**
- Buffer overflow vulnerabilities
- Format string vulnerabilities
- Use-after-free and double-free errors
- Integer overflow/underflow
- Null pointer dereferences
- Memory leaks
- Race conditions

**Best Practices:**
- Use secure string functions (strncpy, strncat)
- Implement proper bounds checking
- Use valgrind for memory debugging
- Enable compiler security flags
- Follow CERT C secure coding standards`
		};

		return languageFocus[language] || languageFocus['javascript']; // fallback to JavaScript
	}
}

class SecurityCodeLensProvider implements vscode.CodeLensProvider {
	private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
	public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

	async provideCodeLenses(document: vscode.TextDocument): Promise<vscode.CodeLens[]> {
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
	}

	public refresh(): void {
		this._onDidChangeCodeLenses.fire();
	}
}

class SecurityHoverProvider implements vscode.HoverProvider {
	async provideHover(document: vscode.TextDocument, position: vscode.Position): Promise<vscode.Hover | undefined> {
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
		
		return undefined;
	}
}

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
			vscode.window.withProgress({
				location: vscode.ProgressLocation.Window,
				title: "Analyzing code security...",
				cancellable: false
			}, async (progress) => {
				progress.report({ increment: 0 });
				
				const issues = await AISecurityAnalyzer.analyzeDocument(document);
				
				progress.report({ increment: 50 });
				
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
				
				progress.report({ increment: 100 });
			});
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
						.cve-reference a {
							color: var(--vscode-textLink-foreground);
							text-decoration: none;
						}
						.cve-reference a:hover {
							text-decoration: underline;
						}
						.analysis-details {
							background-color: var(--vscode-editor-inactiveSelectionBackground);
							padding: 10px;
							border-radius: 4px;
							font-size: 0.9em;
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
							<br>
							<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${issue.cveReference}" target="_blank">
								View CVE Details
							</a>
						</div>
					</div>
					` : ''}
					
					<div class="section">
						<h3>📊 Analysis Details</h3>
						<div class="analysis-details">
							<p><strong>Source:</strong> ${issue.source}</p>
							<p><strong>Confidence:</strong> ${confidence} (${issue.confidence}%)</p>
							<p><strong>Type:</strong> ${issue.type.charAt(0).toUpperCase() + issue.type.slice(1)}</p>
						</div>
					</div>
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

	// Analyze active document on activation
	const activeEditor = vscode.window.activeTextEditor;
	if (activeEditor) {
		analyzeDocument(activeEditor.document);
	}

	// Listen for document changes
	context.subscriptions.push(
		vscode.workspace.onDidChangeTextDocument(event => {
			if (vscode.window.activeTextEditor?.document === event.document) {
				// Debounce analysis to avoid too frequent API calls
				clearTimeout((global as any).analysisTimeout);
				(global as any).analysisTimeout = setTimeout(() => {
					analyzeDocument(event.document);
				}, 2000); // Wait 2 seconds after last change
			}
		})
	);

	// Listen for active editor changes
	context.subscriptions.push(
		vscode.window.onDidChangeActiveTextEditor(editor => {
			if (editor) {
				analyzeDocument(editor.document);
			}
		})
	);
}

export function deactivate() {}
