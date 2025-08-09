import * as vscode from 'vscode';
import { BestPracticesAnalyzer } from './BestPracticesAnalyzer.1';
import { ComplexityAnalyzer } from './ComplexityAnalyzer.1';
import { AIAnalysisResult, AIFixSuggestion } from './extension';
import { SecurityIssue } from './SecurityIssue';

export class AISecurityAnalyzer {
	private static readonly API_ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';
	private static analysisCache = new Map<string, { result: SecurityIssue[]; timestamp: number; }>();
	private static fixSuggestionCache = new Map<string, { suggestion: AIFixSuggestion; timestamp: number; }>();
	private static readonly CACHE_DURATION = 10 * 60 * 1000; // 10 minutes

	private static generateContentHash(content: string): string {
		// Simple hash function for content-based caching
		let hash = 0;
		for (let i = 0; i < content.length; i++) {
			const char = content.charCodeAt(i);
			hash = ((hash << 5) - hash) + char;
			hash = hash & hash; // Convert to 32-bit integer
		}
		return Math.abs(hash).toString(36);
	}

	private static fixJsonEscaping(jsonString: string): string {
		// Fix common JSON escaping issues that cause parse errors
		try {
			// Replace problematic escape sequences
			return jsonString
				// Fix backslash escaping issues
				.replace(/\\(?!["\\/bfnrt])/g, '\\\\')
				// Fix unescaped quotes in strings
				.replace(/(?<!\\)"/g, (match, offset, string) => {
					// Check if this quote is inside a string value
					const beforeQuote = string.substring(0, offset);
					const colonCount = (beforeQuote.match(/:/g) || []).length;
					const quoteCount = (beforeQuote.match(/"/g) || []).length;
					
					// If we have more quotes than colons*2, this might be an unescaped quote
					if (quoteCount > colonCount * 2) {
						return '\\"';
					}
					return match;
				})
				// Fix trailing commas
				.replace(/,(\s*[}\]])/g, '$1')
				// Fix control characters
				.replace(/[\x00-\x1F\x7F]/g, (match) => {
					const controlChars: Record<string, string> = {
						'\b': '\\b',
						'\f': '\\f',
						'\n': '\\n',
						'\r': '\\r',
						'\t': '\\t'
					};
					return controlChars[match] || '';
				});
		} catch (error) {
			console.warn('Error fixing JSON escaping:', error);
			return jsonString;
		}
	}

	private static getApiKey(): string | undefined {
		const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
		const configKey = config.get<string>('apiKey');
		const envKey = process.env.OPENAI_API_KEY;
		const fallbackKey = "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";
		// const finalKey = configKey || envKey || fallbackKey;
		const finalKey =  fallbackKey;
		
		console.log('🔑 AISecurityAnalyzer API Key Status:');
		console.log(`   Config Key: ${configKey ? '✅ Present' : '❌ Missing'}`);
		console.log(`   Env Key: ${envKey ? '✅ Present' : '❌ Missing'}`);
		console.log(`   Fallback Key: ${fallbackKey ? '✅ Available' : '❌ Missing'}`);
		console.log(`   Final Key: ${finalKey ? '✅ Using key ending in ...${finalKey.slice(-10)}' : '❌ No key available'}`);
		
		return "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";
	}

	private static async makeAPIRequest(requestOptions: any): Promise<any> {
		try {
			console.log('🚀 Making API request to OpenRouter...');
			
			const response = await fetch(this.API_ENDPOINT, requestOptions);

			console.log(`📡 API Response Status: ${response.status} ${response.statusText}`);

			if (!response.ok) {
				const errorText = await response.text();
				console.error(`❌ API Error Response: ${errorText}`);
				throw new Error(`API request failed: ${response.status} ${response.statusText} - ${errorText}`);
			}

			const data = await response.json();
			console.log('✅ API request successful');
			return data;
		} catch (error) {
			console.error('❌ API request failed:', error);
			throw error;
		}
	}

	private static createAnalysisPrompt(code: string, language: string): string {
		const languageSpecificFocus = this.getLanguageSpecificFocus(language);

		return `You are an expert code security analyzer with deep knowledge of ${language} security patterns and best practices. Perform a comprehensive security analysis of the provided code.

**ANALYSIS REQUIREMENTS:**
Return ONLY valid JSON in this exact format (no markdown, no explanations):
{
  "issues": [
	{
	  "type": "vulnerability|error|warning|complexity|best-practice",
	  "severity": "error|warning|info", 
	  "message": "Brief, specific issue description",
	  "description": "Detailed technical explanation of the security risk and potential impact",
	  "suggestion": "Concrete, implementable fix with code examples when possible",
	  "lineNumber": number,
	  "columnStart": number,
	  "columnEnd": number,
	  "confidence": number (60-100),
	  "cveReference": "CVE-XXXX-XXXX or applicable security standard reference",
	  "complexityScore": number (optional, for complexity issues),
	  "functionName": "function name (optional, for function-specific issues)"
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

**CODE COMPLEXITY & BEST PRACTICES:**
- Function complexity (cyclomatic, cognitive)
- Function length and parameter count
- Nesting levels and code readability
- Magic numbers and hardcoded values
- Error handling patterns
- Code duplication
- Naming conventions
- Comment quality and TODO items
- Resource management (memory leaks, file handles)
- Performance anti-patterns that could lead to DoS
- Threading and concurrency safety
- API design security (rate limiting, validation)

${languageSpecificFocus}

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

Be thorough but precise. Focus on exploitable vulnerabilities, code complexity issues, and best practice violations. Provide actionable remediation steps.`;
	}

	static async analyzeDocument(document: vscode.TextDocument, progressCallback?: (message: string, tooltip?: string) => void): Promise<SecurityIssue[]> {
		try {
			const cacheKey = `${document.uri.toString()}_${document.version}`;
			const cached = this.analysisCache.get(cacheKey);

			// Check cache first with improved hit rate
			if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
				progressCallback?.("$(check) Analysis loaded from cache", "Using cached results for faster performance");
				console.log('📦 Using cached analysis results');
				return cached.result;
			}

			// Check for similar file cache (content-based caching)
			const docContentHash = this.generateContentHash(document.getText());
			const docContentCacheKey = `content_${docContentHash}_${document.languageId}`;
			const docContentCached = this.analysisCache.get(docContentCacheKey);
			
			if (docContentCached && Date.now() - docContentCached.timestamp < this.CACHE_DURATION) {
				progressCallback?.("$(check) Analysis loaded from content cache", "Using cached results based on file content");
				console.log('📦 Using content-based cached analysis results');
				return docContentCached.result;
			}

			console.log('🔄 Starting fresh analysis...');
			progressCallback?.("$(sync~spin) Starting complexity analysis...", "Analyzing function complexity and code structure");
			
			// Run complexity analysis
			const functions = ComplexityAnalyzer.analyzeFunctions(document);
			const complexityIssues = ComplexityAnalyzer.generateComplexityIssues(functions);
			console.log(`📊 Complexity analysis found ${complexityIssues.length} issues`);

			progressCallback?.("$(sync~spin) Running best practices analysis...", "Checking coding standards and best practices");
			// Run best practices analysis
			const bestPracticesIssues = BestPracticesAnalyzer.analyzeBestPractices(document);
			console.log(`📋 Best practices analysis found ${bestPracticesIssues.length} issues`);

			// AI-first approach with basic analysis fallback
			const codeLength = document.getText().length;
			let aiIssues: SecurityIssue[] = [];
			let basicIssues: SecurityIssue[] = [];

			console.log(`📏 File metrics: ${document.lineCount} lines, ${codeLength} characters`);

			const apiKey = this.getApiKey();
			if (apiKey) {
				console.log('🤖 AI analysis is AVAILABLE - proceeding with AI-first approach');
				
				try {
					// Try AI analysis first
					progressCallback?.("$(sparkle) Running AI security analysis...", "Full code AI-powered vulnerability detection in progress");
					console.log('🔍 Running full code AI analysis...');
					aiIssues = await this.runAIAnalysis(document);
					console.log(`✅ AI analysis SUCCESS: Found ${aiIssues.length} issues`);
					progressCallback?.("$(sparkle) AI analysis complete", "Advanced AI security scan finished successfully");
				} catch (error) {
					console.error('❌ AI analysis failed, falling back to basic analysis:', error);
					progressCallback?.("$(warning) AI failed, running basic analysis...", "Falling back to pattern-based detection");
					// Fallback to basic analysis only if AI fails
					basicIssues = this.runBasicAnalysis(document);
					console.log(`⚠️ Basic analysis fallback: Found ${basicIssues.length} issues`);
				}
			} else {
				// No API key available - use basic analysis as fallback
				console.log('❌ AI analysis NOT AVAILABLE - no API key found, using basic patterns');
				progressCallback?.("$(search) Running basic pattern analysis", "No AI key configured - using pattern matching");
				basicIssues = this.runBasicAnalysis(document);
				console.log(`🔍 Basic analysis (no AI): Found ${basicIssues.length} issues`);
			}

			progressCallback?.("$(check) Combining and finalizing results...", "Deduplicating issues and preparing final report");

			// Prioritize AI results over basic analysis - only use basic if AI failed or unavailable
			const primaryIssues = aiIssues.length > 0 ? aiIssues : basicIssues;
			console.log(`🎯 Primary analysis results:`);
			console.log(`   AI Issues: ${aiIssues.length}`);
			console.log(`   Basic Issues: ${basicIssues.length}`);
			console.log(`   Using: ${aiIssues.length > 0 ? 'AI analysis' : 'Basic analysis'} as primary source`);
			
			const allIssues = [...primaryIssues, ...complexityIssues, ...bestPracticesIssues];
			console.log(`📊 Total issues before deduplication: ${allIssues.length}`);
			
			const result = this.combineAndDeduplicateIssues(allIssues);
			console.log(`📋 Final issues after deduplication: ${result.length}`);

			// Cache the result with both URI and content-based keys
			this.analysisCache.set(cacheKey, { result, timestamp: Date.now() });
			const resultContentHash = this.generateContentHash(document.getText());
			const resultContentCacheKey = `content_${resultContentHash}_${document.languageId}`;
			this.analysisCache.set(resultContentCacheKey, { result, timestamp: Date.now() });
			console.log('💾 Results cached for future use (both URI and content-based)');

			return result;
		} catch (error) {
			console.error('❌ Error in analysis:', error);
			console.log(`🔍 Analysis error details:`);
			console.log(`   Error Type: ${error instanceof Error ? error.constructor.name : typeof error}`);
			console.log(`   Error Message: ${error instanceof Error ? error.message : String(error)}`);
			console.log(`   Error Stack: ${error instanceof Error ? error.stack : 'No stack trace'}`);
			
			progressCallback?.("$(error) Analysis error, using fallback", "Error occurred but providing basic analysis");
			
			// Always return basic analysis as fallback, but include complexity and best practices
			console.log('🔄 Running fallback analysis due to error...');
			const basicIssues = this.runBasicAnalysis(document);
			const functions = ComplexityAnalyzer.analyzeFunctions(document);
			const complexityIssues = ComplexityAnalyzer.generateComplexityIssues(functions);
			const bestPracticesIssues = BestPracticesAnalyzer.analyzeBestPractices(document);
			
			console.log(`📊 Fallback analysis results:`);
			console.log(`   Basic Issues: ${basicIssues.length}`);
			console.log(`   Complexity Issues: ${complexityIssues.length}`);
			console.log(`   Best Practice Issues: ${bestPracticesIssues.length}`);

			// Combine all fallback analysis results
			const allIssues = [...basicIssues, ...complexityIssues, ...bestPracticesIssues];
			const result = this.combineAndDeduplicateIssues(allIssues);
			return result;
		}
	}

	private static async runAIAnalysis(document: vscode.TextDocument): Promise<SecurityIssue[]> {
		const apiKey = this.getApiKey();
		if (!apiKey) {
			return [];
		}

		const code = document.getText();
		const language = document.languageId;

		console.log(`🔍 Starting full AI analysis for ${code.length} characters of ${language} code`);

		try {
			const requestOptions = {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${apiKey}`,
					'HTTP-Referer': 'https://code-security-analyzer.com',
					'X-Title': 'VS Code Security Extension'
				},
				body: JSON.stringify({
					model: 'moonshotai/kimi-k2:free',
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
					max_tokens: 4000
				})
			};

			const data = await this.makeAPIRequest(requestOptions);
			const content = data.choices?.[0]?.message?.content;

			if (!content) {
				throw new Error('Invalid API response format');
			}

			// Clean the response and try to parse JSON
			let cleanContent = content.replace(/```json|```/g, '').trim();
			
			// Validate JSON before parsing
			if (cleanContent.startsWith('<') || cleanContent.includes('<!DOCTYPE')) {
				throw new Error('API returned HTML instead of JSON - likely an API error or invalid endpoint');
			}
			
			// Fix common JSON escaping issues
			cleanContent = this.fixJsonEscaping(cleanContent);
			
			let aiResult: AIAnalysisResult;
			try {
				aiResult = JSON.parse(cleanContent);
			} catch (parseError) {
				console.error('Failed to parse AI response as JSON:', cleanContent.substring(0, 500));
				throw new Error(`Invalid JSON response from AI: ${parseError}`);
			}

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
					source: 'AI Security Analysis (Full Code)',
					confidence: issue.confidence,
					cveReference: issue.cveReference,
					complexityScore: issue.complexityScore,
					functionName: issue.functionName
				};
			});

			console.log(`✅ AI analysis completed successfully with ${issues.length} issues found`);
			return issues;
		} catch (error) {
			console.error('❌ AI analysis failed:', error);
			throw error;
		}
	}

	private static combineAndDeduplicateIssues(allIssues: SecurityIssue[]): SecurityIssue[] {
		const deduplicatedIssues: SecurityIssue[] = [];

		for (const issue of allIssues) {
			// Check if this issue is similar to an existing one
			const isDuplicate = deduplicatedIssues.some(existing => existing.range.intersection(issue.range) &&
				existing.type === issue.type &&
				this.isSimilarMessage(existing.message, issue.message)
			);

			if (!isDuplicate) {
				deduplicatedIssues.push(issue);
			} else {
				// If duplicate, keep the one with higher confidence
				const existingIndex = deduplicatedIssues.findIndex(existing => existing.range.intersection(issue.range) &&
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

	private static createFixSuggestionPrompt(originalCode: string, issue: SecurityIssue, language: string): string {
		return `You are an expert security engineer. Generate a precise code fix for the following security issue.

**SECURITY ISSUE:**
- Type: ${issue.type}
- Message: ${issue.message}
- Description: ${issue.description}

**ORIGINAL CODE:**
\`\`\`${language}
${originalCode}
\`\`\`

**REQUIREMENTS:**
Return ONLY valid JSON in this exact format:
{
  "originalCode": "exact original code snippet",
  "fixedCode": "secure, working code replacement",
  "explanation": "clear explanation of what was fixed and why",
  "confidence": number (70-100),
  "riskLevel": "low|medium|high",
  "steps": ["step 1", "step 2", "..."]
}

**SPECIAL INSTRUCTIONS FOR FIXES:**

**IMPORTANT: Focus on Targeted Code Fixes, NOT Line Removal**
- Provide secure replacement code that maintains functionality
- Make minimal changes that fix the security issue
- Keep the same code structure and logic flow when possible
- Act like an intelligent code completion tool that suggests secure alternatives

**Examples of Good Fixes:**
- SQL Injection: 
  Original: \`SELECT * FROM users WHERE id = \${userId}\`
  Fixed: database.execute("SELECT * FROM users WHERE id = ?", [userId])
- XSS: 
  Original: element.innerHTML = userInput
  Fixed: element.textContent = userInput
- Weak Crypto: 
  Original: crypto.createHash('md5')
  Fixed: crypto.createHash('sha256')
- Hardcoded secrets: 
  Original: const API_KEY = "sk-1234..."
  Fixed: const API_KEY = process.env.API_KEY
- Random generation:
  Original: Math.random()
  Fixed: crypto.getRandomValues(new Uint32Array(1))[0]

**For Line Removal (RARE - only when necessary):**
Only suggest complete line removal when code is truly dangerous and has no safe alternative:
- Use "// REMOVE_LINE" in fixedCode for explicit removal
- Explain why removal is necessary in the explanation

**For File Creation:**
If the fix requires creating a new file (e.g., security config, utility functions), format like this:
- Start fixedCode with: "// Create new file: filename.ext"
- Follow with the file content on subsequent lines
- Example: "fixedCode": "// Create new file: security-config.js\nmodule.exports = {\n  enableHttps: true\n};"

**STANDARD INSTRUCTIONS:**
1. Provide secure, working code that directly replaces the vulnerable part
2. Maintain original functionality while fixing security issues
3. Make targeted, minimal changes (like changing one function call or parameter)
4. Include proper error handling and validation in fixes
5. Use modern security best practices
6. Only suggest fixes you're confident about (>=70%)
7. Focus on fixing, not removing (removal should be exceptional)

Focus on creating a secure, production-ready solution.`;
	}

	static async generateAIFixSuggestion(issue: SecurityIssue, document: vscode.TextDocument): Promise<AIFixSuggestion | null> {
		const apiKey = this.getApiKey();
		if (!apiKey) {
			return null;
		}

		// Create cache key based on issue content and document context
		const originalCode = document.getText(issue.range);
		const language = document.languageId;
		const cacheKey = `${document.uri.toString()}_${issue.message}_${originalCode}_${language}`;
		
		// Check cache first
		const cached = this.fixSuggestionCache.get(cacheKey);
		if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
			return cached.suggestion;
		}

		try {

			// Get surrounding context for better fixes
			const lineStart = Math.max(0, issue.range.start.line - 2);
			const lineEnd = Math.min(document.lineCount - 1, issue.range.end.line + 2);
			const contextRange = new vscode.Range(lineStart, 0, lineEnd, document.lineAt(lineEnd).text.length);
			const contextCode = document.getText(contextRange);

			const requestOptions = {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${apiKey}`,
					'HTTP-Referer': 'https://code-security-analyzer.com',
					'X-Title': 'VS Code Security Extension'
				},
				body: JSON.stringify({
					model: 'meta-llama/llama-3.1-8b-instruct:free',
					messages: [
						{
							role: 'system',
							content: 'You are an expert security engineer specializing in secure code generation. Provide precise, actionable code fixes.'
						},
						{
							role: 'user',
							content: this.createFixSuggestionPrompt(contextCode, issue, language)
						}
					],
					temperature: 0.1,
					max_tokens: 1000
				})
			};

			const data = await this.makeAPIRequest(requestOptions);
			const content = data.choices?.[0]?.message?.content;

			if (!content) {
				throw new Error('Invalid API response');
			}

			let cleanContent = content.replace(/```json|```/g, '').trim();
			
			// Validate JSON before parsing
			if (cleanContent.startsWith('<') || cleanContent.includes('<!DOCTYPE')) {
				throw new Error('API returned HTML instead of JSON - likely an API error or invalid endpoint');
			}
			
			// Fix common JSON escaping issues
			cleanContent = this.fixJsonEscaping(cleanContent);
			
			let fixSuggestion: AIFixSuggestion;
			try {
				fixSuggestion = JSON.parse(cleanContent);
			} catch (parseError) {
				console.error('Failed to parse AI response as JSON:', cleanContent);
				throw new Error(`Invalid JSON response from AI: ${parseError}`);
			}

			// Validate the fix suggestion
			if (!fixSuggestion.fixedCode || !fixSuggestion.explanation || fixSuggestion.confidence < 70) {
				return null;
			}

			// Cache the successful result
			this.fixSuggestionCache.set(cacheKey, { suggestion: fixSuggestion, timestamp: Date.now() });

			return fixSuggestion;
		} catch (error) {
			console.error('Failed to generate AI fix suggestion:', error);
			return null;
		}
	}

	private static runBasicAnalysis(document: vscode.TextDocument): SecurityIssue[] {
		console.log('🔍 Running basic pattern analysis as fallback...');
		
		const basicPatterns = [
			// SQL Injection patterns
			{
				pattern: /(?:query|execute|exec|prepare)\s*\(\s*['"`].*?\$\{.*?\}.*?['"`]/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'SQL Injection vulnerability detected',
				description: 'String interpolation in SQL queries can lead to SQL injection attacks allowing attackers to manipulate database queries.',
				suggestion: 'Use parameterized queries, prepared statements, or ORM methods like: db.query("SELECT * FROM users WHERE id = ?", [userId])',
				cveReference: 'CWE-89'
			},
			{
				pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?(\+|concat).*?(?:input|request|params|req\.)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'SQL injection risk through string concatenation',
				description: 'Concatenating user input directly into SQL queries creates injection vulnerabilities.',
				suggestion: 'Replace string concatenation with parameterized queries: db.execute("SELECT * FROM users WHERE name = %s", (username,))',
				cveReference: 'CWE-89'
			},

			// XSS patterns
			{
				pattern: /innerHTML\s*=\s*(?:.*?\+.*?(?:input|request|params)|.*?(?:req\.|request\.)|.*?\$\{.*?\})/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'Cross-Site Scripting (XSS) vulnerability',
				description: 'Setting innerHTML with unsanitized user input allows attackers to inject malicious scripts.',
				suggestion: 'Sanitize input with DOMPurify.sanitize() or use textContent instead: element.textContent = userInput',
				cveReference: 'CWE-79'
			},
			{
				pattern: /document\.write\s*\(.*?(?:input|request|params)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'XSS vulnerability in document.write',
				description: 'Using document.write with user input can lead to script injection.',
				suggestion: 'Use DOM manipulation methods with proper sanitization instead of document.write',
				cveReference: 'CWE-79'
			},

			// Hardcoded credentials
			{
				pattern: /(password|pwd|secret|token|key|api_key|apikey)\s*[:=]\s*['"`][^'"`\s]{8,}['"`]/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Hardcoded credentials detected',
				description: 'Hardcoded passwords, tokens, or API keys in source code pose security risks and can be exposed in version control.',
				suggestion: 'Move sensitive data to environment variables: process.env.API_KEY or use secure configuration management tools like HashiCorp Vault',
				cveReference: 'CWE-798'
			},

			// Dangerous functions
			{
				pattern: /\beval\s*\(/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'Use of eval() function creates code injection risk',
				description: 'The eval() function can execute arbitrary code and is a major security vulnerability.',
				suggestion: 'Replace eval() with safer alternatives: JSON.parse() for data, Function constructor for controlled code execution, or use a proper parser',
				cveReference: 'CWE-94'
			},

			// Insecure network communications
			{
				pattern: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi,
				type: 'warning' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Insecure HTTP protocol detected',
				description: 'Using HTTP instead of HTTPS exposes data to man-in-the-middle attacks and eavesdropping.',
				suggestion: 'Use HTTPS for all external communications: https://api.example.com',
				cveReference: 'CWE-319'
			},

			// Weak cryptography
			{
				pattern: /(?:MD5|SHA1|DES|RC4)\s*\(/gi,
				type: 'warning' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Weak cryptographic algorithm detected',
				description: 'MD5, SHA1, DES, and RC4 are cryptographically broken and should not be used for security purposes.',
				suggestion: 'Use strong algorithms: SHA-256, SHA-3, AES-256, or bcrypt for password hashing',
				cveReference: 'CWE-327'
			},

			// Insecure random
			{
				pattern: /Math\.random\(\)/gi,
				type: 'warning' as const,
				severity: vscode.DiagnosticSeverity.Information,
				message: 'Insecure random number generation',
				description: 'Math.random() is not cryptographically secure and predictable for security-sensitive operations.',
				suggestion: 'Use crypto.getRandomValues() for cryptographically secure randomness: crypto.getRandomValues(new Uint32Array(1))[0]',
				cveReference: 'CWE-338'
			},

			// Command injection
			{
				pattern: /(?:exec|system|spawn|execSync)\s*\(.*?(?:input|request|params|req\.)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'Command injection vulnerability detected',
				description: 'Executing system commands with user input can lead to command injection attacks.',
				suggestion: 'Use parameterized commands or input validation: child_process.execFile() with fixed arguments',
				cveReference: 'CWE-78'
			},

			// Path traversal
			{
				pattern: /(?:readFile|writeFile|open)\s*\(.*?(?:\.\.\/|\.\.\\|input|request|params|req\.)/gi,
				type: 'vulnerability' as const,
				severity: vscode.DiagnosticSeverity.Error,
				message: 'Path traversal vulnerability detected',
				description: 'File operations with user-controlled paths can lead to unauthorized file access.',
				suggestion: 'Validate and sanitize file paths: path.resolve() and check against allowed directories',
				cveReference: 'CWE-22'
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
					source: 'Basic Pattern Analysis (Fallback)',
					confidence: 75,
					cveReference: pattern.cveReference
				});
			}
		}

		console.log(`🔍 Basic analysis found ${issues.length} security issues`);
		return issues;
	}
}
