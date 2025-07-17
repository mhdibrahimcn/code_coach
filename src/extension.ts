import * as vscode from 'vscode';

interface SecurityIssue {
	type: 'vulnerability' | 'error' | 'warning' | 'complexity' | 'best-practice';
	severity: vscode.DiagnosticSeverity;
	message: string;
	description: string;
	range: vscode.Range;
	source: string;
	suggestion?: string;
	confidence: number;
	cveReference?: string;
	complexityScore?: number;
	functionName?: string;
}

interface ComplexityMetrics {
	cyclomaticComplexity: number;
	cognitiveComplexity: number;
	linesOfCode: number;
	parameterCount: number;
	nestingLevel: number;
}

interface FunctionInfo {
	name: string;
	range: vscode.Range;
	parameters: string[];
	complexity: ComplexityMetrics;
	bodyRange: vscode.Range;
}

interface AIAnalysisResult {
	issues: Array<{
		type: 'vulnerability' | 'error' | 'warning' | 'complexity' | 'best-practice';
		severity: 'error' | 'warning' | 'info';
		message: string;
		description: string;
		suggestion: string;
		lineNumber: number;
		columnStart: number;
		columnEnd: number;
		confidence: number;
		cveReference?: string;
		complexityScore?: number;
		functionName?: string;
	}>;
	summary: string;
}

class ComplexityAnalyzer {
	static analyzeFunctions(document: vscode.TextDocument): FunctionInfo[] {
		const text = document.getText();
		const functions: FunctionInfo[] = [];
		const language = document.languageId;

		// Function patterns for different languages
		const patterns = this.getFunctionPatterns(language);
		
		for (const pattern of patterns) {
			let match;
			pattern.regex.lastIndex = 0;
			
			while ((match = pattern.regex.exec(text)) !== null) {
				const functionInfo = this.extractFunctionInfo(document, match, pattern.type, language);
				if (functionInfo) {
					functions.push(functionInfo);
				}
			}
		}

		return functions;
	}

	private static getFunctionPatterns(language: string): Array<{regex: RegExp, type: string}> {
		const patterns: Record<string, Array<{regex: RegExp, type: string}>> = {
			'javascript': [
				{ regex: /function\s+(\w+)\s*\(([^)]*)\)\s*\{/g, type: 'function' },
				{ regex: /const\s+(\w+)\s*=\s*\(([^)]*)\)\s*=>\s*\{/g, type: 'arrow' },
				{ regex: /(\w+)\s*:\s*function\s*\(([^)]*)\)\s*\{/g, type: 'method' },
				{ regex: /(\w+)\s*\(([^)]*)\)\s*\{/g, type: 'method' },
				{ regex: /async\s+function\s+(\w+)\s*\(([^)]*)\)\s*\{/g, type: 'async' }
			],
			'typescript': [
				{ regex: /function\s+(\w+)\s*\(([^)]*)\)\s*:\s*[^{]*\{/g, type: 'function' },
				{ regex: /const\s+(\w+)\s*=\s*\(([^)]*)\)\s*:\s*[^{]*=>\s*\{/g, type: 'arrow' },
				{ regex: /(\w+)\s*\(([^)]*)\)\s*:\s*[^{]*\{/g, type: 'method' },
				{ regex: /async\s+(\w+)\s*\(([^)]*)\)\s*:\s*[^{]*\{/g, type: 'async' }
			],
			'python': [
				{ regex: /def\s+(\w+)\s*\(([^)]*)\)\s*:/g, type: 'function' },
				{ regex: /async\s+def\s+(\w+)\s*\(([^)]*)\)\s*:/g, type: 'async' }
			],
			'java': [
				{ regex: /(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*\w+\s+(\w+)\s*\(([^)]*)\)\s*\{/g, type: 'method' }
			],
			'csharp': [
				{ regex: /(?:public|private|protected|internal)?\s*(?:static)?\s*(?:virtual|override)?\s*\w+\s+(\w+)\s*\(([^)]*)\)\s*\{/g, type: 'method' }
			],
			'go': [
				{ regex: /func\s+(\w+)\s*\(([^)]*)\)\s*[^{]*\{/g, type: 'function' }
			],
			'rust': [
				{ regex: /fn\s+(\w+)\s*\(([^)]*)\)\s*[^{]*\{/g, type: 'function' }
			],
			'cpp': [
				{ regex: /(?:\w+\s+)*(\w+)\s*\(([^)]*)\)\s*\{/g, type: 'function' }
			],
			'php': [
				{ regex: /function\s+(\w+)\s*\(([^)]*)\)\s*\{/g, type: 'function' }
			]
		};

		return patterns[language] || patterns['javascript'];
	}

	private static extractFunctionInfo(document: vscode.TextDocument, match: RegExpExecArray, type: string, language: string): FunctionInfo | null {
		const functionName = match[1];
		const parameters = match[2] ? match[2].split(',').map(p => p.trim()).filter(p => p.length > 0) : [];
		
		const startPos = document.positionAt(match.index);
		const functionStart = match.index;
		
		// Find the function body
		const text = document.getText();
		const bodyStart = text.indexOf('{', match.index);
		if (bodyStart === -1) {
			return null;
		}
		
		const bodyEnd = this.findMatchingBrace(text, bodyStart);
		if (bodyEnd === -1) {
			return null;
		}
		
		const endPos = document.positionAt(bodyEnd + 1);
		const range = new vscode.Range(startPos, endPos);
		
		const bodyStartPos = document.positionAt(bodyStart);
		const bodyEndPos = document.positionAt(bodyEnd + 1);
		const bodyRange = new vscode.Range(bodyStartPos, bodyEndPos);
		
		const functionBody = text.substring(bodyStart, bodyEnd + 1);
		const complexity = this.calculateComplexity(functionBody, parameters, language);
		
		return {
			name: functionName,
			range,
			parameters,
			complexity,
			bodyRange
		};
	}

	private static findMatchingBrace(text: string, start: number): number {
		let braceCount = 0;
		let inString = false;
		let stringChar = '';
		let inComment = false;
		
		for (let i = start; i < text.length; i++) {
			const char = text[i];
			const nextChar = text[i + 1];
			
			// Handle comments
			if (!inString && char === '/' && nextChar === '/') {
				inComment = true;
				continue;
			}
			if (inComment && char === '\n') {
				inComment = false;
				continue;
			}
			if (inComment) {
				continue;
			}
			
			// Handle strings
			if (!inString && (char === '"' || char === "'" || char === '`')) {
				inString = true;
				stringChar = char;
				continue;
			}
			if (inString && char === stringChar && text[i - 1] !== '\\') {
				inString = false;
				stringChar = '';
				continue;
			}
			if (inString) {
				continue;
			}
			
			// Handle braces
			if (char === '{') {
				braceCount++;
			} else if (char === '}') {
				braceCount--;
				if (braceCount === 0) {
					return i;
				}
			}
		}
		
		return -1;
	}

	private static calculateComplexity(functionBody: string, parameters: string[], language: string): ComplexityMetrics {
		const lines = functionBody.split('\n').filter(line => line.trim().length > 0);
		const linesOfCode = lines.length;
		const parameterCount = parameters.length;
		
		// Calculate cyclomatic complexity
		const cyclomaticComplexity = this.calculateCyclomaticComplexity(functionBody, language);
		
		// Calculate cognitive complexity
		const cognitiveComplexity = this.calculateCognitiveComplexity(functionBody, language);
		
		// Calculate maximum nesting level
		const nestingLevel = this.calculateNestingLevel(functionBody);
		
		return {
			cyclomaticComplexity,
			cognitiveComplexity,
			linesOfCode,
			parameterCount,
			nestingLevel
		};
	}

	private static calculateCyclomaticComplexity(code: string, language: string): number {
		let complexity = 1; // Base complexity
		
		const patterns = {
			'javascript': [
				/\bif\s*\(/g,
				/\belse\s+if\s*\(/g,
				/\bwhile\s*\(/g,
				/\bfor\s*\(/g,
				/\bdo\s*\{/g,
				/\bswitch\s*\(/g,
				/\bcase\s+/g,
				/\bcatch\s*\(/g,
				/\&\&/g,
				/\|\|/g,
				/\?/g // Ternary operator
			],
			'python': [
				/\bif\s+/g,
				/\belif\s+/g,
				/\bwhile\s+/g,
				/\bfor\s+/g,
				/\bexcept\s+/g,
				/\band\s+/g,
				/\bor\s+/g
			],
			'java': [
				/\bif\s*\(/g,
				/\belse\s+if\s*\(/g,
				/\bwhile\s*\(/g,
				/\bfor\s*\(/g,
				/\bdo\s*\{/g,
				/\bswitch\s*\(/g,
				/\bcase\s+/g,
				/\bcatch\s*\(/g,
				/\&\&/g,
				/\|\|/g,
				/\?/g
			]
		};
		
		const languagePatterns = patterns[language as keyof typeof patterns] || patterns['javascript'];
		
		for (const pattern of languagePatterns) {
			const matches = code.match(pattern);
			if (matches) {
				complexity += matches.length;
			}
		}
		
		return complexity;
	}

	private static calculateCognitiveComplexity(code: string, language: string): number {
		let complexity = 0;
		let nestingLevel = 0;
		
		const lines = code.split('\n');
		
		for (const line of lines) {
			const trimmed = line.trim();
			
			// Increase nesting level
			if (trimmed.includes('{')) {
				nestingLevel++;
			}
			
			// Decrease nesting level
			if (trimmed.includes('}')) {
				nestingLevel = Math.max(0, nestingLevel - 1);
			}
			
			// Add complexity for control structures
			if (this.isControlStructure(trimmed, language)) {
				complexity += 1 + nestingLevel;
			}
			
			// Add complexity for logical operators
			const logicalOperators = (trimmed.match(/(\&\&|\|\|)/g) || []).length;
			complexity += logicalOperators;
		}
		
		return complexity;
	}

	private static isControlStructure(line: string, language: string): boolean {
		const patterns = {
			'javascript': /^\s*(if|else|while|for|do|switch|case|catch)\s*[\(\{]|^\s*else\s*$/,
			'python': /^\s*(if|elif|else|while|for|try|except|finally)[\s:]/,
			'java': /^\s*(if|else|while|for|do|switch|case|catch|finally)\s*[\(\{]|^\s*else\s*$/,
			'csharp': /^\s*(if|else|while|for|do|switch|case|catch|finally)\s*[\(\{]|^\s*else\s*$/,
			'go': /^\s*(if|else|for|switch|case|select)\s*[\(\{]|^\s*else\s*$/,
			'rust': /^\s*(if|else|while|for|loop|match)\s*[\(\{]|^\s*else\s*$/,
			'cpp': /^\s*(if|else|while|for|do|switch|case|catch)\s*[\(\{]|^\s*else\s*$/,
			'php': /^\s*(if|else|while|for|do|switch|case|catch|finally)\s*[\(\{]|^\s*else\s*$/
		};
		
		const pattern = patterns[language as keyof typeof patterns] || patterns['javascript'];
		return pattern.test(line);
	}

	private static calculateNestingLevel(code: string): number {
		let maxNesting = 0;
		let currentNesting = 0;
		
		for (const char of code) {
			if (char === '{') {
				currentNesting++;
				maxNesting = Math.max(maxNesting, currentNesting);
			} else if (char === '}') {
				currentNesting = Math.max(0, currentNesting - 1);
			}
		}
		
		return maxNesting;
	}

	static generateComplexityIssues(functions: FunctionInfo[]): SecurityIssue[] {
		const issues: SecurityIssue[] = [];
		
		for (const func of functions) {
			const { complexity } = func;
			
			// Cyclomatic complexity warnings
			if (complexity.cyclomaticComplexity > 15) {
				issues.push({
					type: 'complexity',
					severity: vscode.DiagnosticSeverity.Warning,
					message: `High cyclomatic complexity (${complexity.cyclomaticComplexity})`,
					description: `Function '${func.name}' has high cyclomatic complexity (${complexity.cyclomaticComplexity}). This indicates too many decision points and makes the code hard to test and maintain.`,
					suggestion: 'Consider breaking this function into smaller, more focused functions. Extract complex logic into separate methods.',
					range: func.range,
					source: 'Complexity Analysis',
					confidence: 90,
					complexityScore: complexity.cyclomaticComplexity,
					functionName: func.name
				});
			} else if (complexity.cyclomaticComplexity > 10) {
				issues.push({
					type: 'complexity',
					severity: vscode.DiagnosticSeverity.Information,
					message: `Moderate cyclomatic complexity (${complexity.cyclomaticComplexity})`,
					description: `Function '${func.name}' has moderate cyclomatic complexity (${complexity.cyclomaticComplexity}). Consider monitoring this function for future refactoring.`,
					suggestion: 'Monitor this function and consider refactoring if it becomes more complex.',
					range: func.range,
					source: 'Complexity Analysis',
					confidence: 80,
					complexityScore: complexity.cyclomaticComplexity,
					functionName: func.name
				});
			}
			
			// Cognitive complexity warnings
			if (complexity.cognitiveComplexity > 15) {
				issues.push({
					type: 'complexity',
					severity: vscode.DiagnosticSeverity.Warning,
					message: `High cognitive complexity (${complexity.cognitiveComplexity})`,
					description: `Function '${func.name}' has high cognitive complexity (${complexity.cognitiveComplexity}). This makes the code difficult to understand and maintain.`,
					suggestion: 'Simplify the logic flow. Consider using early returns, extracting nested logic, or using design patterns like Strategy or State.',
					range: func.range,
					source: 'Complexity Analysis',
					confidence: 90,
					complexityScore: complexity.cognitiveComplexity,
					functionName: func.name
				});
			}
			
			// Parameter count warnings
			if (complexity.parameterCount > 7) {
				issues.push({
					type: 'best-practice',
					severity: vscode.DiagnosticSeverity.Warning,
					message: `Too many parameters (${complexity.parameterCount})`,
					description: `Function '${func.name}' has ${complexity.parameterCount} parameters. Functions with many parameters are hard to use and test.`,
					suggestion: 'Consider using an options object, parameter object pattern, or breaking the function into smaller functions.',
					range: func.range,
					source: 'Best Practices Analysis',
					confidence: 85,
					functionName: func.name
				});
			} else if (complexity.parameterCount > 5) {
				issues.push({
					type: 'best-practice',
					severity: vscode.DiagnosticSeverity.Information,
					message: `Many parameters (${complexity.parameterCount})`,
					description: `Function '${func.name}' has ${complexity.parameterCount} parameters. Consider if this could be simplified.`,
					suggestion: 'Consider using an options object or grouping related parameters.',
					range: func.range,
					source: 'Best Practices Analysis',
					confidence: 75,
					functionName: func.name
				});
			}
			
			// Function length warnings
			if (complexity.linesOfCode > 100) {
				issues.push({
					type: 'best-practice',
					severity: vscode.DiagnosticSeverity.Warning,
					message: `Very long function (${complexity.linesOfCode} lines)`,
					description: `Function '${func.name}' is ${complexity.linesOfCode} lines long. Long functions are harder to understand, test, and maintain.`,
					suggestion: 'Break this function into smaller, more focused functions. Each function should have a single responsibility.',
					range: func.range,
					source: 'Best Practices Analysis',
					confidence: 90,
					functionName: func.name
				});
			} else if (complexity.linesOfCode > 50) {
				issues.push({
					type: 'best-practice',
					severity: vscode.DiagnosticSeverity.Information,
					message: `Long function (${complexity.linesOfCode} lines)`,
					description: `Function '${func.name}' is ${complexity.linesOfCode} lines long. Consider if it could be broken down further.`,
					suggestion: 'Consider extracting some logic into separate functions for better readability.',
					range: func.range,
					source: 'Best Practices Analysis',
					confidence: 80,
					functionName: func.name
				});
			}
			
			// Nesting level warnings
			if (complexity.nestingLevel > 4) {
				issues.push({
					type: 'best-practice',
					severity: vscode.DiagnosticSeverity.Warning,
					message: `Deep nesting (${complexity.nestingLevel} levels)`,
					description: `Function '${func.name}' has deep nesting (${complexity.nestingLevel} levels). This makes code hard to read and understand.`,
					suggestion: 'Use early returns, extract nested logic into functions, or flatten the structure using guard clauses.',
					range: func.range,
					source: 'Best Practices Analysis',
					confidence: 85,
					functionName: func.name
				});
			}
		}
		
		return issues;
	}
}

class BestPracticesAnalyzer {
	static analyzeBestPractices(document: vscode.TextDocument): SecurityIssue[] {
		const issues: SecurityIssue[] = [];
		const text = document.getText();
		const language = document.languageId;
		
		// Define interface for pattern objects
		interface BestPracticePattern {
			pattern: RegExp;
			type: 'best-practice';
			severity: vscode.DiagnosticSeverity;
			message: string;
			description: string;
			suggestion: string;
			exclude?: RegExp;
			isPositive?: boolean;
		}
		
		// General best practices patterns
		const patterns: BestPracticePattern[] = [
			// Magic numbers
			{
				pattern: /(?<!\w)(?<![\d.])\b(?:0x[\da-f]+|\d{3,}(?:\.\d+)?)\b(?![\d.])/gi,
				type: 'best-practice' as const,
				severity: vscode.DiagnosticSeverity.Information,
				message: 'Magic number detected',
				description: 'Magic numbers make code harder to understand and maintain. Consider using named constants.',
				suggestion: 'Replace magic numbers with named constants: const MAX_RETRY_COUNT = 3;',
				exclude: /console\.log|print|setTimeout|setInterval/
			},
			
			// TODO/FIXME comments
			{
				pattern: /\/\/\s*(TODO|FIXME|HACK|XXX|BUG)[\s:].*$/gmi,
				type: 'best-practice' as const,
				severity: vscode.DiagnosticSeverity.Information,
				message: 'TODO/FIXME comment found',
				description: 'This comment indicates incomplete or problematic code that needs attention.',
				suggestion: 'Address the TODO/FIXME comment or create a proper issue tracker item.'
			},
			
			// Empty catch blocks
			{
				pattern: /catch\s*\([^)]*\)\s*\{\s*\}/g,
				type: 'best-practice' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Empty catch block',
				description: 'Empty catch blocks hide exceptions and make debugging difficult.',
				suggestion: 'Add proper error handling: log the error, rethrow it, or handle it appropriately.'
			},
			
			// Console.log in production code
			{
				pattern: /console\.log\s*\(/g,
				type: 'best-practice' as const,
				severity: vscode.DiagnosticSeverity.Information,
				message: 'Console.log statement',
				description: 'Console.log statements should not be left in production code.',
				suggestion: 'Remove console.log or replace with proper logging framework.'
			},
			
			// Debugger statements
			{
				pattern: /\bdebugger\s*;/g,
				type: 'best-practice' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Debugger statement',
				description: 'Debugger statements should not be left in production code.',
				suggestion: 'Remove debugger statements before deploying to production.'
			},
			
			// Long lines
			{
				pattern: /.{121,}/g,
				type: 'best-practice' as const,
				severity: vscode.DiagnosticSeverity.Information,
				message: 'Line too long',
				description: 'Very long lines are hard to read and maintain. Consider breaking them up.',
				suggestion: 'Break long lines into multiple lines or extract complex expressions into variables.'
			},
			
			// Deeply nested ternary operators
			{
				pattern: /\?[^:]*\?[^:]*\?[^:]*:/g,
				type: 'best-practice' as const,
				severity: vscode.DiagnosticSeverity.Warning,
				message: 'Nested ternary operators',
				description: 'Deeply nested ternary operators are hard to read and understand.',
				suggestion: 'Replace nested ternary operators with if-else statements or extract into a function.'
			},
			
			// Duplicate code patterns
			{
				pattern: /(\w+\s*=\s*[^;]+;)\s*\n\s*\1/g,
				type: 'best-practice' as const,
				severity: vscode.DiagnosticSeverity.Information,
				message: 'Duplicate code detected',
				description: 'Duplicate code increases maintenance burden and can lead to inconsistencies.',
				suggestion: 'Extract duplicate code into a reusable function or variable.'
			}
		];
		
		// Add language-specific patterns
		if (language === 'javascript' || language === 'typescript') {
			patterns.push(
				{
					pattern: /===/g,
					type: 'best-practice' as const,
					severity: vscode.DiagnosticSeverity.Information,
					message: 'Good practice: strict equality',
					description: 'Using strict equality (===) is a good practice.',
					suggestion: 'Continue using strict equality for type-safe comparisons.',
					isPositive: true
				},
				{
					pattern: /==/g,
					type: 'best-practice' as const,
					severity: vscode.DiagnosticSeverity.Information,
					message: 'Use strict equality (===)',
					description: 'Loose equality (==) can lead to unexpected type coercion.',
					suggestion: 'Use strict equality (===) instead of loose equality (==).'
				},
				{
					pattern: /var\s+\w+/g,
					type: 'best-practice' as const,
					severity: vscode.DiagnosticSeverity.Information,
					message: 'Use const or let instead of var',
					description: 'var has function scope and can lead to unexpected behavior.',
					suggestion: 'Use const for constants and let for variables with block scope.'
				}
			);
		}
		
		// Analyze patterns
		for (const pattern of patterns) {
			let match;
			pattern.pattern.lastIndex = 0;
			
			while ((match = pattern.pattern.exec(text)) !== null) {
				// Skip if exclude pattern matches
				if (pattern.exclude && pattern.exclude.test(match[0])) {
					continue;
				}
				
				// Skip positive patterns (they're just informational)
				if (pattern.isPositive) {
					continue;
				}
				
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
					source: 'Best Practices Analysis',
					confidence: 80
				});
			}
		}
		
		return issues;
	}
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
			
			// Run complexity analysis
			const functions = ComplexityAnalyzer.analyzeFunctions(document);
			const complexityIssues = ComplexityAnalyzer.generateComplexityIssues(functions);
			
			// Run best practices analysis
			const bestPracticesIssues = BestPracticesAnalyzer.analyzeBestPractices(document);
			
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
			
			// Combine and deduplicate all results
			const allIssues = [...basicIssues, ...complexityIssues, ...bestPracticesIssues, ...aiIssues];
			const result = this.combineAndDeduplicateIssues(allIssues);
			
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
					model: 'deepseek/deepseek-chat',
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
					cveReference: issue.cveReference,
					complexityScore: issue.complexityScore,
					functionName: issue.functionName
				};
			});

			return issues;
		} catch (error) {
			console.error('AI analysis failed:', error);
			throw error;
		}
	}

	private static combineAndDeduplicateIssues(allIssues: SecurityIssue[]): SecurityIssue[] {
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
				
				let icon = '🔍';
				if (issue.type === 'vulnerability') {
					icon = '🚨';
				} else if (issue.type === 'complexity') {
					icon = '📊';
				} else if (issue.type === 'best-practice') {
					icon = '💡';
				} else if (issue.type === 'warning') {
					icon = '⚠️';
				}
				
				let title = `${confidence} ${icon} ${issue.message}`;
				
				// Add complexity score if available
				if (issue.complexityScore) {
					title += ` (${issue.complexityScore})`;
				}
				
				// Add function name if available
				if (issue.functionName) {
					title += ` - ${issue.functionName}()`;
				}
				
				const lens = new vscode.CodeLens(issue.range, {
					title,
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
					
					if (issue.complexityScore) {
						markdown.appendMarkdown(`**📊 Complexity Score:** ${issue.complexityScore}\n\n`);
					}
					
					if (issue.functionName) {
						markdown.appendMarkdown(`**🔧 Function:** ${issue.functionName}()\n\n`);
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
			
			const diagnostics: vscode.Diagnostic[] = issues
				.filter((issue: SecurityIssue) => {
					// Exclude best-practice issues from diagnostics to remove underlines
					// They will still be visible in CodeLens and hover
					return issue.type !== 'best-practice';
				})
				.map((issue: SecurityIssue) => {
					// For complexity issues, use Information severity to avoid red tab decoration
					let diagnosticSeverity = issue.severity;
					if (issue.type === 'complexity') {
						diagnosticSeverity = vscode.DiagnosticSeverity.Information;
					}
					
					const diagnostic = new vscode.Diagnostic(
						issue.range,
						issue.message,
						diagnosticSeverity
					);
					diagnostic.source = issue.source;
					diagnostic.code = issue.type;
					return diagnostic;
				});
			
			diagnosticCollection.set(document.uri, diagnostics);
			codeLensProvider.refresh();
			
			// Show summary in status bar
			const vulnerabilities = issues.filter(i => i.type === 'vulnerability').length;
			const complexityIssues = issues.filter(i => i.type === 'complexity').length;
			const bestPracticeIssues = issues.filter(i => i.type === 'best-practice').length;
			
			statusBarItem.text = `$(check) Analysis complete: ${vulnerabilities} vulnerabilities, ${complexityIssues} complexity, ${bestPracticeIssues} best practices`;
			setTimeout(() => statusBarItem.dispose(), 5000);
			
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
		vscode.commands.registerCommand('codeSecurityAnalyzer.showComplexityReport', async () => {
			const activeEditor = vscode.window.activeTextEditor;
			if (!activeEditor) {
				vscode.window.showWarningMessage('No active file to analyze');
				return;
			}

			const functions = ComplexityAnalyzer.analyzeFunctions(activeEditor.document);
			
			const panel = vscode.window.createWebviewPanel(
				'complexityReport',
				'Code Complexity Report',
				vscode.ViewColumn.Beside,
				{
					enableScripts: true
				}
			);

			panel.webview.html = generateComplexityReportHtml(functions);
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
						.type-badge {
							font-size: 0.8em;
							padding: 2px 6px;
							border-radius: 2px;
							background-color: var(--vscode-button-background);
							color: var(--vscode-button-foreground);
							margin-left: 10px;
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
						.complexity-info {
							background-color: var(--vscode-editor-inactiveSelectionBackground);
							padding: 10px;
							border-radius: 4px;
							font-size: 0.9em;
						}
						.function-info {
							background-color: var(--vscode-editor-selectionBackground);
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
						<span class="type-badge">${issue.type.toUpperCase()}</span>
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
					
					${issue.complexityScore ? `
					<div class="section">
						<h3>📊 Complexity Information</h3>
						<div class="complexity-info">
							<p><strong>Complexity Score:</strong> ${issue.complexityScore}</p>
							<p><strong>Impact:</strong> ${issue.complexityScore > 15 ? 'High - Urgent refactoring needed' : 
															issue.complexityScore > 10 ? 'Medium - Consider refactoring' : 
															'Low - Acceptable complexity'}</p>
						</div>
					</div>
					` : ''}
					
					${issue.functionName ? `
					<div class="section">
						<h3>🔧 Function Information</h3>
						<div class="function-info">
							<p><strong>Function Name:</strong> ${issue.functionName}()</p>
							<p><strong>Analysis Focus:</strong> This issue is specific to the function implementation</p>
						</div>
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
					
					<div class="section">
						<h3>📋 Analysis Details</h3>
						<div class="analysis-details">
							<p><strong>Source:</strong> ${issue.source}</p>
							<p><strong>Issue Type:</strong> ${issue.type}</p>
							<p><strong>Severity:</strong> ${severity}</p>
							<p><strong>Confidence:</strong> ${confidence} (${issue.confidence}%)</p>
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
				prompt: 'Enter your OpenRouter API key',
				password: true,
				placeHolder: 'sk-...'
			});
			
			if (apiKey) {
				await vscode.workspace.getConfiguration('codeSecurityAnalyzer').update('apiKey', apiKey, vscode.ConfigurationTarget.Global);
				vscode.window.showInformationMessage('API key configured successfully!');
			}
		})
	);

	// Helper function to generate complexity report HTML
	function generateComplexityReportHtml(functions: FunctionInfo[]): string {
		const sortedFunctions = functions.sort((a, b) => b.complexity.cyclomaticComplexity - a.complexity.cyclomaticComplexity);
		
		let functionsHtml = '';
		for (const func of sortedFunctions) {
			const complexity = func.complexity.cyclomaticComplexity;
			const complexityClass = complexity > 15 ? 'high' : complexity > 10 ? 'medium' : 'low';
			
			functionsHtml += `
				<div class="function-item ${complexityClass}">
					<h4>${func.name}()</h4>
					<div class="metrics">
						<div class="metric">
							<span class="label">Cyclomatic Complexity:</span>
							<span class="value">${func.complexity.cyclomaticComplexity}</span>
						</div>
						<div class="metric">
							<span class="label">Cognitive Complexity:</span>
							<span class="value">${func.complexity.cognitiveComplexity}</span>
						</div>
						<div class="metric">
							<span class="label">Lines of Code:</span>
							<span class="value">${func.complexity.linesOfCode}</span>
						</div>
						<div class="metric">
							<span class="label">Parameters:</span>
							<span class="value">${func.complexity.parameterCount}</span>
						</div>
						<div class="metric">
							<span class="label">Nesting Level:</span>
							<span class="value">${func.complexity.nestingLevel}</span>
						</div>
					</div>
				</div>
			`;
		}
		
		return `
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Code Complexity Report</title>
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
					.summary {
						background-color: var(--vscode-textBlockQuote-background);
						padding: 15px;
						border-radius: 4px;
						margin-bottom: 20px;
					}
					.function-item {
						background-color: var(--vscode-editor-inactiveSelectionBackground);
						padding: 15px;
						margin-bottom: 15px;
						border-radius: 4px;
						border-left: 4px solid;
					}
					.function-item.high {
						border-left-color: #dc3545;
					}
					.function-item.medium {
						border-left-color: #ffc107;
					}
					.function-item.low {
						border-left-color: #28a745;
					}
					.function-item h4 {
						margin: 0 0 10px 0;
						color: var(--vscode-foreground);
					}
					.metrics {
						display: grid;
						grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
						gap: 10px;
					}
					.metric {
						display: flex;
						justify-content: space-between;
						padding: 5px 0;
					}
					.label {
						font-weight: bold;
					}
					.value {
						color: var(--vscode-textLink-foreground);
					}
					.complexity-legend {
						background-color: var(--vscode-editor-selectionBackground);
						padding: 10px;
						border-radius: 4px;
						margin-bottom: 20px;
					}
					.legend-item {
						display: inline-block;
						margin-right: 20px;
						padding: 5px 10px;
						border-radius: 3px;
						font-size: 0.9em;
					}
					.legend-high { background-color: #dc3545; color: white; }
					.legend-medium { background-color: #ffc107; color: black; }
					.legend-low { background-color: #28a745; color: white; }
				</style>
			</head>
			<body>
				<div class="header">
					<h2>📊 Code Complexity Report</h2>
					<p>Analysis of function complexity metrics</p>
				</div>
				
				<div class="summary">
					<h3>Summary</h3>
					<p><strong>Total Functions:</strong> ${functions.length}</p>
					<p><strong>High Complexity:</strong> ${functions.filter(f => f.complexity.cyclomaticComplexity > 15).length}</p>
					<p><strong>Medium Complexity:</strong> ${functions.filter(f => f.complexity.cyclomaticComplexity > 10 && f.complexity.cyclomaticComplexity <= 15).length}</p>
					<p><strong>Low Complexity:</strong> ${functions.filter(f => f.complexity.cyclomaticComplexity <= 10).length}</p>
				</div>
				
				<div class="complexity-legend">
					<h4>Complexity Legend:</h4>
					<span class="legend-item legend-high">High (>15) - Urgent refactoring needed</span>
					<span class="legend-item legend-medium">Medium (10-15) - Consider refactoring</span>
					<span class="legend-item legend-low">Low (≤10) - Acceptable complexity</span>
				</div>
				
				<div class="functions-list">
					<h3>Functions by Complexity</h3>
					${functionsHtml}
				</div>
			</body>
			</html>
		`;
	}

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