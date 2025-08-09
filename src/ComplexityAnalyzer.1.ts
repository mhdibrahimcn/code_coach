import * as vscode from 'vscode';
import { FunctionInfo, ComplexityMetrics } from './extension';
import { SecurityIssue } from './SecurityIssue';

export class ComplexityAnalyzer {
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

	private static getFunctionPatterns(language: string): Array<{ regex: RegExp; type: string; }> {
		const patterns: Record<string, Array<{ regex: RegExp; type: string; }>> = {
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
