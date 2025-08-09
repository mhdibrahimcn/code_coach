import * as vscode from 'vscode';
import { SecurityIssue } from './SecurityIssue';

export class BestPracticesAnalyzer {
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
