import * as vscode from 'vscode';
import { AISecurityAnalyzer } from './AISecurityAnalyzer';
import { SecurityIssue } from './SecurityIssue';

export class SecurityHoverProvider implements vscode.HoverProvider {
	async provideHover(document: vscode.TextDocument, position: vscode.Position): Promise<vscode.Hover | undefined> {
		try {
			const issues = await AISecurityAnalyzer.analyzeDocument(document);

			for (const issue of issues) {
				if (issue.range.contains(position)) {
					const severity = this.getSeverityIcon(issue);
					const category = this.getCategoryIcon(issue);
					const confidence = this.getConfidenceIndicator(issue.confidence);

					const markdown = new vscode.MarkdownString();
					markdown.isTrusted = true;
					markdown.supportHtml = true;

					// Enhanced header with severity, category, and risk level
					markdown.appendMarkdown(`${severity} **${issue.message}** ${category}\n\n`);
					
					// Enhanced metadata display
					if (issue.isDeepAnalysis) {
						markdown.appendMarkdown(`🔬 **Deep Analysis Result**\n\n`);
					}
					
					if (issue.riskLevel) {
						const riskIcon = this.getRiskIcon(issue.riskLevel);
						markdown.appendMarkdown(`**${riskIcon} Risk Level:** ${issue.riskLevel.toUpperCase()}\n\n`);
					}

					markdown.appendMarkdown(`**Description:** ${issue.description}\n\n`);

					if (issue.suggestion) {
						markdown.appendMarkdown(`**💡 Suggestion:** ${issue.suggestion}\n\n`);
					}

					// Add AI fix suggestion if available
					if (issue.aiFixSuggestion) {
						const fix = issue.aiFixSuggestion;
						const riskIcon = fix.riskLevel === 'high' ? '🔴' : fix.riskLevel === 'medium' ? '🟡' : '🟢';

						markdown.appendMarkdown(`**🤖 AI Fix Suggestion** ${riskIcon} (${fix.confidence}% confidence)\n\n`);
						markdown.appendMarkdown(`**Fix:** ${fix.explanation}\n\n`);
						markdown.appendMarkdown(`**Fixed Code:**\n\`\`\`${document.languageId}\n${fix.fixedCode}\n\`\`\`\n\n`);

						if (fix.steps && fix.steps.length > 0) {
							markdown.appendMarkdown(`**Steps:**\n`);
							fix.steps.forEach((step, index) => {
								markdown.appendMarkdown(`${index + 1}. ${step}\n`);
							});
							markdown.appendMarkdown(`\n`);
						}
					} else if (issue.type === 'vulnerability' || issue.type === 'error') {
						// Show button to get AI fix
						markdown.appendMarkdown(`**🤖 AI Fix Suggestion:** [Click to get AI fix suggestion](command:codeSecurityAnalyzer.getAIFix?${encodeURIComponent(JSON.stringify([document.uri.toString(), issue]))})\n\n`);
					}

					// Security-specific information
					if (issue.category === 'security') {
						if (issue.cweId) {
							markdown.appendMarkdown(`**🔒 CWE:** ${issue.cweId}\n\n`);
						}
						if (issue.owaspCategory) {
							markdown.appendMarkdown(`**🛡️ OWASP:** ${issue.owaspCategory}\n\n`);
						}
						if (issue.vulnerabilityType) {
							markdown.appendMarkdown(`**⚠️ Vulnerability Type:** ${issue.vulnerabilityType}\n\n`);
						}
					}

					// Function-level information
					if (issue.functionName) {
						markdown.appendMarkdown(`**🔧 Function:** \`${issue.functionName}()\`\n\n`);
						
						if (issue.functionStartLine && issue.functionEndLine) {
							markdown.appendMarkdown(`**📍 Function Location:** Lines ${issue.functionStartLine + 1}-${issue.functionEndLine + 1}\n\n`);
						}
					}

					if (issue.complexityScore) {
						const complexityIcon = issue.complexityScore > 7 ? '🔴' : issue.complexityScore > 4 ? '🟡' : '🟢';
						markdown.appendMarkdown(`**📊 Complexity Score:** ${complexityIcon} ${issue.complexityScore}/10\n\n`);
					}

					// Context information
					if (issue.affectedLines && issue.affectedLines.length > 1) {
						markdown.appendMarkdown(`**📋 Affected Lines:** ${issue.affectedLines.map(l => l + 1).join(', ')}\n\n`);
					}

					markdown.appendMarkdown(`**Confidence:** ${confidence} (${issue.confidence}%)\n\n`);
					
					// Enhanced source information
					let sourceText = issue.source;
					if (issue.isDeepAnalysis) {
						sourceText += ' (Deep Analysis)';
					}
					markdown.appendMarkdown(`*Source: ${sourceText}*`);

					return new vscode.Hover(markdown, issue.range);
				}
			}
		} catch (error) {
			console.error('Error providing hover:', error);
		}

		return undefined;
	}

	private getSeverityIcon(issue: SecurityIssue): string {
		if (issue.riskLevel) {
			switch (issue.riskLevel) {
				case 'critical': return '🚨';
				case 'high': return '❗';
				case 'medium': return '⚠️';
				case 'low': return 'ℹ️';
			}
		}
		
		// Fallback to severity
		switch (issue.severity) {
			case vscode.DiagnosticSeverity.Error: return '🚨';
			case vscode.DiagnosticSeverity.Warning: return '⚠️';
			case vscode.DiagnosticSeverity.Information: return 'ℹ️';
			default: return '⚠️';
		}
	}

	private getCategoryIcon(issue: SecurityIssue): string {
		if (!issue.category) return '📝';
		
		switch (issue.category) {
			case 'security': return '🔒';
			case 'performance': return '⚡';
			case 'maintainability': return '🔧';
			case 'reliability': return '🛠️';
			case 'style': return '🎨';
			default: return '📝';
		}
	}

	private getRiskIcon(riskLevel: string): string {
		switch (riskLevel) {
			case 'critical': return '🚨';
			case 'high': return '🔴';
			case 'medium': return '🟡';
			case 'low': return '🟢';
			default: return '🟡';
		}
	}

	private getConfidenceIndicator(confidence: number): string {
		if (confidence >= 90) return '🟢 Very High';
		if (confidence >= 80) return '🟢 High';
		if (confidence >= 70) return '🟡 Medium';
		if (confidence >= 60) return '🟡 Medium-Low';
		return '🟠 Low';
	}
}
