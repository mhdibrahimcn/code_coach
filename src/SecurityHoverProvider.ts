import * as vscode from 'vscode';
import { AISecurityAnalyzer } from './AISecurityAnalyzer';

export class SecurityHoverProvider implements vscode.HoverProvider {
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
					markdown.isTrusted = true;
					markdown.supportHtml = true;

					markdown.appendMarkdown(`${severity} **${issue.message}**\n\n`);
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
