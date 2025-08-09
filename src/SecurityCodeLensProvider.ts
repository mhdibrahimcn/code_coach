import * as vscode from 'vscode';
import { AISecurityAnalyzer } from './AISecurityAnalyzer';

export class SecurityCodeLensProvider implements vscode.CodeLensProvider {
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

				// Add "Fix with AI" button for vulnerability and error issues
				if (issue.type === 'vulnerability' || issue.type === 'error') {
					const fixLens = new vscode.CodeLens(
						new vscode.Range(issue.range.start.line, issue.range.end.character + 1, issue.range.start.line, issue.range.end.character + 1),
						{
							title: issue.aiFixSuggestion ? '🚀 Apply AI Fix' : '🤖 Fix with AI',
							command: issue.aiFixSuggestion ? 'codeSecurityAnalyzer.applyAIFix' : 'codeSecurityAnalyzer.getAIFix',
							arguments: [document.uri, issue]
						}
					);
					codeLenses.push(fixLens);
				}
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
