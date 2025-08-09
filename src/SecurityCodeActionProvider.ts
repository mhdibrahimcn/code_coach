import * as vscode from 'vscode';
import { AISecurityAnalyzer } from './AISecurityAnalyzer';

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
	async provideCodeActions(document: vscode.TextDocument, range: vscode.Range, context: vscode.CodeActionContext): Promise<vscode.CodeAction[]> {
		const actions: vscode.CodeAction[] = [];

		try {
			const issues = await AISecurityAnalyzer.analyzeDocument(document);

			for (const issue of issues) {
				if (issue.range.intersection(range) && (issue.type === 'vulnerability' || issue.type === 'error')) {
					// Create action to get AI fix
					const getFixAction = new vscode.CodeAction(
						`🤖 Get AI Fix for: ${issue.message}`,
						vscode.CodeActionKind.QuickFix
					);
					getFixAction.command = {
						title: 'Get AI Fix',
						command: 'codeSecurityAnalyzer.getAIFix',
						arguments: [document.uri, issue]
					};
					actions.push(getFixAction);

					// If AI fix is already available, create apply action
					if (issue.aiFixSuggestion) {
						const applyFixAction = new vscode.CodeAction(
							`🚀 Apply AI Fix (${issue.aiFixSuggestion.confidence}% confidence)`,
							vscode.CodeActionKind.QuickFix
						);
						applyFixAction.command = {
							title: 'Apply AI Fix',
							command: 'codeSecurityAnalyzer.applyAIFix',
							arguments: [document.uri, issue]
						};
						actions.push(applyFixAction);
					}
				}
			}
		} catch (error) {
			console.error('Error providing code actions:', error);
		}

		return actions;
	}
}
