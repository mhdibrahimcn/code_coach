import * as vscode from 'vscode';
import { AIFixSuggestion } from './extension';


export interface SecurityIssue {
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
	aiFixSuggestion?: AIFixSuggestion;
}
