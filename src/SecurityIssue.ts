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
	// Enhanced fields for function-based analysis
	category?: 'security' | 'performance' | 'maintainability' | 'reliability' | 'style';
	owaspCategory?: string;
	cweId?: string;
	functionStartLine?: number;
	functionEndLine?: number;
	riskLevel?: 'low' | 'medium' | 'high' | 'critical';
	vulnerabilityType?: string;
	affectedLines?: number[];
	contextCode?: string;
	isDeepAnalysis?: boolean;
}

export interface FunctionVulnerability {
	functionName: string;
	startLine: number;
	endLine: number;
	vulnerabilities: VulnerabilityDetails[];
	complexity: number;
	securityRisk: 'low' | 'medium' | 'high' | 'critical';
	codeChunk: string;
}

export interface VulnerabilityDetails {
	type: string;
	severity: 'critical' | 'high' | 'medium' | 'low';
	description: string;
	explanation: string;
	mitigation: string;
	cweId?: string;
	owaspCategory?: string;
	affectedLines: number[];
	confidence: number;
}

export interface DeepAnalysisResult {
	issues: SecurityIssue[];
	functionVulnerabilities: FunctionVulnerability[];
	overallRisk: 'low' | 'medium' | 'high' | 'critical';
	summary: {
		totalVulnerabilities: number;
		criticalCount: number;
		highCount: number;
		mediumCount: number;
		lowCount: number;
		functionsAnalyzed: number;
	};
	analysisMetadata: {
		analysisType: 'deep' | 'standard';
		executionTime: number;
		aiProvider?: string;
		timestamp: number;
	};
}
