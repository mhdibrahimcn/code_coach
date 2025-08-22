import * as vscode from 'vscode';
import { SecurityIssue, DeepAnalysisResult, FunctionVulnerability } from '../SecurityIssue';
import { logger } from '../core/DebugLogger';
import { VulnerabilityClassifier } from '../core/VulnerabilityClassifier';

export class AnalysisReportWebview {
    private static currentPanel: vscode.WebviewPanel | undefined;
    private readonly extensionUri: vscode.Uri;

    constructor(extensionUri: vscode.Uri) {
        this.extensionUri = extensionUri;
    }

    public async showReport(
        document: vscode.TextDocument,
        analysisResult: DeepAnalysisResult,
        executionTime: number
    ): Promise<void> {
        const columnToShowIn = vscode.ViewColumn.Beside;

        if (AnalysisReportWebview.currentPanel) {
            // If we already have a panel, update it
            AnalysisReportWebview.currentPanel.reveal(columnToShowIn);
        } else {
            // Otherwise, create a new panel
            AnalysisReportWebview.currentPanel = vscode.window.createWebviewPanel(
                'securityAnalysisReport',
                'Security Analysis Report',
                columnToShowIn,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true,
                    localResourceRoots: [
                        vscode.Uri.joinPath(this.extensionUri, 'media'),
                        vscode.Uri.joinPath(this.extensionUri, 'dist')
                    ]
                }
            );

            AnalysisReportWebview.currentPanel.onDidDispose(
                () => {
                    AnalysisReportWebview.currentPanel = undefined;
                },
                null
            );
        }

        // Set the webview's initial HTML content
        AnalysisReportWebview.currentPanel.webview.html = await this.getWebviewContent(
            AnalysisReportWebview.currentPanel.webview,
            document,
            analysisResult,
            executionTime
        );

        // Handle messages from the webview
        AnalysisReportWebview.currentPanel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'goToLine':
                        this.goToLine(document, message.line);
                        break;
                    case 'exportReport':
                        this.exportReport(analysisResult, document);
                        break;
                    case 'showDebugLogs':
                        logger.show();
                        break;
                    case 'reAnalyze':
                        vscode.commands.executeCommand('codeSecurityAnalyzer.deepSecurityAnalysis');
                        break;
                }
            }
        );

        logger.info('Analysis report webview created', {
            file: document.fileName,
            issues: analysisResult.issues.length,
            functions: analysisResult.functionVulnerabilities.length
        });
    }

    private async goToLine(document: vscode.TextDocument, lineNumber: number): Promise<void> {
        try {
            const editor = await vscode.window.showTextDocument(document);
            const position = new vscode.Position(lineNumber - 1, 0);
            editor.selection = new vscode.Selection(position, position);
            editor.revealRange(new vscode.Range(position, position));
        } catch (error) {
            logger.error('Failed to navigate to line', { lineNumber, error });
        }
    }

    private async exportReport(result: DeepAnalysisResult, document: vscode.TextDocument): Promise<void> {
        try {
            const reportData = {
                timestamp: new Date().toISOString(),
                file: document.fileName,
                language: document.languageId,
                analysis: result,
                summary: {
                    totalIssues: result.issues.length,
                    overallRisk: result.overallRisk,
                    functionsAnalyzed: result.functionVulnerabilities.length
                }
            };

            const jsonString = JSON.stringify(reportData, null, 2);
            const fileName = `security-report-${Date.now()}.json`;
            
            const uri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(fileName),
                filters: {
                    'JSON Reports': ['json'],
                    'All Files': ['*']
                }
            });

            if (uri) {
                await vscode.workspace.fs.writeFile(uri, Buffer.from(jsonString, 'utf8'));
                vscode.window.showInformationMessage(`Report exported to ${uri.fsPath}`);
                logger.info('Report exported', { path: uri.fsPath });
            }
        } catch (error) {
            logger.error('Failed to export report', error);
            vscode.window.showErrorMessage('Failed to export report');
        }
    }

    private async getWebviewContent(
        webview: vscode.Webview,
        document: vscode.TextDocument,
        result: DeepAnalysisResult,
        executionTime: number
    ): Promise<string> {
        const fileName = document.fileName.split('/').pop() || 'Unknown File';
        const criticalIssues = result.issues.filter(i => i.riskLevel === 'critical');
        const highIssues = result.issues.filter(i => i.riskLevel === 'high');
        const mediumIssues = result.issues.filter(i => i.riskLevel === 'medium');
        const lowIssues = result.issues.filter(i => i.riskLevel === 'low');

        const functionsSummary = this.generateFunctionsSummary(result.functionVulnerabilities);
        const issuesHtml = this.generateIssuesHtml(result.issues);
        const functionsHtml = this.generateFunctionsHtml(result.functionVulnerabilities);
        const chartData = this.generateChartData(result);
        
        // Generate comprehensive security classification report
        const securityReport = VulnerabilityClassifier.generateSecurityReport(result.issues);
        const classificationHtml = this.generateClassificationHtml(securityReport);

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        :root {
            --bg-primary: var(--vscode-editor-background);
            --bg-secondary: var(--vscode-editorWidget-background);
            --text-primary: var(--vscode-editor-foreground);
            --text-secondary: var(--vscode-descriptionForeground);
            --border-color: var(--vscode-panel-border);
            --accent-color: var(--vscode-textLink-foreground);
            --error-color: var(--vscode-errorForeground);
            --warning-color: var(--vscode-warningForeground);
            --success-color: var(--vscode-charts-green);
            --info-color: var(--vscode-charts-blue);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: var(--vscode-font-family);
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--accent-color) 100%);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            color: white;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        .file-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .info-card {
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }

        .info-card .label {
            font-size: 0.9rem;
            opacity: 0.8;
            margin-bottom: 5px;
        }

        .info-card .value {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }

        .summary-card .icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
            display: block;
        }

        .summary-card .number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 8px;
            display: block;
        }

        .summary-card .label {
            font-size: 1rem;
            color: var(--text-secondary);
        }

        .critical { color: #ff4757; }
        .high { color: #ff6b6b; }
        .medium { color: #ffa502; }
        .low { color: #7bed9f; }
        .success { color: var(--success-color); }

        .tabs {
            display: flex;
            background: var(--bg-secondary);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }

        .tab {
            flex: 1;
            padding: 15px 20px;
            background: transparent;
            border: none;
            color: var(--text-primary);
            cursor: pointer;
            transition: background-color 0.2s ease;
            font-size: 1rem;
        }

        .tab:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .tab.active {
            background: var(--accent-color);
            color: white;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .issue-list {
            space-y: 15px;
        }

        .issue-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            transition: border-color 0.2s ease;
        }

        .issue-item:hover {
            border-color: var(--accent-color);
        }

        .issue-header {
            display: flex;
            justify-content: between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .issue-title {
            flex: 1;
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 5px;
        }

        .issue-badges {
            display: flex;
            gap: 8px;
            flex-shrink: 0;
        }

        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }

        .badge-critical { background: #ff4757; color: white; }
        .badge-high { background: #ff6b6b; color: white; }
        .badge-medium { background: #ffa502; color: white; }
        .badge-low { background: #7bed9f; color: black; }
        .badge-line { background: var(--accent-color); color: white; }

        .issue-description {
            margin: 15px 0;
            line-height: 1.6;
        }

        .issue-suggestion {
            background: rgba(46, 160, 67, 0.1);
            border-left: 4px solid var(--success-color);
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
        }

        .issue-metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }

        .metadata-item {
            display: flex;
            justify-content: space-between;
        }

        .action-buttons {
            position: fixed;
            bottom: 20px;
            right: 20px;
            display: flex;
            gap: 10px;
        }

        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.2s ease;
        }

        .btn-primary {
            background: var(--accent-color);
            color: white;
        }

        .btn-secondary {
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .function-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }

        .function-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .function-name {
            font-size: 1.2rem;
            font-weight: 600;
            font-family: 'Courier New', monospace;
        }

        .function-metrics {
            display: flex;
            gap: 15px;
        }

        .metric {
            text-align: center;
        }

        .metric .value {
            font-size: 1.5rem;
            font-weight: bold;
            display: block;
        }

        .metric .label {
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .vulnerability-list {
            margin-top: 15px;
        }

        .vulnerability-item {
            background: rgba(255, 0, 0, 0.05);
            border-left: 4px solid var(--error-color);
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .clickable {
            cursor: pointer;
            transition: background-color 0.2s ease;
        }

        .clickable:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .no-issues {
            text-align: center;
            padding: 60px 20px;
            color: var(--success-color);
        }

        .no-issues .icon {
            font-size: 4rem;
            margin-bottom: 20px;
            display: block;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .tabs {
                flex-direction: column;
            }
            
            .action-buttons {
                position: static;
                margin-top: 30px;
                justify-content: center;
            }
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 Security Analysis Report</h1>
            <div class="file-info">
                <div class="info-card">
                    <div class="label">File</div>
                    <div class="value">${fileName}</div>
                </div>
                <div class="info-card">
                    <div class="label">Language</div>
                    <div class="value">${document.languageId.toUpperCase()}</div>
                </div>
                <div class="info-card">
                    <div class="label">Analysis Time</div>
                    <div class="value">${executionTime}ms</div>
                </div>
                <div class="info-card">
                    <div class="label">Overall Risk</div>
                    <div class="value ${result.overallRisk}">${result.overallRisk.toUpperCase()}</div>
                </div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <span class="icon">🚨</span>
                <span class="number critical">${criticalIssues.length}</span>
                <span class="label">Critical Issues</span>
            </div>
            <div class="summary-card">
                <span class="icon">⚠️</span>
                <span class="number high">${highIssues.length}</span>
                <span class="label">High Priority</span>
            </div>
            <div class="summary-card">
                <span class="icon">🔍</span>
                <span class="number medium">${mediumIssues.length}</span>
                <span class="label">Medium Priority</span>
            </div>
            <div class="summary-card">
                <span class="icon">ℹ️</span>
                <span class="number low">${lowIssues.length}</span>
                <span class="label">Low Priority</span>
            </div>
            <div class="summary-card">
                <span class="icon">🔧</span>
                <span class="number success">${result.functionVulnerabilities.length}</span>
                <span class="label">Functions Analyzed</span>
            </div>
            <div class="summary-card">
                <span class="icon">📊</span>
                <span class="number success">${result.issues.length}</span>
                <span class="label">Total Issues</span>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="showTab('issues')">🔍 Security Issues</button>
            <button class="tab" onclick="showTab('functions')">🔧 Function Analysis</button>
            <button class="tab" onclick="showTab('classifications')">🏷️ Classifications</button>
            <button class="tab" onclick="showTab('summary')">📊 Executive Summary</button>
        </div>

        <div id="issues-tab" class="tab-content active">
            ${result.issues.length > 0 ? issuesHtml : '<div class="no-issues"><span class="icon">✅</span><h2>No Security Issues Found</h2><p>Your code appears to follow security best practices!</p></div>'}
        </div>

        <div id="functions-tab" class="tab-content">
            ${result.functionVulnerabilities.length > 0 ? functionsHtml : '<div class="no-issues"><span class="icon">🔧</span><h2>No Function Vulnerabilities</h2><p>All analyzed functions appear secure!</p></div>'}
        </div>

        <div id="classifications-tab" class="tab-content">
            ${classificationHtml}
        </div>

        <div id="summary-tab" class="tab-content">
            ${functionsSummary}
        </div>
    </div>

    <div class="action-buttons">
        <button class="btn btn-secondary" onclick="exportReport()">📥 Export Report</button>
        <button class="btn btn-secondary" onclick="showDebugLogs()">🐛 Debug Logs</button>
        <button class="btn btn-primary" onclick="reAnalyze()">🔄 Re-analyze</button>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        
        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Add active class to selected tab
            event.target.classList.add('active');
        }
        
        function goToLine(line) {
            vscode.postMessage({
                command: 'goToLine',
                line: line
            });
        }
        
        function exportReport() {
            vscode.postMessage({
                command: 'exportReport'
            });
        }
        
        function showDebugLogs() {
            vscode.postMessage({
                command: 'showDebugLogs'
            });
        }
        
        function reAnalyze() {
            vscode.postMessage({
                command: 'reAnalyze'
            });
        }

        // Auto-refresh timestamp
        setInterval(() => {
            const timestamp = document.querySelector('.timestamp');
            if (timestamp) {
                timestamp.textContent = 'Report generated: ' + new Date().toLocaleString();
            }
        }, 60000);
    </script>
</body>
</html>`;
    }

    private generateIssuesHtml(issues: SecurityIssue[]): string {
        return issues.map(issue => {
            const riskClass = issue.riskLevel || 'medium';
            const categoryIcon = this.getCategoryIcon(issue.category);
            
            return `
                <div class="issue-item">
                    <div class="issue-header">
                        <div class="issue-title">
                            ${categoryIcon} ${issue.message}
                        </div>
                        <div class="issue-badges">
                            <span class="badge badge-${riskClass}">${(issue.riskLevel || 'medium').toUpperCase()}</span>
                            <span class="badge badge-line clickable" onclick="goToLine(${issue.range.start.line + 1})">Line ${issue.range.start.line + 1}</span>
                        </div>
                    </div>
                    <div class="issue-description">${issue.description}</div>
                    ${issue.suggestion ? `<div class="issue-suggestion"><strong>💡 Fix:</strong> ${issue.suggestion}</div>` : ''}
                    <div class="issue-metadata">
                        ${issue.functionName ? `<div class="metadata-item"><span>Function:</span><span><code>${issue.functionName}()</code></span></div>` : ''}
                        ${issue.cweId ? `<div class="metadata-item"><span>CWE:</span><span>${issue.cweId}</span></div>` : ''}
                        ${issue.owaspCategory ? `<div class="metadata-item"><span>OWASP:</span><span>${issue.owaspCategory}</span></div>` : ''}
                        <div class="metadata-item"><span>Confidence:</span><span>${issue.confidence}%</span></div>
                        <div class="metadata-item"><span>Source:</span><span>${issue.source}</span></div>
                    </div>
                </div>
            `;
        }).join('');
    }

    private generateFunctionsHtml(functions: FunctionVulnerability[]): string {
        return functions.map(func => {
            const riskClass = func.securityRisk;
            const complexityClass = func.complexity > 7 ? 'critical' : func.complexity > 4 ? 'medium' : 'success';
            
            return `
                <div class="function-card">
                    <div class="function-header">
                        <div class="function-name">${func.functionName}()</div>
                        <div class="function-metrics">
                            <div class="metric">
                                <span class="value ${riskClass}">${func.vulnerabilities.length}</span>
                                <span class="label">Vulnerabilities</span>
                            </div>
                            <div class="metric">
                                <span class="value ${complexityClass}">${func.complexity}</span>
                                <span class="label">Complexity</span>
                            </div>
                            <div class="metric">
                                <span class="value ${riskClass}">${func.securityRisk.toUpperCase()}</span>
                                <span class="label">Risk</span>
                            </div>
                        </div>
                    </div>
                    <div class="metadata-item">
                        <span>Location:</span>
                        <span class="clickable" onclick="goToLine(${func.startLine + 1})">Lines ${func.startLine + 1}-${func.endLine + 1}</span>
                    </div>
                    ${func.vulnerabilities.length > 0 ? `
                        <div class="vulnerability-list">
                            ${func.vulnerabilities.map(vuln => `
                                <div class="vulnerability-item">
                                    <div><strong>${vuln.type}</strong> (${vuln.severity.toUpperCase()})</div>
                                    <div>${vuln.description}</div>
                                    ${vuln.mitigation ? `<div><strong>Fix:</strong> ${vuln.mitigation}</div>` : ''}
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');
    }

    private generateFunctionsSummary(functions: FunctionVulnerability[]): string {
        const totalFunctions = functions.length;
        const vulnerableFunctions = functions.filter(f => f.vulnerabilities.length > 0).length;
        const highRiskFunctions = functions.filter(f => f.securityRisk === 'high' || f.securityRisk === 'critical').length;
        const avgComplexity = totalFunctions > 0 ? 
            (functions.reduce((sum, f) => sum + f.complexity, 0) / totalFunctions).toFixed(1) : '0';

        return `
            <div class="summary-content">
                <h2>📊 Executive Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <span class="icon">🔧</span>
                        <span class="number">${totalFunctions}</span>
                        <span class="label">Total Functions</span>
                    </div>
                    <div class="summary-card">
                        <span class="icon">⚠️</span>
                        <span class="number high">${vulnerableFunctions}</span>
                        <span class="label">Vulnerable Functions</span>
                    </div>
                    <div class="summary-card">
                        <span class="icon">🚨</span>
                        <span class="number critical">${highRiskFunctions}</span>
                        <span class="label">High Risk Functions</span>
                    </div>
                    <div class="summary-card">
                        <span class="icon">📊</span>
                        <span class="number">${avgComplexity}</span>
                        <span class="label">Avg Complexity</span>
                    </div>
                </div>
                
                <div class="recommendations">
                    <h3>🎯 Recommendations</h3>
                    <ul>
                        ${vulnerableFunctions > 0 ? `<li>Review and fix ${vulnerableFunctions} vulnerable function${vulnerableFunctions === 1 ? '' : 's'}</li>` : ''}
                        ${highRiskFunctions > 0 ? `<li>Prioritize ${highRiskFunctions} high-risk function${highRiskFunctions === 1 ? '' : 's'} for immediate attention</li>` : ''}
                        ${parseFloat(avgComplexity) > 6 ? '<li>Consider refactoring complex functions to improve maintainability</li>' : ''}
                        <li>Implement regular security code reviews</li>
                        <li>Add automated security testing to your CI/CD pipeline</li>
                    </ul>
                </div>
            </div>
        `;
    }

    private generateChartData(result: DeepAnalysisResult): any {
        return {
            vulnerabilities: {
                critical: result.summary.criticalCount,
                high: result.summary.highCount,
                medium: result.summary.mediumCount,
                low: result.summary.lowCount
            },
            functions: result.functionVulnerabilities.length,
            overallRisk: result.overallRisk
        };
    }

    private getCategoryIcon(category?: string): string {
        switch (category) {
            case 'security': return '🔒';
            case 'performance': return '⚡';
            case 'maintainability': return '🔧';
            case 'reliability': return '🛠️';
            case 'style': return '🎨';
            default: return '📝';
        }
    }

    private generateClassificationHtml(securityReport: any): string {
        const { summary, classifications, riskDistribution, remediationPriority } = securityReport;

        return `
            <div class="classification-content">
                <h2>🏷️ Vulnerability Classifications</h2>
                
                <div class="classification-summary">
                    <div class="summary-grid">
                        <div class="summary-card">
                            <span class="icon">📊</span>
                            <span class="number">${summary.classifiedIssues}</span>
                            <span class="label">Classified Issues</span>
                        </div>
                        <div class="summary-card">
                            <span class="icon">⚖️</span>
                            <span class="number">${summary.averageRiskScore.toFixed(1)}</span>
                            <span class="label">Avg Risk Score</span>
                        </div>
                        <div class="summary-card">
                            <span class="icon">🎯</span>
                            <span class="number">${classifications.length}</span>
                            <span class="label">Unique Types</span>
                        </div>
                    </div>
                </div>

                <div class="classification-details">
                    <h3>🔍 Detailed Classifications</h3>
                    ${classifications.map(({ classification, count, averageRiskScore, issues }: any) => `
                        <div class="classification-card">
                            <div class="classification-header">
                                <div class="classification-title">
                                    <h4>${classification.name}</h4>
                                    <div class="classification-badges">
                                        <span class="badge badge-${classification.severity}">${classification.severity.toUpperCase()}</span>
                                        <span class="badge badge-count">${count} issues</span>
                                        <span class="badge badge-risk">Risk: ${averageRiskScore.toFixed(1)}</span>
                                    </div>
                                </div>
                            </div>
                            <p class="classification-description">${classification.description}</p>
                            
                            <div class="classification-metadata">
                                <div class="metadata-grid">
                                    <div class="metadata-item">
                                        <span class="label">OWASP:</span>
                                        <span class="value">${classification.owaspTop10}</span>
                                    </div>
                                    <div class="metadata-item">
                                        <span class="label">CWE:</span>
                                        <span class="value">${classification.cweMapping.join(', ')}</span>
                                    </div>
                                    <div class="metadata-item">
                                        <span class="label">Category:</span>
                                        <span class="value">${classification.category}</span>
                                    </div>
                                    <div class="metadata-item">
                                        <span class="label">Likelihood:</span>
                                        <span class="value">${classification.likelihood}</span>
                                    </div>
                                </div>
                            </div>

                            <div class="classification-impact">
                                <h5>💼 Business Impact</h5>
                                <p>${classification.businessImpact}</p>
                                <h5>⚙️ Technical Impact</h5>
                                <p>${classification.technicalImpact}</p>
                            </div>

                            <div class="classification-remediation">
                                <h5>🛠️ Remediation Strategies</h5>
                                <ul>
                                    ${classification.remediations.slice(0, 3).map((rem: string) => `<li>${rem}</li>`).join('')}
                                </ul>
                            </div>

                            <div class="classification-examples">
                                <h5>📝 Common Examples</h5>
                                <div class="examples-list">
                                    ${classification.examples.slice(0, 2).map((example: string) => `
                                        <div class="example-item">
                                            <code>${example}</code>
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>

                <div class="remediation-priority">
                    <h3>🎯 Remediation Priority</h3>
                    <div class="priority-list">
                        ${remediationPriority.slice(0, 5).map((item: any, index: number) => `
                            <div class="priority-item priority-${index + 1}">
                                <div class="priority-header">
                                    <span class="priority-rank">#${index + 1}</span>
                                    <span class="priority-name">${item.classification}</span>
                                    <span class="priority-score">Score: ${item.priority.toFixed(1)}</span>
                                </div>
                                <div class="priority-details">
                                    <span class="priority-count">${item.count} issue${item.count === 1 ? '' : 's'}</span>
                                    <span class="priority-action">${item.remediation}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>

            <style>
                .classification-content {
                    padding: 20px 0;
                }

                .classification-summary {
                    margin-bottom: 30px;
                }

                .classification-card {
                    background: var(--bg-secondary);
                    border: 1px solid var(--border-color);
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                    transition: border-color 0.2s ease;
                }

                .classification-card:hover {
                    border-color: var(--accent-color);
                }

                .classification-header {
                    margin-bottom: 15px;
                }

                .classification-title {
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    margin-bottom: 10px;
                }

                .classification-title h4 {
                    margin: 0;
                    font-size: 1.2rem;
                    color: var(--text-primary);
                }

                .classification-badges {
                    display: flex;
                    gap: 8px;
                    flex-wrap: wrap;
                }

                .badge-count {
                    background: var(--info-color);
                    color: white;
                }

                .badge-risk {
                    background: var(--warning-color);
                    color: white;
                }

                .classification-description {
                    color: var(--text-secondary);
                    margin-bottom: 15px;
                    line-height: 1.5;
                }

                .classification-metadata {
                    margin-bottom: 15px;
                }

                .metadata-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 10px;
                }

                .metadata-item {
                    display: flex;
                    justify-content: space-between;
                    padding: 5px 0;
                }

                .metadata-item .label {
                    font-weight: 600;
                    color: var(--text-secondary);
                }

                .metadata-item .value {
                    font-family: monospace;
                    color: var(--text-primary);
                }

                .classification-impact h5,
                .classification-remediation h5,
                .classification-examples h5 {
                    margin: 15px 0 8px 0;
                    font-size: 1rem;
                    color: var(--text-primary);
                }

                .classification-impact p {
                    margin-bottom: 10px;
                    color: var(--text-secondary);
                    line-height: 1.4;
                }

                .classification-remediation ul {
                    margin: 0 0 15px 20px;
                    color: var(--text-secondary);
                }

                .classification-remediation li {
                    margin-bottom: 5px;
                    line-height: 1.4;
                }

                .examples-list {
                    margin-bottom: 15px;
                }

                .example-item {
                    background: rgba(0, 0, 0, 0.1);
                    border-radius: 4px;
                    padding: 8px 12px;
                    margin-bottom: 8px;
                }

                .example-item code {
                    font-family: 'Courier New', monospace;
                    font-size: 0.9rem;
                    color: var(--accent-color);
                }

                .priority-list {
                    margin-top: 15px;
                }

                .priority-item {
                    background: var(--bg-secondary);
                    border: 1px solid var(--border-color);
                    border-radius: 6px;
                    padding: 15px;
                    margin-bottom: 10px;
                    transition: all 0.2s ease;
                }

                .priority-item:hover {
                    border-color: var(--accent-color);
                    transform: translateX(5px);
                }

                .priority-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 8px;
                }

                .priority-rank {
                    background: var(--accent-color);
                    color: white;
                    padding: 4px 8px;
                    border-radius: 12px;
                    font-weight: bold;
                    font-size: 0.9rem;
                }

                .priority-name {
                    font-weight: 600;
                    font-size: 1.1rem;
                }

                .priority-score {
                    background: var(--warning-color);
                    color: white;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.9rem;
                }

                .priority-details {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    color: var(--text-secondary);
                    font-size: 0.9rem;
                }

                .priority-count {
                    font-weight: 500;
                }

                .priority-action {
                    flex: 1;
                    text-align: right;
                    padding-left: 10px;
                }

                @media (max-width: 768px) {
                    .classification-title {
                        flex-direction: column;
                        align-items: flex-start;
                    }

                    .classification-badges {
                        margin-top: 10px;
                    }

                    .metadata-grid {
                        grid-template-columns: 1fr;
                    }

                    .priority-header {
                        flex-direction: column;
                        align-items: flex-start;
                        gap: 8px;
                    }

                    .priority-details {
                        flex-direction: column;
                        align-items: flex-start;
                        gap: 5px;
                    }

                    .priority-action {
                        text-align: left;
                        padding-left: 0;
                    }
                }
            </style>
        `;
    }
}