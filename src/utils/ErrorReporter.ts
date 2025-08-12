import * as vscode from 'vscode';

export interface DetailedError {
    message: string;
    code?: string;
    category: 'ai-provider' | 'analysis' | 'configuration' | 'network' | 'validation' | 'unknown';
    severity: 'low' | 'medium' | 'high' | 'critical';
    timestamp: Date;
    context?: Record<string, any>;
    suggestions: string[];
    technicalDetails?: string;
    userFriendlyMessage: string;
}

export class ErrorReporter {
    private static readonly ERROR_PATTERNS = [
        // AI Provider Errors
        {
            pattern: /(?:401|unauthorized|invalid.*api.*key|authentication)/i,
            category: 'ai-provider' as const,
            severity: 'high' as const,
            userMessage: 'Invalid API key',
            suggestions: [
                'Verify your API key is correct',
                'Check if your API key has sufficient credits',
                'Ensure the API key has required permissions',
                'Try regenerating your API key from the provider dashboard'
            ]
        },
        {
            pattern: /(?:403|forbidden|access.*denied)/i,
            category: 'ai-provider' as const,
            severity: 'high' as const,
            userMessage: 'Access forbidden',
            suggestions: [
                'Check your API key permissions',
                'Verify your account has access to the requested model',
                'Contact your API provider for access issues'
            ]
        },
        {
            pattern: /(?:429|rate.*limit|too.*many.*requests)/i,
            category: 'ai-provider' as const,
            severity: 'medium' as const,
            userMessage: 'Rate limit exceeded',
            suggestions: [
                'Wait a few minutes before trying again',
                'Consider upgrading your API plan for higher limits',
                'Reduce the analysis frequency in settings',
                'Use smaller chunk sizes to reduce API calls'
            ]
        },
        {
            pattern: /(?:500|502|503|504|server.*error|service.*unavailable)/i,
            category: 'ai-provider' as const,
            severity: 'medium' as const,
            userMessage: 'AI service temporarily unavailable',
            suggestions: [
                'Try again in a few minutes',
                'Check the AI provider status page',
                'Switch to offline-only mode temporarily',
                'Use a different AI provider if available'
            ]
        },
        {
            pattern: /(?:timeout|timed.*out|network.*error|connection.*failed)/i,
            category: 'network' as const,
            severity: 'medium' as const,
            userMessage: 'Network connection failed',
            suggestions: [
                'Check your internet connection',
                'Try increasing the request timeout in settings',
                'Disable VPN or proxy if using one',
                'Check firewall settings'
            ]
        },
        {
            pattern: /(?:parse.*error|invalid.*json|malformed)/i,
            category: 'ai-provider' as const,
            severity: 'low' as const,
            userMessage: 'Received invalid response from AI provider',
            suggestions: [
                'Try the request again',
                'Check if the AI provider is experiencing issues',
                'Enable debug mode for more details',
                'Report this issue if it persists'
            ]
        },
        {
            pattern: /(?:no.*api.*key|missing.*api.*key|api.*key.*required)/i,
            category: 'configuration' as const,
            severity: 'high' as const,
            userMessage: 'API key not configured',
            suggestions: [
                'Open the settings panel and add your API key',
                'Use the "Configure API Key" command',
                'Switch to offline-only mode if you prefer'
            ]
        },
        {
            pattern: /(?:invalid.*endpoint|invalid.*url|malformed.*url)/i,
            category: 'configuration' as const,
            severity: 'high' as const,
            userMessage: 'Invalid API endpoint URL',
            suggestions: [
                'Check the endpoint URL format (must start with http:// or https://)',
                'Verify the endpoint URL is correct for your provider',
                'Test the endpoint manually in a browser or API client'
            ]
        }
    ];

    public static analyzeError(error: any, context?: Record<string, any>): DetailedError {
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorStack = error instanceof Error ? error.stack : undefined;
        
        // Find matching pattern
        const matchingPattern = this.ERROR_PATTERNS.find(pattern => 
            pattern.pattern.test(errorMessage)
        );

        const category = matchingPattern?.category || 'unknown';
        const severity = matchingPattern?.severity || 'medium';
        const suggestions = matchingPattern?.suggestions || [
            'Try the operation again',
            'Check your configuration settings',
            'Enable debug mode for more information'
        ];
        const userFriendlyMessage = matchingPattern?.userMessage || 'An unexpected error occurred';

        return {
            message: errorMessage,
            category,
            severity,
            timestamp: new Date(),
            context,
            suggestions,
            technicalDetails: errorStack,
            userFriendlyMessage
        };
    }

    public static async showErrorDialog(detailedError: DetailedError): Promise<void> {
        const severityIcon = this.getSeverityIcon(detailedError.severity);
        const categoryIcon = this.getCategoryIcon(detailedError.category);
        
        const actions: string[] = [];
        
        // Add category-specific actions
        switch (detailedError.category) {
            case 'ai-provider':
            case 'configuration':
                actions.push('Open Settings', 'View Details');
                break;
            case 'network':
                actions.push('Retry', 'View Details');
                break;
            default:
                actions.push('View Details');
        }

        const selection = await vscode.window.showErrorMessage(
            `${severityIcon} ${detailedError.userFriendlyMessage}`,
            ...actions
        );

        switch (selection) {
            case 'Open Settings':
                vscode.commands.executeCommand('codeSecurityAnalyzer.openSettings');
                break;
            case 'Retry':
                // Return a special result to indicate retry
                break;
            case 'View Details':
                this.showDetailedErrorPanel(detailedError);
                break;
        }
    }

    private static showDetailedErrorPanel(detailedError: DetailedError): void {
        const panel = vscode.window.createWebviewPanel(
            'errorDetails',
            'Error Details - Code Security Analyzer',
            vscode.ViewColumn.Beside,
            { enableScripts: true }
        );

        panel.webview.html = this.generateErrorDetailsHtml(detailedError);
    }

    private static generateErrorDetailsHtml(error: DetailedError): string {
        const severityColor = this.getSeverityColor(error.severity);
        const categoryIcon = this.getCategoryIcon(error.category);
        
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error Details</title>
                <style>
                    body {
                        font-family: var(--vscode-font-family);
                        padding: 20px;
                        background-color: var(--vscode-editor-background);
                        color: var(--vscode-editor-foreground);
                        line-height: 1.6;
                    }
                    .error-header {
                        background: linear-gradient(135deg, ${severityColor}, ${this.darkenColor(severityColor)});
                        color: white;
                        padding: 20px;
                        border-radius: 8px;
                        margin-bottom: 20px;
                        text-align: center;
                    }
                    .error-header h1 {
                        margin: 0;
                        font-size: 1.5em;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 10px;
                    }
                    .error-meta {
                        font-size: 0.9em;
                        opacity: 0.9;
                        margin-top: 8px;
                    }
                    .section {
                        background-color: var(--vscode-editor-selectionBackground);
                        border-radius: 8px;
                        padding: 20px;
                        margin-bottom: 20px;
                        border-left: 4px solid ${severityColor};
                    }
                    .section h3 {
                        margin-top: 0;
                        color: var(--vscode-foreground);
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }
                    .suggestions {
                        list-style: none;
                        padding: 0;
                    }
                    .suggestions li {
                        background-color: var(--vscode-textBlockQuote-background);
                        padding: 12px;
                        margin-bottom: 8px;
                        border-radius: 4px;
                        border-left: 3px solid #28a745;
                        display: flex;
                        align-items: flex-start;
                        gap: 10px;
                    }
                    .suggestions li::before {
                        content: "💡";
                        font-size: 1.1em;
                        flex-shrink: 0;
                    }
                    .technical-details {
                        background-color: var(--vscode-textCodeBlock-background);
                        border: 1px solid var(--vscode-panel-border);
                        border-radius: 4px;
                        padding: 15px;
                        font-family: 'Courier New', monospace;
                        font-size: 0.85em;
                        overflow-x: auto;
                        white-space: pre-wrap;
                    }
                    .context-table {
                        width: 100%;
                        border-collapse: collapse;
                        font-size: 0.9em;
                    }
                    .context-table th,
                    .context-table td {
                        text-align: left;
                        padding: 8px 12px;
                        border-bottom: 1px solid var(--vscode-panel-border);
                    }
                    .context-table th {
                        background-color: var(--vscode-editor-selectionBackground);
                        font-weight: 600;
                    }
                    .copy-button {
                        background-color: var(--vscode-button-background);
                        color: var(--vscode-button-foreground);
                        border: none;
                        padding: 8px 16px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 0.9em;
                        margin-top: 10px;
                    }
                    .copy-button:hover {
                        background-color: var(--vscode-button-hoverBackground);
                    }
                    .severity-badge {
                        display: inline-block;
                        padding: 4px 12px;
                        border-radius: 12px;
                        font-size: 0.8em;
                        font-weight: bold;
                        color: white;
                        background-color: ${severityColor};
                        text-transform: uppercase;
                    }
                </style>
            </head>
            <body>
                <div class="error-header">
                    <h1>
                        <span style="font-size: 2em;">${categoryIcon}</span>
                        ${error.userFriendlyMessage}
                    </h1>
                    <div class="error-meta">
                        <span class="severity-badge">${error.severity} severity</span>
                        <span style="margin-left: 16px;">
                            ${error.timestamp.toLocaleString()}
                        </span>
                    </div>
                </div>

                <div class="section">
                    <h3>💡 Suggested Solutions</h3>
                    <ul class="suggestions">
                        ${error.suggestions.map(suggestion => `<li>${suggestion}</li>`).join('')}
                    </ul>
                </div>

                ${error.context && Object.keys(error.context).length > 0 ? `
                <div class="section">
                    <h3>📋 Context Information</h3>
                    <table class="context-table">
                        <thead>
                            <tr>
                                <th>Property</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${Object.entries(error.context).map(([key, value]) => `
                                <tr>
                                    <td><strong>${key}</strong></td>
                                    <td>${this.formatContextValue(value)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                ` : ''}

                <div class="section">
                    <h3>🔧 Technical Details</h3>
                    <p><strong>Error Message:</strong> ${error.message}</p>
                    <p><strong>Category:</strong> ${error.category}</p>
                    
                    ${error.technicalDetails ? `
                        <div>
                            <strong>Stack Trace:</strong>
                            <div class="technical-details">${error.technicalDetails}</div>
                            <button class="copy-button" onclick="copyToClipboard()">Copy Stack Trace</button>
                        </div>
                    ` : ''}
                </div>

                <script>
                    function copyToClipboard() {
                        const text = document.querySelector('.technical-details').textContent;
                        navigator.clipboard.writeText(text).then(() => {
                            const button = document.querySelector('.copy-button');
                            const originalText = button.textContent;
                            button.textContent = 'Copied!';
                            setTimeout(() => {
                                button.textContent = originalText;
                            }, 2000);
                        });
                    }
                </script>
            </body>
            </html>
        `;
    }

    private static getSeverityIcon(severity: string): string {
        switch (severity) {
            case 'critical': return '🚨';
            case 'high': return '❌';
            case 'medium': return '⚠️';
            case 'low': return '⚡';
            default: return '❓';
        }
    }

    private static getCategoryIcon(category: string): string {
        switch (category) {
            case 'ai-provider': return '🤖';
            case 'network': return '🌐';
            case 'configuration': return '⚙️';
            case 'analysis': return '🔍';
            case 'validation': return '✅';
            default: return '❓';
        }
    }

    private static getSeverityColor(severity: string): string {
        switch (severity) {
            case 'critical': return '#dc3545';
            case 'high': return '#fd7e14';
            case 'medium': return '#ffc107';
            case 'low': return '#17a2b8';
            default: return '#6c757d';
        }
    }

    private static darkenColor(color: string): string {
        // Simple color darkening for gradient effect
        const colors: Record<string, string> = {
            '#dc3545': '#c82333',
            '#fd7e14': '#e85d04',
            '#ffc107': '#e0a800',
            '#17a2b8': '#138496',
            '#6c757d': '#5a6268'
        };
        return colors[color] || color;
    }

    private static formatContextValue(value: any): string {
        if (typeof value === 'object') {
            return JSON.stringify(value, null, 2);
        }
        return String(value);
    }

    public static logError(error: DetailedError): void {
        const debugMode = vscode.workspace.getConfiguration('codeSecurityAnalyzer').get<boolean>('debugMode', false);
        
        if (debugMode) {
            console.error('🚨 Code Security Analyzer Error:', {
                message: error.message,
                category: error.category,
                severity: error.severity,
                timestamp: error.timestamp,
                context: error.context,
                technicalDetails: error.technicalDetails
            });
        }
    }
}