import * as vscode from 'vscode';
import { SecurityIssue } from './SecurityIssue';
import { SecurityCodeLensProvider } from './SecurityCodeLensProvider';
import { SecurityHoverProvider } from './SecurityHoverProvider';
import { SecurityCodeActionProvider } from './SecurityCodeActionProvider';
import { ComplexityAnalyzer } from './ComplexityAnalyzer.1';
import { HybridAnalyzer } from './analyzers/HybridAnalyzer';
import { AIProviderManager } from './core/AIProviderManager';
import { SmartAIAnalyzer } from './analyzers/SmartAIAnalyzer';
import { SettingsWebviewProvider } from './ui/SettingsWebviewProvider';
import { AnalysisReportWebview } from './ui/AnalysisReportWebview';
import { logger } from './core/DebugLogger';
import { ProductKeyManager } from './core/ProductKeyManager';
export interface AIFixSuggestion {
    originalCode: string;
    fixedCode: string;
    explanation: string;
    confidence: number;
    riskLevel: 'low' | 'medium' | 'high';
    steps: string[];
}

export interface ComplexityMetrics {
    cyclomaticComplexity: number;
    cognitiveComplexity: number;
    linesOfCode: number;
    parameterCount: number;
    nestingLevel: number;
}

export interface FunctionInfo {
    name: string;
    range: vscode.Range;
    parameters: string[];
    complexity: ComplexityMetrics;
    bodyRange: vscode.Range;
}

export interface AIAnalysisResult {
    issues: Array<{
        type: 'vulnerability' | 'error' | 'warning' | 'complexity' | 'best-practice';
        severity: 'error' | 'warning' | 'info';
        message: string;
        description: string;
        suggestion: string;
        lineNumber: number;
        columnStart: number;
        columnEnd: number;
        confidence: number;
        cveReference?: string;
        complexityScore?: number;
        functionName?: string;
    }>;
    summary: string;
}

export interface AnalysisContext {
    document: vscode.TextDocument;
    issues: SecurityIssue[];
    analysisType: string;
    executionTime: number;
    aiProvider?: string;
}

// Global state
let analysisTimeout: NodeJS.Timeout | undefined;
let diagnosticCollection: vscode.DiagnosticCollection;
let codeLensProvider: SecurityCodeLensProvider;
let settingsWebviewProvider: SettingsWebviewProvider;
let analysisReportWebview: AnalysisReportWebview;
let statusBarItem: vscode.StatusBarItem;
let currentAnalysisContext: AnalysisContext | null = null;
let productKeyManager: ProductKeyManager;

export async function activate(context: vscode.ExtensionContext) {
    console.log('🚀 Code Security Analyzer (Enhanced) starting...');

    // Initialize product key manager
    productKeyManager = new ProductKeyManager(context);
    
    // Check if the extension is activated with a valid product key
    const isActivated = await productKeyManager.isActivated();
    if (!isActivated) {
        // Show modal dialog that blocks until product key is entered
        let activationSuccessful = false;
        
        while (!activationSuccessful) {
            const choice = await vscode.window.showErrorMessage(
                'Code Security Analyzer requires a valid product key to run. Please contact the administrator or check your documentation for the product key.',
                { modal: true },
                'Enter Product Key'
            );
            
            if (choice === 'Enter Product Key') {
                activationSuccessful = await productKeyManager.showActivationDialog();
                if (!activationSuccessful) {
                    const retry = await vscode.window.showErrorMessage(
                        'Invalid product key entered. Please verify your product key and try again.',
                        { modal: true },
                        'Try Again',
                        'Cancel'
                    );
                    if (retry !== 'Try Again') {
                        // User cancelled, block extension activation
                        vscode.window.showErrorMessage('Code Security Analyzer activation cancelled. Extension disabled.');
                        return;
                    }
                }
            } else {
                // User cancelled, block extension activation
                vscode.window.showErrorMessage('Code Security Analyzer requires activation to run. Extension disabled.');
                return;
            }
        }
        
        vscode.window.showInformationMessage('✅ Code Security Analyzer activated successfully!');
    } else {
        console.log('✅ Extension already activated with valid product key');
    }

    // Initialize core components
    diagnosticCollection = vscode.languages.createDiagnosticCollection('codeSecurityAnalyzer');
    context.subscriptions.push(diagnosticCollection);

    // Initialize providers
    codeLensProvider = new SecurityCodeLensProvider();
    const hoverProvider = new SecurityHoverProvider();
    const codeActionProvider = new SecurityCodeActionProvider();
    
    // Initialize webview provider for settings
    settingsWebviewProvider = new SettingsWebviewProvider(context.extensionUri);
    
    // Initialize analysis report webview
    analysisReportWebview = new AnalysisReportWebview(context.extensionUri);
    
    // Initialize status bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'codeSecurityAnalyzer.openSettings';
    statusBarItem.tooltip = 'Click to open Code Security Analyzer settings';
    context.subscriptions.push(statusBarItem);
    await updateStatusBar();

    // Register providers for supported languages
    const supportedLanguages = [
        'javascript', 'typescript', 'python', 'java', 'csharp',
        'php', 'go', 'rust', 'cpp', 'c', 'dart'
    ];

    for (const language of supportedLanguages) {
        context.subscriptions.push(
            vscode.languages.registerCodeLensProvider(language, codeLensProvider),
            vscode.languages.registerHoverProvider(language, hoverProvider),
            vscode.languages.registerCodeActionsProvider(language, codeActionProvider)
        );
    }

    // Register webview provider
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            SettingsWebviewProvider.viewType,
            settingsWebviewProvider
        )
    );

    // Register commands
    registerCommands(context);

    // Set up event listeners
    setupEventListeners(context);

    // Perform initial analysis if there's an active editor
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor && isLanguageSupported(activeEditor.document.languageId)) {
        setTimeout(() => analyzeDocument(activeEditor.document), 1000);
    }

    console.log('✅ Extension activation completed');
}

function registerCommands(context: vscode.ExtensionContext) {
    // Main analysis command
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.analyzeActiveFile', async () => {
            try {
                await productKeyManager.requireAuthentication();
            } catch (error) {
                vscode.window.showErrorMessage('Authentication required. Please restart the extension to activate.');
                return;
            }

            const activeEditor = vscode.window.activeTextEditor;
            if (!activeEditor) {
                vscode.window.showWarningMessage('No active file to analyze');
                return;
            }

            if (!isLanguageSupported(activeEditor.document.languageId)) {
                vscode.window.showWarningMessage(
                    `Language ${activeEditor.document.languageId} is not supported for security analysis`
                );
                return;
            }

            await analyzeDocument(activeEditor.document, true);
        })
    );

    // Settings panel command
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.openSettings', () => {
            vscode.commands.executeCommand('workbench.view.extension.codeSecurityAnalyzer');
        })
    );

    // Complexity report command
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.showComplexityReport', async () => {
            try {
                await productKeyManager.requireAuthentication();
            } catch (error) {
                vscode.window.showErrorMessage('Authentication required. Please restart the extension to activate.');
                return;
            }

            const activeEditor = vscode.window.activeTextEditor;
            if (!activeEditor) {
                vscode.window.showWarningMessage('No active file to analyze');
                return;
            }

            try {
                const functions = ComplexityAnalyzer.analyzeFunctions(activeEditor.document);
                const panel = vscode.window.createWebviewPanel(
                    'complexityReport',
                    'Code Complexity Report',
                    vscode.ViewColumn.Beside,
                    { enableScripts: true }
                );

                panel.webview.html = generateComplexityReportHtml(functions);
            } catch (error) {
                vscode.window.showErrorMessage(`Failed to generate complexity report: ${error}`);
            }
        })
    );

    // Deep Security Analysis command
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.deepSecurityAnalysis', async () => {
            try {
                await productKeyManager.requireAuthentication();
            } catch (error) {
                vscode.window.showErrorMessage('Authentication required. Please restart the extension to activate.');
                return;
            }
            const activeEditor = vscode.window.activeTextEditor;
            if (!activeEditor) {
                vscode.window.showWarningMessage('No active file to analyze');
                return;
            }

            if (!isLanguageSupported(activeEditor.document.languageId)) {
                vscode.window.showWarningMessage(
                    `Language ${activeEditor.document.languageId} is not supported for deep analysis`
                );
                return;
            }

            if (!AIProviderManager.hasValidConfig()) {
                vscode.window.showWarningMessage(
                    'Deep analysis requires AI provider configuration.',
                    'Open Settings'
                ).then(selection => {
                    if (selection === 'Open Settings') {
                        vscode.commands.executeCommand('codeSecurityAnalyzer.openSettings');
                    }
                });
                return;
            }

            await performDeepAnalysis(activeEditor.document);
        })
    );

    // Toggle Deep Mode command
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.toggleDeepMode', async () => {
            const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
            const currentMode = config.get<boolean>('enableDeepSecurityAnalysis', false);
            
            await config.update('enableDeepSecurityAnalysis', !currentMode, vscode.ConfigurationTarget.Global);
            
            const mode = currentMode ? 'disabled' : 'enabled';
            vscode.window.showInformationMessage(`🔍 Deep Security Analysis ${mode}`);
            updateStatusBar();
        })
    );

    // Legacy API key configuration (for backward compatibility)
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.configureApiKey', async () => {
            const providers = AIProviderManager.getProviders();
            const items = providers.map(p => ({ 
                label: p.name, 
                description: p.description,
                providerId: p.id 
            }));

            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select AI provider to configure'
            });

            if (selected) {
                const apiKey = await vscode.window.showInputBox({
                    prompt: `Enter API key for ${selected.label}`,
                    password: true,
                    placeHolder: 'sk-...'
                });

                if (apiKey) {
                    try {
                        await AIProviderManager.setApiKey(selected.providerId, apiKey);
                        await AIProviderManager.setProvider(selected.providerId);
                        vscode.window.showInformationMessage(
                            `✅ ${selected.label} configured successfully!`
                        );
                        updateStatusBar();
                        settingsWebviewProvider.refresh();
                    } catch (error) {
                        vscode.window.showErrorMessage(`Failed to configure API key: ${error}`);
                    }
                }
            }
        })
    );

    // AI provider switching
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.switchAiProvider', async () => {
            const providers = AIProviderManager.getProviders();
            const current = AIProviderManager.getCurrentConfig();
            
            const items = providers.map(p => ({
                label: p.name,
                description: p.id === current?.provider.id ? '(Current)' : p.description,
                providerId: p.id
            }));

            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select AI provider'
            });

            if (selected) {
                try {
                    await AIProviderManager.setProvider(selected.providerId);
                    vscode.window.showInformationMessage(`Switched to ${selected.label}`);
                    updateStatusBar();
                    settingsWebviewProvider.refresh();
                } catch (error) {
                    vscode.window.showErrorMessage(`Failed to switch provider: ${error}`);
                }
            }
        })
    );

    // Toggle offline mode
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.toggleOfflineMode', async () => {
            const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
            const currentMode = config.get<boolean>('enableAIAnalysis', true);
            
            await config.update('enableAIAnalysis', !currentMode, vscode.ConfigurationTarget.Global);
            
            const mode = currentMode ? 'Offline' : 'AI-Enhanced';
            vscode.window.showInformationMessage(`Switched to ${mode} mode`);
            updateStatusBar();
        })
    );

    // AI fix commands
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.getAIFix', async (documentUri: string | vscode.Uri, issue: SecurityIssue) => {
            try {
                await productKeyManager.requireAuthentication();
            } catch (error) {
                vscode.window.showErrorMessage('Authentication required. Please restart the extension to activate.');
                return;
            }
            await handleGetAIFix(context, documentUri, issue);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.applyAIFix', async (documentUri: string | vscode.Uri, issue: SecurityIssue) => {
            try {
                await productKeyManager.requireAuthentication();
            } catch (error) {
                vscode.window.showErrorMessage('Authentication required. Please restart the extension to activate.');
                return;
            }
            await handleApplyAIFix(context, documentUri, issue);
        })
    );

    // Issue details command
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.showIssueDetails', (issue: SecurityIssue) => {
            showIssueDetailsPanel(issue);
        })
    );

    // Product Key Management Commands (Limited functionality)
    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurityAnalyzer.showActivationStatus', async () => {
            const activationInfo = await productKeyManager.getActivationInfo();
            if (activationInfo.isActivated) {
                vscode.window.showInformationMessage(
                    `Code Security Analyzer is activated and running.\nActivated: ${new Date(activationInfo.activationTimestamp!).toLocaleString()}`
                );
            }
        })
    );
}

function setupEventListeners(context: vscode.ExtensionContext) {
    // Document change listener with debouncing
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor?.document === event.document && 
                isLanguageSupported(event.document.languageId)) {
                
                clearTimeout(analysisTimeout);
                
                const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
                const delay = config.get<number>('analysisDelay', 2000);
                
                analysisTimeout = setTimeout(() => {
                    analyzeDocument(event.document);
                }, delay);
            }
        })
    );

    // Active editor change listener
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && isLanguageSupported(editor.document.languageId)) {
                clearTimeout(analysisTimeout);
                analysisTimeout = setTimeout(() => {
                    analyzeDocument(editor.document);
                }, 500);
            }
            updateStatusBar();
        })
    );

    // Configuration change listener
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(event => {
            if (event.affectsConfiguration('codeSecurityAnalyzer')) {
                updateStatusBar();
                settingsWebviewProvider.refresh();
                
                // Re-analyze current document if analysis settings changed
                const activeEditor = vscode.window.activeTextEditor;
                if (activeEditor && isLanguageSupported(activeEditor.document.languageId)) {
                    setTimeout(() => analyzeDocument(activeEditor.document), 500);
                }
            }
        })
    );
}

async function analyzeDocument(document: vscode.TextDocument, forceAnalysis: boolean = false): Promise<void> {
    if (!isLanguageSupported(document.languageId)) {
        return;
    }

    // Check authentication for all analysis
    const isAuthenticated = await productKeyManager.isAuthenticated();
    if (!isAuthenticated) {
        console.log('Analysis skipped - extension not authenticated');
        return;
    }

    try {
        // Update status to show analysis in progress
        statusBarItem.text = '$(loading~spin) Analyzing...';
        statusBarItem.show();

        const progressCallback = (message: string, tooltip?: string) => {
            statusBarItem.text = message;
            statusBarItem.tooltip = tooltip || 'Code Security Analysis in progress';
        };

        console.log(`🔍 Starting analysis of ${document.fileName}`);
        const startTime = Date.now();

        // Perform hybrid analysis
        const result = await HybridAnalyzer.analyzeDocument(document, progressCallback);
        
        console.log(`✅ Analysis completed in ${result.executionTime}ms`);
        console.log(`   Found ${result.issues.length} issues`);
        console.log(`   Analysis type: ${result.analysisType}`);
        console.log(`   AI analysis used: ${result.aiAnalysisUsed}`);

        // Update diagnostic collection
        const diagnostics: vscode.Diagnostic[] = result.issues
            .filter(issue => issue.type !== 'best-practice' && issue.type !== 'complexity')
            .map(issue => {
                const diagnostic = new vscode.Diagnostic(
                    issue.range,
                    issue.message,
                    issue.severity
                );
                diagnostic.source = issue.source;
                diagnostic.code = issue.type;
                return diagnostic;
            });

        diagnosticCollection.set(document.uri, diagnostics);
        codeLensProvider.refresh();

        // Store current analysis context
        const aiConfig = AIProviderManager.getCurrentConfig();
        currentAnalysisContext = {
            document,
            issues: result.issues,
            analysisType: result.analysisType,
            executionTime: result.executionTime,
            aiProvider: aiConfig ? `${aiConfig.provider.name} (${aiConfig.model})` : undefined
        };

        // Update status bar with results
        updateStatusBarWithResults(result);

        if (forceAnalysis) {
            const vulnerabilities = result.issues.filter(i => i.type === 'vulnerability').length;
            const total = result.issues.length;
            
            vscode.window.showInformationMessage(
                `Security analysis completed: ${vulnerabilities} vulnerabilities, ${total} total issues`
            );
        }

    } catch (error) {
        console.error('❌ Analysis failed:', error);
        
        statusBarItem.text = '$(error) Analysis failed';
        statusBarItem.tooltip = `Analysis failed: ${error}`;
        
        if (forceAnalysis) {
            vscode.window.showErrorMessage(`Security analysis failed: ${error}`);
        }
    }
}

async function updateStatusBar(): Promise<void> {
    const config = AIProviderManager.getCurrentConfig();
    
    let statusText: string;
    let tooltip: string;
    
    if (config && config.apiKey) {
        statusText = `$(shield) ${config.provider.name}`;
        tooltip = `Code Security Analyzer\nProvider: ${config.provider.name}\nModel: ${config.model}\nClick to open settings`;
    } else {
        statusText = '$(shield) Security (Offline)';
        tooltip = 'Code Security Analyzer (Offline mode)\nClick to configure AI provider';
    }
    
    statusBarItem.text = statusText;
    statusBarItem.tooltip = tooltip;
    statusBarItem.backgroundColor = undefined;
    statusBarItem.show();
}

function updateStatusBarWithResults(result: any): void {
    const vulnerabilities = result.issues.filter((i: SecurityIssue) => i.type === 'vulnerability').length;
    const total = result.issues.length;
    
    let icon = '$(shield)';
    if (vulnerabilities > 0) {
        icon = vulnerabilities > 3 ? '$(error)' : '$(warning)';
    }
    
    // Enhanced status bar for deep analysis
    if (result.analysisType === 'deep') {
        icon = '🔬';
        const riskLevel = result.deepAnalysisResult?.overallRisk || 'low';
        const riskIcon = riskLevel === 'critical' ? '🚨' : riskLevel === 'high' ? '🔴' : riskLevel === 'medium' ? '🟡' : '🟢';
        statusBarItem.text = `${icon} ${riskIcon} ${vulnerabilities}/${total}`;
        statusBarItem.tooltip = `Deep Security Analysis\n${vulnerabilities} vulnerabilities\n${total} total issues\nRisk Level: ${riskLevel}\nFunctions: ${result.deepAnalysisResult?.summary.functionsAnalyzed || 0}\nClick for settings`;
    } else {
        statusBarItem.text = `${icon} ${vulnerabilities}/${total}`;
        statusBarItem.tooltip = `Security Analysis Results\n${vulnerabilities} vulnerabilities\n${total} total issues\nAnalysis: ${result.analysisType}\nClick for settings`;
    }
}

async function performDeepAnalysis(document: vscode.TextDocument): Promise<void> {
    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Deep Security Analysis',
            cancellable: false
        }, async (progress) => {
            const progressCallback = (message: string, tooltip?: string) => {
                progress.report({ message, increment: undefined });
                statusBarItem.text = message;
                statusBarItem.tooltip = tooltip || 'Deep Security Analysis in progress';
            };

            const startTime = Date.now();
            console.log(`🔬 Starting deep analysis of ${document.fileName}`);

            // Perform deep analysis
            const result = await HybridAnalyzer.analyzeDocumentDeep(document, progressCallback);
            
            const executionTime = Date.now() - startTime;
            console.log(`✅ Deep analysis completed in ${executionTime}ms`);
            console.log(`   Found ${result.issues.length} issues across ${result.functionVulnerabilities.length} functions`);
            console.log(`   Overall risk: ${result.overallRisk}`);

            // Update diagnostic collection with enhanced information
            const diagnostics: vscode.Diagnostic[] = result.issues
                .filter(issue => issue.type !== 'best-practice')
                .map(issue => {
                    const diagnostic = new vscode.Diagnostic(
                        issue.range,
                        issue.message,
                        issue.severity
                    );
                    diagnostic.source = issue.source;
                    diagnostic.code = issue.type;
                    
                    // Add enhanced metadata for deep analysis
                    if (issue.isDeepAnalysis) {
                        diagnostic.tags = [vscode.DiagnosticTag.Unnecessary]; // Use as indicator for enhanced UI
                    }
                    
                    return diagnostic;
                });

            diagnosticCollection.set(document.uri, diagnostics);
            codeLensProvider.refresh();

            // Store enhanced analysis context
            const aiConfig = AIProviderManager.getCurrentConfig();
            currentAnalysisContext = {
                document,
                issues: result.issues,
                analysisType: 'deep',
                executionTime,
                aiProvider: aiConfig ? `${aiConfig.provider.name} (${aiConfig.model})` : undefined
            };

            // Update status bar with deep analysis results
            updateStatusBarWithResults({
                issues: result.issues,
                analysisType: 'deep',
                deepAnalysisResult: result
            });

            // Show detailed analysis report in webview
            await analysisReportWebview.showReport(document, result, executionTime);

            // Show comprehensive results notification
            const criticalCount = result.summary.criticalCount;
            const highCount = result.summary.highCount;
            const totalVulns = result.summary.totalVulnerabilities;
            const functionsAnalyzed = result.summary.functionsAnalyzed;

            if (totalVulns === 0) {
                vscode.window.showInformationMessage(
                    `🛡️ Deep Security Analysis: No vulnerabilities detected across ${functionsAnalyzed} function${functionsAnalyzed === 1 ? '' : 's'}! Your code appears secure.`,
                    'View Report'
                ).then((selection: string | undefined) => {
                    if (selection === 'View Report') {
                        analysisReportWebview.showReport(document, result, executionTime);
                    }
                });
            } else {
                const message = criticalCount > 0 ? 'showErrorMessage' : highCount > 0 ? 'showWarningMessage' : 'showInformationMessage';
                (vscode.window as any)[message](
                    `🔬 Deep Analysis: Found ${totalVulns} security issue${totalVulns === 1 ? '' : 's'} ` +
                    `(${criticalCount} critical, ${highCount} high) across ${functionsAnalyzed} function${functionsAnalyzed === 1 ? '' : 's'}. ` +
                    `Overall risk: ${result.overallRisk.toUpperCase()}.`,
                    'View Report'
                ).then((selection: string | undefined) => {
                    if (selection === 'View Report') {
                        analysisReportWebview.showReport(document, result, executionTime);
                    }
                });
            }
        });

    } catch (error) {
        console.error('❌ Deep analysis failed:', error);
        statusBarItem.text = '$(error) Deep analysis failed';
        statusBarItem.tooltip = `Deep analysis failed: ${error}`;
        vscode.window.showErrorMessage(`Deep security analysis failed: ${error}`);
    }
}

function isLanguageSupported(languageId: string): boolean {
    const supportedLanguages = [
        'javascript', 'typescript', 'python', 'java', 'csharp',
        'php', 'go', 'rust', 'cpp', 'c', 'dart'
    ];
    return supportedLanguages.includes(languageId);
}

async function handleGetAIFix(
    context: vscode.ExtensionContext,
    documentUri: string | vscode.Uri,
    issue: SecurityIssue
): Promise<void> {
    if (!AIProviderManager.hasValidConfig()) {
        vscode.window.showWarningMessage(
            'AI provider not configured. Please configure an AI provider in settings.',
            'Open Settings'
        ).then(selection => {
            if (selection === 'Open Settings') {
                vscode.commands.executeCommand('codeSecurityAnalyzer.openSettings');
            }
        });
        return;
    }

    try {
        const document = await vscode.workspace.openTextDocument(
            typeof documentUri === 'string' ? vscode.Uri.parse(documentUri) : documentUri
        );

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Getting AI fix suggestion...',
            cancellable: false
        }, async () => {
            const fixSuggestion = await SmartAIAnalyzer.generateFixSuggestion(issue, document);
            
            if (fixSuggestion) {
                issue.aiFixSuggestion = fixSuggestion;
                showAIFixPanel(context, issue, fixSuggestion, documentUri);
                codeLensProvider.refresh();
                vscode.window.showInformationMessage('AI fix suggestion generated!');
            } else {
                vscode.window.showWarningMessage('Could not generate AI fix suggestion. Please try again.');
            }
        });
    } catch (error) {
        console.error('Error getting AI fix:', error);
        vscode.window.showErrorMessage(`Failed to get AI fix: ${error}`);
    }
}

async function handleApplyAIFix(
    context: vscode.ExtensionContext,
    documentUri: string | vscode.Uri,
    issue: SecurityIssue
): Promise<void> {
    try {
        const document = await vscode.workspace.openTextDocument(
            typeof documentUri === 'string' ? vscode.Uri.parse(documentUri) : documentUri
        );

        if (!issue.aiFixSuggestion) {
            // Generate fix suggestion first
            await handleGetAIFix(context, documentUri, issue);
            return;
        }

        const fix = issue.aiFixSuggestion;
        showDiffPreviewPanel(context, issue, fix, document);

    } catch (error) {
        console.error('Error applying AI fix:', error);
        vscode.window.showErrorMessage(`Failed to apply AI fix: ${error}`);
    }
}

function showIssueDetailsPanel(issue: SecurityIssue): void {
    const panel = vscode.window.createWebviewPanel(
        'securityIssueDetails',
        'Security Issue Details',
        vscode.ViewColumn.Beside,
        { enableScripts: true }
    );

    panel.webview.html = generateIssueDetailsHtml(issue);
}

function showAIFixPanel(
    context: vscode.ExtensionContext,
    issue: SecurityIssue,
    fix: AIFixSuggestion,
    documentUri: string | vscode.Uri
): void {
    const panel = vscode.window.createWebviewPanel(
        'aiFixSuggestion',
        'AI Fix Suggestion',
        vscode.ViewColumn.Beside,
        { enableScripts: true }
    );

    panel.webview.html = generateAIFixHtml(issue, fix);

    panel.webview.onDidReceiveMessage(
        async (message) => {
            if (message.command === 'applyFix') {
                await handleApplyAIFix(context, documentUri, issue);
                panel.dispose();
            }
        },
        undefined,
        context.subscriptions
    );
}

function showDiffPreviewPanel(
    context: vscode.ExtensionContext,
    issue: SecurityIssue,
    fix: AIFixSuggestion,
    document: vscode.TextDocument
): void {
    const panel = vscode.window.createWebviewPanel(
        'diffPreview',
        'Apply AI Fix - Preview Changes',
        vscode.ViewColumn.Beside,
        { enableScripts: true }
    );

    panel.webview.html = generateDiffPreviewHtml(issue, fix, document);

    panel.webview.onDidReceiveMessage(
        async (message) => {
            if (message.command === 'applyFix') {
                try {
                    const editor = await vscode.window.showTextDocument(document);
                    
                    await editor.edit(editBuilder => {
                        let finalFixedCode = fix.fixedCode
                            .replace(/^```[\w]*\n?/gm, '')
                            .replace(/\n?```$/gm, '')
                            .trim();

                        if (finalFixedCode) {
                            editBuilder.replace(issue.range, finalFixedCode);
                        }
                    });

                    vscode.window.showInformationMessage('AI fix applied successfully!');
                    
                    // Re-analyze the document
                    await analyzeDocument(document);
                    panel.dispose();
                } catch (error) {
                    vscode.window.showErrorMessage(`Failed to apply fix: ${error}`);
                }
            } else if (message.command === 'cancel') {
                panel.dispose();
            }
        },
        undefined,
        context.subscriptions
    );
}

// HTML generation functions (simplified versions - you can expand these)
function generateComplexityReportHtml(functions: any[]): string {
    // Implementation would be similar to the original, but simplified for brevity
    return `<html><body><h1>Complexity Report</h1><p>${functions.length} functions analyzed</p></body></html>`;
}

function generateIssueDetailsHtml(issue: SecurityIssue): string {
    const config = AIProviderManager.getCurrentConfig();
    const providerInfo = config ? ` (${config.provider.name} ${config.model})` : '';

    // Pull out optional context prefix from description
    const [firstLine, ...rest] = (issue.description || '').split('\n');
    const hasContext = /^Line\s+\d+\s*:/.test(firstLine.trim());
    const contextLine = hasContext ? firstLine : '';
    const descriptionBody = hasContext ? rest.join('\n') : issue.description;
    
    return `
        <html>
        <head>
            <style>
                body { font-family: var(--vscode-font-family); padding: 20px; }
                .header { border-bottom: 1px solid #ccc; padding-bottom: 10px; }
                .severity { padding: 5px 10px; border-radius: 3px; color: white; }
                .error { background-color: #dc3545; }
                .warning { background-color: #ffc107; color: black; }
                .info { background-color: #17a2b8; }
                .ctx { font-family: monospace; background: #f8f9fa; padding: 8px; border-radius: 4px; margin: 8px 0; color: #555; }
                .meta { color: #6c757d; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>${issue.message}</h2>
                <span class="severity ${issue.severity === 0 ? 'error' : issue.severity === 1 ? 'warning' : 'info'}">
                    ${issue.severity === 0 ? 'Error' : issue.severity === 1 ? 'Warning' : 'Info'}
                </span>
            </div>
            ${hasContext ? `<div class="ctx">${escapeHtml(contextLine)}</div>` : ''}
            <p><strong>Description:</strong> ${escapeHtml(descriptionBody)}</p>
            <p><strong>Suggestion:</strong> ${issue.suggestion}</p>
            <p class="meta"><strong>Source:</strong> ${issue.source}${providerInfo} | <strong>Confidence:</strong> ${issue.confidence}% ${issue.cveReference ? `| <strong>Ref:</strong> ${issue.cveReference}` : ''}</p>
        </body>
        </html>
    `;
}

function generateAIFixHtml(issue: SecurityIssue, fix: AIFixSuggestion): string {
    return `
        <html>
        <head>
            <style>
                body { font-family: var(--vscode-font-family); padding: 20px; }
                .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
                .code { background: #f4f4f4; padding: 10px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; }
                .btn { padding: 10px 20px; background: #007acc; color: white; border: none; border-radius: 4px; cursor: pointer; }
                .meta { color: #6c757d; font-size: 12px; margin-top: 8px; }
            </style>
        </head>
        <body>
            <h1>🤖 AI Fix Suggestion</h1>
            <p><strong>Issue:</strong> ${issue.message}</p>
            <p><strong>Explanation:</strong> ${fix.explanation}</p>
            <div class="grid">
              <div>
                <h3>Original</h3>
                <div class="code">${escapeHtml(fix.originalCode)}</div>
              </div>
              <div>
                <h3>Fixed</h3>
                <div class="code">${escapeHtml(fix.fixedCode)}</div>
              </div>
            </div>
            <div class="meta"><strong>Confidence:</strong> ${fix.confidence}% | <strong>Risk:</strong> ${fix.riskLevel}</div>
            <button class="btn" onclick="applyFix()">Apply Fix</button>
            
            <script>
                const vscode = acquireVsCodeApi();
                function applyFix() {
                    vscode.postMessage({ command: 'applyFix' });
                }
            </script>
        </body>
        </html>
    `;
}

function generateDiffPreviewHtml(issue: SecurityIssue, fix: AIFixSuggestion, document: vscode.TextDocument): string {
    return `
        <html>
        <head>
            <style>
                body { font-family: var(--vscode-font-family); padding: 20px; }
                .diff { background: #f4f4f4; padding: 10px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; }
                .removed { background: #ffdddd; }
                .added { background: #ddffdd; }
                .btn { padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }
                .btn-primary { background: #007acc; color: white; }
                .btn-secondary { background: #6c757d; color: white; }
            </style>
        </head>
        <body>
            <h1>Preview Changes</h1>
            <p><strong>File:</strong> ${document.fileName}</p>
            <p><strong>Line:</strong> ${issue.range.start.line + 1}</p>
            
            <div class="diff">
                <div class="removed">- ${escapeHtml(fix.originalCode)}</div>
                <div class="added">+ ${escapeHtml(fix.fixedCode)}</div>
            </div>
            
            <button class="btn btn-primary" onclick="applyFix()">Apply Changes</button>
            <button class="btn btn-secondary" onclick="cancel()">Cancel</button>
            
            <script>
                const vscode = acquireVsCodeApi();
                function applyFix() { vscode.postMessage({ command: 'applyFix' }); }
                function cancel() { vscode.postMessage({ command: 'cancel' }); }
            </script>
        </body>
        </html>
    `;
}

function escapeHtml(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

export function deactivate() {
    if (analysisTimeout) {
        clearTimeout(analysisTimeout);
    }
    
    if (statusBarItem) {
        statusBarItem.dispose();
    }
    
    console.log('Code Security Analyzer deactivated');
}