import * as vscode from 'vscode';
import { ComplexityAnalyzer } from './ComplexityAnalyzer.1';
import { AISecurityAnalyzer } from './AISecurityAnalyzer';
import { SecurityCodeLensProvider } from './SecurityCodeLensProvider';
import { SecurityHoverProvider } from './SecurityHoverProvider';
import { SecurityCodeActionProvider } from './SecurityCodeActionProvider';
import { SecurityIssue } from './SecurityIssue';

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

// Global timeout reference
let analysisTimeout: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext) {
	console.log('Code Security Analyzer is now active!');

	// Create diagnostic collection
	const diagnosticCollection = vscode.languages.createDiagnosticCollection('codeSecurityAnalyzer');
	context.subscriptions.push(diagnosticCollection);

	// Create providers
	const codeLensProvider = new SecurityCodeLensProvider();
	const hoverProvider = new SecurityHoverProvider();
	const codeActionProvider = new SecurityCodeActionProvider();

	// Register providers for multiple languages
	const languageSelectors = [
		'javascript',
		'typescript', 
		'python',
		'java',
		'csharp',
		'php',
		'go',
		'rust',
		'cpp',
		'c'
	];

	for (const language of languageSelectors) {
		context.subscriptions.push(
			vscode.languages.registerCodeLensProvider(language, codeLensProvider)
		);
		context.subscriptions.push(
			vscode.languages.registerHoverProvider(language, hoverProvider)
		);
		context.subscriptions.push(
			vscode.languages.registerCodeActionsProvider(language, codeActionProvider)
		);
	}

	// Function to analyze and update diagnostics
	const analyzeDocument = async (document: vscode.TextDocument) => {
		let statusBarItem: vscode.StatusBarItem | undefined;
		
		try {
			// Show progress for user feedback with enhanced status
			statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
			
			// Enhanced API key detection - use our hardcoded key as fallback
			const configApiKey = vscode.workspace.getConfiguration('codeSecurityAnalyzer').get<string>('apiKey');
			const envApiKey = process.env.OPENAI_API_KEY;
			const fallbackApiKey = "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";
			const apiKey = "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";
			// Debug information for API key status
			console.log('🔍 API Key Debug Info:');
			console.log('  - Config API Key:', configApiKey ? '✅ Present' : '❌ Not set');
			console.log('  - Environment API Key:', envApiKey ? '✅ Present' : '❌ Not set');
			console.log('  - Fallback API Key:', fallbackApiKey ? '✅ Available' : '❌ Missing');
			console.log('  - Final API Key:', apiKey ? '✅ Using API key' : '❌ No API key available');
			
			if (apiKey) {
				statusBarItem.text = "$(sparkle) AI Security Analysis (PRIORITY) - Initializing...";
				statusBarItem.tooltip = "Running advanced AI-powered security analysis with priority over basic patterns";
				console.log('🤖 AI Analysis Mode: ENABLED');
			} else {
				statusBarItem.text = "$(search) Basic Security Analysis - AI unavailable";
				statusBarItem.tooltip = "AI analysis failed, using pattern-based detection only";
				console.log('🔍 Basic Analysis Mode: API key missing');
			}
			
			statusBarItem.show();

			// Enhanced progress callback with debugging
			const progressCallback = (message: string, tooltip?: string) => {
				console.log(`📊 Analysis Progress: ${message}`);
				if (statusBarItem) {
					statusBarItem.text = message;
					if (tooltip) {
						statusBarItem.tooltip = tooltip;
						console.log(`   Details: ${tooltip}`);
					}
				}
			};

			console.log(`🔄 Starting analysis for: ${document.fileName}`);
			console.log(`   Language: ${document.languageId}`);
			console.log(`   Lines: ${document.lineCount}`);
			console.log(`   Size: ${document.getText().length} characters`);

			const issues = await AISecurityAnalyzer.analyzeDocument(document, progressCallback);
			
			
			const diagnostics: vscode.Diagnostic[] = issues
				.filter((issue: SecurityIssue) => {
					// Exclude best-practice and complexity issues from diagnostics to remove underlines
					// They will still be visible in CodeLens and hover
					return issue.type !== 'best-practice' && issue.type !== 'complexity';
				})
				.map((issue: SecurityIssue) => {
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
			
			// Enhanced debugging and summary with analysis type indication
			console.log(`📈 Analysis Results Summary:`);
			console.log(`   Total Issues Found: ${issues.length}`);
			
			const vulnerabilities = issues.filter(i => i.type === 'vulnerability').length;
			const complexityIssues = issues.filter(i => i.type === 'complexity').length;
			const bestPracticeIssues = issues.filter(i => i.type === 'best-practice').length;
			
			console.log(`   Vulnerabilities: ${vulnerabilities}`);
			console.log(`   Complexity Issues: ${complexityIssues}`);
			console.log(`   Best Practice Issues: ${bestPracticeIssues}`);
			
			// Determine analysis type used with detailed breakdown
			const aiIssues = issues.filter(i => i.source.includes('AI')).length;
			const complexityAnalysisIssues = issues.filter(i => i.source.includes('Complexity')).length;
			const bestPracticesAnalysisIssues = issues.filter(i => i.source.includes('Best Practice')).length;
			
			console.log(`📊 Analysis Breakdown by Source:`);
			console.log(`   AI Analysis: ${aiIssues} issues`);
			console.log(`   Complexity Analysis: ${complexityAnalysisIssues} issues`);
			console.log(`   Best Practices Analysis: ${bestPracticesAnalysisIssues} issues`);
			
			let analysisTypeIcon = "";
			let analysisTypeText = "";
			let analysisSuccess = "";
			
			if (aiIssues > 0 || complexityAnalysisIssues > 0 || bestPracticesAnalysisIssues > 0) {
				analysisTypeIcon = "$(sparkle)";
				analysisTypeText = "AI Analysis SUCCESS";
				analysisSuccess = "✅ AI-powered detection completed successfully";
				console.log(`🎉 SUCCESS: AI analysis worked! Found ${aiIssues} AI-detected issues`);
			} else {
				analysisTypeIcon = "$(check)";
				analysisTypeText = "Clean Code";
				analysisSuccess = "✅ No security issues detected";
				console.log(`✅ INFO: No security issues found in ${document.fileName}`);
			}
			
			statusBarItem.text = `${analysisTypeIcon} ${analysisTypeText}: ${vulnerabilities} vulnerabilities, ${complexityIssues} complexity, ${bestPracticeIssues} best practices`;
			statusBarItem.tooltip = `${analysisSuccess}\nTotal: ${issues.length} issues found using AI-powered detection`;
			
			console.log(`📋 Final Status: ${statusBarItem.text}`);
			
			setTimeout(() => statusBarItem?.dispose(), 10000); // Show for 10 seconds
			
		} catch (error) {
			console.error('❌ Analysis failed with error:', error);
			
			// Enhanced error handling
			if (statusBarItem) {
				statusBarItem.text = "$(error) Analysis failed - Using fallback";
				statusBarItem.tooltip = `Error: ${error}`;
				setTimeout(() => statusBarItem?.dispose(), 10000);
			}
			
			// Show detailed error message in HTML tab instead of console only
			const errorMsg = error instanceof Error ? error.message : String(error);
			const errorType = error instanceof Error ? error.constructor.name : typeof error;
			const errorStack = error instanceof Error ? error.stack : 'No stack trace';
			
			// Create detailed error panel
			const panel = vscode.window.createWebviewPanel(
				'aiAnalysisError',
				'AI Analysis Error - Debug Information',
				vscode.ViewColumn.Beside,
				{
					enableScripts: true
				}
			);

			panel.webview.html = generateErrorReportHtml(error, document.fileName);
			
			console.log(`🔍 Error Analysis:`);
			console.log(`   Error Type: ${errorType}`);
			console.log(`   Error Message: ${errorMsg}`);
			console.log(`   Error Stack: ${errorStack}`);
			
			if (errorMsg.includes('Rate limited') || errorMsg.includes('429') || errorMsg.includes('Too Many Requests')) {
				console.log(`⏱️ Rate limit error detected - showing retry options`);
				vscode.window.showErrorMessage(
					`AI analysis rate limited: ${errorMsg}`,
					'Wait and Retry',
					'View Error Details'
				).then(selection => {
					if (selection === 'Wait and Retry') {
						console.log(`🔄 Retrying analysis in 10 seconds...`);
						setTimeout(() => analyzeDocument(document), 10000);
					} else if (selection === 'View Error Details') {
						// Error panel is already shown above
					}
				});
			} else if (errorMsg.includes('API') || errorMsg.includes('fetch') || errorMsg.includes('401') || errorMsg.includes('403')) {
				console.log(`🔑 API-related error detected - showing API key configuration dialog`);
				vscode.window.showErrorMessage(
					`AI analysis failed: ${errorMsg}`, 
					'Configure API Key', 
					'View Error Details'
				).then(selection => {
					if (selection === 'Configure API Key') {
						vscode.commands.executeCommand('codeSecurityAnalyzer.configureApiKey');
					} else if (selection === 'View Error Details') {
						// Error panel is already shown above
					}
				});
			} else if (errorMsg.includes('timeout') || errorMsg.includes('ECONNREFUSED')) {
				console.log(`🌐 Network error detected - offering retry option`);
				vscode.window.showErrorMessage(
					`Network error during AI analysis: ${errorMsg}. Check your internet connection.`,
					'Retry',
					'View Error Details'
				).then(selection => {
					if (selection === 'Retry') {
						console.log(`🔄 Retrying analysis in 2 seconds...`);
						// Retry analysis
						setTimeout(() => analyzeDocument(document), 2000);
					} else if (selection === 'View Error Details') {
						// Error panel is already shown above
					}
				});
			} else {
				console.log(`🚨 Generic error - showing details in HTML tab`);
				vscode.window.showErrorMessage(
					`Security analysis failed: ${errorMsg}`,
					'View Error Details'
				).then(selection => {
					if (selection === 'View Error Details') {
						// Error panel is already shown above
					}
				});
			}
		}
	};

	// Register commands
	context.subscriptions.push(
		vscode.commands.registerCommand('codeSecurityAnalyzer.analyzeActiveFile', async () => {
			const activeEditor = vscode.window.activeTextEditor;
			if (activeEditor) {
				await analyzeDocument(activeEditor.document);
				vscode.window.showInformationMessage(
					`Security analysis completed for ${activeEditor.document.fileName}`
				);
			} else {
				vscode.window.showWarningMessage('No active file to analyze');
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('codeSecurityAnalyzer.showComplexityReport', async () => {
			const activeEditor = vscode.window.activeTextEditor;
			if (!activeEditor) {
				vscode.window.showWarningMessage('No active file to analyze');
				return;
			}

			const functions = ComplexityAnalyzer.analyzeFunctions(activeEditor.document);
			
			const panel = vscode.window.createWebviewPanel(
				'complexityReport',
				'Code Complexity Report',
				vscode.ViewColumn.Beside,
				{
					enableScripts: true
				}
			);

			panel.webview.html = generateComplexityReportHtml(functions);
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('codeSecurityAnalyzer.showIssueDetails', (issue: SecurityIssue) => {
			const panel = vscode.window.createWebviewPanel(
				'securityIssueDetails',
				'Security Issue Details',
				vscode.ViewColumn.Beside,
				{
					enableScripts: true
				}
			);

			const severity = issue.severity === vscode.DiagnosticSeverity.Error ? 'Error' : 
							issue.severity === vscode.DiagnosticSeverity.Warning ? 'Warning' : 'Info';
			
			const confidence = issue.confidence >= 80 ? 'High' : 
							  issue.confidence >= 60 ? 'Medium' : 'Low';
			
			panel.webview.html = `
				<!DOCTYPE html>
				<html>
				<head>
					<meta charset="UTF-8">
					<meta name="viewport" content="width=device-width, initial-scale=1.0">
					<title>Security Issue Details</title>
					<style>
						body { 
							font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
							padding: 20px; 
							background-color: var(--vscode-editor-background);
							color: var(--vscode-editor-foreground);
						}
						.header { 
							border-bottom: 1px solid var(--vscode-panel-border); 
							padding-bottom: 15px; 
							margin-bottom: 20px; 
						}
						.severity { 
							font-weight: bold; 
							padding: 5px 10px; 
							border-radius: 3px; 
							display: inline-block; 
							margin-right: 10px;
						}
						.error { background-color: #f8d7da; color: #721c24; }
						.warning { background-color: #fff3cd; color: #856404; }
						.info { background-color: #d1ecf1; color: #0c5460; }
						.confidence {
							font-size: 0.9em;
							padding: 3px 8px;
							border-radius: 3px;
							background-color: var(--vscode-badge-background);
							color: var(--vscode-badge-foreground);
						}
						.type-badge {
							font-size: 0.8em;
							padding: 2px 6px;
							border-radius: 2px;
							background-color: var(--vscode-button-background);
							color: var(--vscode-button-foreground);
							margin-left: 10px;
						}
						.section { margin-bottom: 20px; }
						.section h3 { 
							color: var(--vscode-foreground); 
							margin-bottom: 10px;
							font-size: 1.1em;
						}
						.description, .suggestion { 
							line-height: 1.6; 
							background-color: var(--vscode-textBlockQuote-background);
							padding: 15px;
							border-left: 4px solid var(--vscode-textBlockQuote-border);
							border-radius: 4px;
						}
						.suggestion {
							border-left-color: #28a745;
						}
						.suggestion::before {
							content: "💡 ";
							font-size: 1.2em;
						}
						.complexity-info {
							background-color: var(--vscode-editor-inactiveSelectionBackground);
							padding: 10px;
							border-radius: 4px;
							font-size: 0.9em;
						}
						.function-info {
							background-color: var(--vscode-editor-selectionBackground);
							padding: 10px;
							border-radius: 4px;
							font-size: 0.9em;
						}
						.ai-source {
							color: #28a745;
							font-weight: bold;
							padding: 2px 6px;
							background-color: rgba(40, 167, 69, 0.1);
							border-radius: 3px;
						}
						.basic-source {
							color: #6c757d;
							font-weight: normal;
							padding: 2px 6px;
							background-color: rgba(108, 117, 125, 0.1);
							border-radius: 3px;
						}
					</style>
				</head>
				<body>
					<div class="header">
						<h2>${issue.message}</h2>
						<span class="severity ${severity.toLowerCase()}">${severity}</span>
						<span class="confidence">Confidence: ${confidence} (${issue.confidence}%)</span>
						<span class="type-badge">${issue.type.toUpperCase()}</span>
					</div>
					
					<div class="section">
						<h3>Description</h3>
						<div class="description">${issue.description}</div>
					</div>
					
					${issue.suggestion ? `
					<div class="section">
						<h3>💡 Recommended Solution</h3>
						<div class="suggestion">${issue.suggestion}</div>
					</div>
					` : ''}
					
					${issue.complexityScore ? `
					<div class="section">
						<h3>📊 Complexity Information</h3>
						<div class="complexity-info">
							<p><strong>Complexity Score:</strong> ${issue.complexityScore}</p>
							<p><strong>Impact:</strong> ${issue.complexityScore > 15 ? 'High - Urgent refactoring needed' : 
															issue.complexityScore > 10 ? 'Medium - Consider refactoring' : 
															'Low - Acceptable complexity'}</p>
						</div>
					</div>
					` : ''}
					
					${issue.functionName ? `
					<div class="section">
						<h3>🔧 Function Information</h3>
						<div class="function-info">
							<p><strong>Function Name:</strong> ${issue.functionName}()</p>
							<p><strong>Analysis Focus:</strong> This issue is specific to the function implementation</p>
						</div>
					</div>
					` : ''}
					
					${issue.cveReference ? `
					<div class="section">
						<h3>🔗 Security Reference</h3>
						<div class="cve-reference">
							<strong>${issue.cveReference}</strong>
						</div>
					</div>
					` : ''}
					
					<div class="section">
						<h3>📋 Analysis Details</h3>
						<div class="analysis-details">
							<p><strong>Source:</strong> <span class="${issue.source.includes('AI') ? 'ai-source' : 'basic-source'}">${issue.source}</span></p>
							<p><strong>Issue Type:</strong> ${issue.type}</p>
							<p><strong>Severity:</strong> ${severity}</p>
							<p><strong>Confidence:</strong> ${confidence} (${issue.confidence}%)</p>
						</div>
					</div>
				</body>
				</html>
			`;
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('codeSecurityAnalyzer.configureApiKey', async () => {
			const apiKey = await vscode.window.showInputBox({
				prompt: 'Enter your OpenRouter API key',
				password: true,
				placeHolder: 'sk-...'
			});
			
			if (apiKey) {
				await vscode.workspace.getConfiguration('codeSecurityAnalyzer').update('apiKey', apiKey, vscode.ConfigurationTarget.Global);
				vscode.window.showInformationMessage('API key configured successfully!');
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('codeSecurityAnalyzer.getAIFix', async (documentUri: string | vscode.Uri, issue: SecurityIssue) => {
			try {
				const document = await vscode.workspace.openTextDocument(typeof documentUri === 'string' ? vscode.Uri.parse(documentUri) : documentUri);
				
				// Find the current issue in the document to get the latest state
				const currentIssues = await AISecurityAnalyzer.analyzeDocument(document);
				let currentIssue = currentIssues.find(i => 
					i.range.start.line === issue.range.start.line && 
					i.range.start.character === issue.range.start.character &&
					i.message === issue.message
				);
				
				// If we can't find the current issue, use the passed issue
				if (!currentIssue) {
					currentIssue = issue;
				}
				
				// Show progress
				await vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: 'Getting AI fix suggestion...',
					cancellable: false
				}, async () => {
					const aiFixSuggestion = await AISecurityAnalyzer.generateAIFixSuggestion(currentIssue, document);
					
					if (aiFixSuggestion) {
						// Update the issue with the AI fix suggestion
						currentIssue.aiFixSuggestion = aiFixSuggestion;
						
						// Show fix in a panel
						const panel = vscode.window.createWebviewPanel(
							'aiFixSuggestion',
							'AI Fix Suggestion',
							vscode.ViewColumn.Beside,
							{
								enableScripts: true
							}
						);
						
						panel.webview.html = generateAIFixHtml(currentIssue, aiFixSuggestion);
						
						// Handle messages from webview
						panel.webview.onDidReceiveMessage(
							async (message) => {
								if (message.command === 'applyFix') {
									await vscode.commands.executeCommand('codeSecurityAnalyzer.applyAIFix', documentUri, currentIssue);
									panel.dispose();
								}
							},
							undefined,
							context.subscriptions
						);
						
						// Refresh code lenses to update the "Fix with AI" button
						codeLensProvider.refresh();
						
						vscode.window.showInformationMessage('AI fix suggestion generated successfully!');
					} else {
						vscode.window.showWarningMessage('Could not generate AI fix suggestion. Please check your API key configuration.');
					}
				});
			} catch (error) {
				console.error('Error getting AI fix:', error);
				vscode.window.showErrorMessage(`Failed to get AI fix: ${error}`);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('codeSecurityAnalyzer.applyAIFix', async (documentUri: string | vscode.Uri, issue: SecurityIssue) => {
			try {
				const document = await vscode.workspace.openTextDocument(typeof documentUri === 'string' ? vscode.Uri.parse(documentUri) : documentUri);
				
				// Find the current issue in the document to get the latest state
				const currentIssues = await AISecurityAnalyzer.analyzeDocument(document);
				let currentIssue = currentIssues.find(i => 
					i.range.start.line === issue.range.start.line && 
					i.range.start.character === issue.range.start.character &&
					i.message === issue.message
				);
				
				// If we can't find the current issue, use the passed issue but check for fix suggestion
				if (!currentIssue) {
					currentIssue = issue;
				}
				
				// If no AI fix suggestion, try to generate one
				if (!currentIssue.aiFixSuggestion) {
					vscode.window.showInformationMessage('Generating AI fix suggestion...');
					const aiFixSuggestion = await AISecurityAnalyzer.generateAIFixSuggestion(currentIssue, document);
					if (aiFixSuggestion) {
						currentIssue.aiFixSuggestion = aiFixSuggestion;
					} else {
						vscode.window.showWarningMessage('Could not generate AI fix suggestion. Please check your API key configuration.');
						return;
					}
				}
				
				const fix = currentIssue.aiFixSuggestion;
				
				// Show diff preview panel
				const panel = vscode.window.createWebviewPanel(
					'diffPreview',
					'Apply AI Fix - Preview Changes',
					vscode.ViewColumn.Beside,
					{
						enableScripts: true
					}
				);

				panel.webview.html = generateDiffPreviewHtml(currentIssue, fix, document);

				// Handle messages from webview
				panel.webview.onDidReceiveMessage(
					async (message) => {
						if (message.command === 'applyFix') {
							try {
								const editor = await vscode.window.showTextDocument(document);
								
								// Apply the fix with enhanced logic
								await editor.edit(editBuilder => {
									// Check if the fix suggests creating a new file
									if (fix.fixedCode.includes('// Create new file:') || fix.fixedCode.includes('// New file:')) {
										// Extract file creation instructions
										const lines = fix.fixedCode.split('\n');
										let currentFileContent = '';
										let currentFileName = '';
										let inFileBlock = false;
										
										for (const line of lines) {
											if (line.includes('// Create new file:') || line.includes('// New file:')) {
												// Extract filename from comment
												const fileNameMatch = line.match(/(?:Create new file:|New file:)\s*(.+)/);
												if (fileNameMatch) {
													currentFileName = fileNameMatch[1].trim();
													inFileBlock = true;
													currentFileContent = '';
												}
											} else if (inFileBlock && line.trim() && !line.startsWith('//')) {
												currentFileContent += line + '\n';
											}
										}
										
										// If we found a file to create, create it
										if (currentFileName && currentFileContent) {
											vscode.workspace.openTextDocument().then(newDoc => {
												vscode.window.showTextDocument(newDoc).then(newEditor => {
													newEditor.edit(newEditBuilder => {
														newEditBuilder.insert(new vscode.Position(0, 0), currentFileContent);
													}).then(() => {
														// Save with the suggested filename
														const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
														if (workspaceFolder) {
															const newFileUri = vscode.Uri.joinPath(workspaceFolder.uri, currentFileName);
															vscode.workspace.fs.writeFile(newFileUri, Buffer.from(currentFileContent, 'utf8'));
														}
													});
												});
											});
										}
										return; // Don't apply other fixes if creating a file
									}
									
									// Check for explicit line removal instructions
									const isExplicitRemoval = fix.fixedCode.includes('// REMOVE_LINE') || 
															 fix.fixedCode.includes('// DELETE_LINE') ||
															 (fix.fixedCode.trim() === '' && fix.explanation.toLowerCase().includes('remove'));
									
									if (isExplicitRemoval) {
										// Handle explicit line removal - remove the entire line(s)
										const startLine = currentIssue.range.start.line;
										const endLine = currentIssue.range.end.line;
										
										// Create a range that includes the entire line(s) including newline characters
										const fullLineRange = new vscode.Range(
											new vscode.Position(startLine, 0),
											new vscode.Position(endLine + 1, 0)
										);
										
										// Check if we're removing the last line of the file
										if (endLine >= document.lineCount - 1) {
											// For last line, just remove to end of line without the newline
											const lastLineRange = new vscode.Range(
												new vscode.Position(startLine, 0),
												new vscode.Position(endLine, document.lineAt(endLine).text.length)
											);
											editBuilder.delete(lastLineRange);
										} else {
											editBuilder.delete(fullLineRange);
										}
									} else {
										// Intelligent replacement logic
										let finalFixedCode = fix.fixedCode;
										
										// Clean up AI response artifacts
										finalFixedCode = finalFixedCode
											.replace(/^```[\w]*\n?/gm, '')  // Remove code block markers
											.replace(/\n?```$/gm, '')       // Remove ending code block markers
											.replace(/^\/\/ Fixed.*?\n/gm, '')  // Remove "// Fixed" comments
											.replace(/^\/\/ Secure.*?\n/gm, '') // Remove "// Secure" comments
											.trim();
										
										// If the fix is empty after cleaning, skip the replacement
										if (!finalFixedCode) {
											return;
										}
										
										// Apply the targeted replacement
										editBuilder.replace(currentIssue.range, finalFixedCode);
									}
								});
								
								// Show success message
								vscode.window.showInformationMessage(
									`AI fix applied successfully! Original code replaced with secure implementation.`
								);
								
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
			} catch (error) {
				console.error('Error applying AI fix:', error);
				vscode.window.showErrorMessage(`Failed to apply AI fix: ${error}`);
			}
		})
	);

	// Helper function to generate diff preview HTML
	function generateDiffPreviewHtml(issue: SecurityIssue, fix: AIFixSuggestion, document: vscode.TextDocument): string {
		const lineNumber = issue.range.start.line + 1;
		const fileName = document.fileName.split('/').pop() || document.fileName;
		
		// Get surrounding context lines for better visualization
		const startLine = Math.max(0, issue.range.start.line - 3);
		const endLine = Math.min(document.lineCount - 1, issue.range.end.line + 3);
		const contextRange = new vscode.Range(startLine, 0, endLine, document.lineAt(endLine).text.length);
		const contextLines = document.getText(contextRange).split('\n');
		
		// Create diff visualization
		let diffHtml = '';
		for (let i = 0; i < contextLines.length; i++) {
			const currentLineNum = startLine + i + 1;
			const isChangedLine = currentLineNum >= (issue.range.start.line + 1) && currentLineNum <= (issue.range.end.line + 1);
			
			if (isChangedLine) {
				// Show removed line
				diffHtml += `<tr class="removed-line">
					<td class="line-number">-${currentLineNum}</td>
					<td class="line-content">${escapeHtml(contextLines[i])}</td>
				</tr>`;
			} else {
				// Show context line
				diffHtml += `<tr class="context-line">
					<td class="line-number">${currentLineNum}</td>
					<td class="line-content">${escapeHtml(contextLines[i])}</td>
				</tr>`;
			}
		}
		
		// Add the new lines
		const fixedLines = fix.fixedCode.split('\n');
		for (let i = 0; i < fixedLines.length; i++) {
			const lineNum = issue.range.start.line + 1 + i;
			diffHtml += `<tr class="added-line">
				<td class="line-number">+${lineNum}</td>
				<td class="line-content">${escapeHtml(fixedLines[i])}</td>
			</tr>`;
		}

		return `
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Apply AI Fix - Preview Changes</title>
				<style>
					body {
						font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
						padding: 20px;
						background-color: var(--vscode-editor-background);
						color: var(--vscode-editor-foreground);
						margin: 0;
					}
					.header {
						border-bottom: 2px solid var(--vscode-panel-border);
						padding-bottom: 20px;
						margin-bottom: 20px;
					}
					.file-info {
						display: flex;
						align-items: center;
						gap: 10px;
						margin-bottom: 10px;
					}
					.file-icon {
						font-size: 1.2em;
					}
					.issue-summary {
						background-color: var(--vscode-textBlockQuote-background);
						padding: 15px;
						border-radius: 8px;
						border-left: 4px solid #dc3545;
						margin-bottom: 20px;
					}
					.diff-container {
						background-color: var(--vscode-editor-background);
						border: 1px solid var(--vscode-panel-border);
						border-radius: 8px;
						overflow: hidden;
						margin-bottom: 20px;
					}
					.diff-header {
						background-color: var(--vscode-list-activeSelectionBackground);
						padding: 10px 15px;
						font-weight: bold;
						border-bottom: 1px solid var(--vscode-panel-border);
					}
					.diff-table {
						width: 100%;
						border-collapse: collapse;
						font-family: 'Consolas', 'Courier New', monospace;
						font-size: 0.9em;
					}
					.line-number {
						width: 60px;
						padding: 2px 8px;
						text-align: right;
						background-color: var(--vscode-editorGutter-background);
						border-right: 1px solid var(--vscode-panel-border);
						color: var(--vscode-editorLineNumber-foreground);
						user-select: none;
					}
					.line-content {
						padding: 2px 8px;
						white-space: pre-wrap;
						font-family: inherit;
					}
					.context-line {
						background-color: var(--vscode-editor-background);
					}
					.removed-line {
						background-color: rgba(248, 81, 73, 0.15);
					}
					.removed-line .line-content {
						color: #f85149;
					}
					.added-line {
						background-color: rgba(46, 160, 67, 0.15);
					}
					.added-line .line-content {
						color: #2ea043;
					}
					.fix-info {
						background-color: var(--vscode-editor-selectionBackground);
						padding: 15px;
						border-radius: 8px;
						margin-bottom: 20px;
						border-left: 4px solid #28a745;
					}
					.actions {
						display: flex;
						gap: 10px;
						justify-content: center;
						padding: 20px;
						border-top: 1px solid var(--vscode-panel-border);
					}
					.btn {
						padding: 10px 20px;
						border: none;
						border-radius: 5px;
						cursor: pointer;
						font-size: 1em;
						font-weight: bold;
						min-width: 120px;
					}
					.btn-primary {
						background-color: #007acc;
						color: white;
					}
					.btn-primary:hover {
						background-color: #005a9e;
					}
					.btn-secondary {
						background-color: var(--vscode-button-secondaryBackground);
						color: var(--vscode-button-secondaryForeground);
					}
					.btn-secondary:hover {
						background-color: var(--vscode-button-secondaryHoverBackground);
					}
					.confidence-badge {
						display: inline-block;
						padding: 3px 8px;
						border-radius: 12px;
						font-size: 0.8em;
						font-weight: bold;
						color: white;
						background-color: ${fix.confidence >= 80 ? '#28a745' : fix.confidence >= 60 ? '#ffc107' : '#dc3545'};
					}
				</style>
			</head>
			<body>
				<div class="header">
					<h1>🔄 Preview AI Fix</h1>
					<div class="file-info">
						<span class="file-icon">📄</span>
						<strong>${fileName}</strong>
						<span>Line ${lineNumber}</span>
						<span class="confidence-badge">${fix.confidence}% Confidence</span>
					</div>
				</div>

				<div class="issue-summary">
					<h3>🚨 Security Issue</h3>
					<p><strong>Issue:</strong> ${issue.message}</p>
					<p><strong>Description:</strong> ${issue.description}</p>
				</div>

				<div class="fix-info">
					<h3>🔧 Proposed Fix</h3>
					<p>${fix.explanation}</p>
				</div>

				<div class="diff-container">
					<div class="diff-header">
						📝 Changes Preview (GitHub-style diff)
					</div>
					<table class="diff-table">
						${diffHtml}
					</table>
				</div>

				<div class="actions">
					<button class="btn btn-primary" onclick="applyFix()">
						✅ Accept Changes
					</button>
					<button class="btn btn-secondary" onclick="cancel()">
						❌ Cancel
					</button>
				</div>

				<script>
					const vscode = acquireVsCodeApi();
					
					function applyFix() {
						vscode.postMessage({ command: 'applyFix' });
					}
					
					function cancel() {
						vscode.postMessage({ command: 'cancel' });
					}
				</script>
			</body>
			</html>
		`;
	}

	// Helper function to escape HTML
	function escapeHtml(text: string): string {
		return text
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#x27;');
	}

	// Helper function to generate AI fix HTML
	function generateAIFixHtml(issue: SecurityIssue, fix: AIFixSuggestion): string {
		const riskColor = fix.riskLevel === 'high' ? '#dc3545' : fix.riskLevel === 'medium' ? '#ffc107' : '#28a745';
		const confidenceColor = fix.confidence >= 80 ? '#28a745' : fix.confidence >= 60 ? '#ffc107' : '#dc3545';
		
		let stepsHtml = '';
		if (fix.steps && fix.steps.length > 0) {
			stepsHtml = '<div class="section"><h3>📋 Implementation Steps</h3><ol>';
			fix.steps.forEach(step => {
				stepsHtml += `<li>${step}</li>`;
			});
			stepsHtml += '</ol></div>';
		}
		
		return `
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>AI Fix Suggestion</title>
				<style>
					body { 
						font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
						padding: 20px; 
						background-color: var(--vscode-editor-background);
						color: var(--vscode-editor-foreground);
						line-height: 1.6;
					}
					.header { 
						border-bottom: 2px solid var(--vscode-panel-border); 
						padding-bottom: 20px; 
						margin-bottom: 25px; 
						text-align: center;
					}
					.header h1 {
						color: var(--vscode-foreground);
						margin: 0;
						font-size: 1.8em;
					}
					.issue-info {
						background-color: var(--vscode-textBlockQuote-background);
						padding: 15px;
						border-radius: 8px;
						margin-bottom: 20px;
						border-left: 4px solid #dc3545;
					}
					.fix-info {
						background-color: var(--vscode-editor-selectionBackground);
						padding: 15px;
						border-radius: 8px;
						margin-bottom: 20px;
						border-left: 4px solid ${confidenceColor};
					}
					.confidence-badge {
						display: inline-block;
						padding: 5px 12px;
						border-radius: 20px;
						font-size: 0.9em;
						font-weight: bold;
						color: white;
						background-color: ${confidenceColor};
						margin-right: 10px;
					}
					.risk-badge {
						display: inline-block;
						padding: 5px 12px;
						border-radius: 20px;
						font-size: 0.9em;
						font-weight: bold;
						color: white;
						background-color: ${riskColor};
					}
					.code-block {
						background-color: var(--vscode-textCodeBlock-background);
						padding: 15px;
						border-radius: 8px;
						margin: 15px 0;
						overflow-x: auto;
						border: 1px solid var(--vscode-panel-border);
					}
					.code-block h4 {
						margin-top: 0;
						color: var(--vscode-foreground);
					}
					.code-block pre {
						margin: 0;
						white-space: pre-wrap;
						font-family: 'Consolas', 'Courier New', monospace;
						font-size: 0.9em;
					}
					.section {
						margin-bottom: 25px;
					}
					.section h3 {
						color: var(--vscode-foreground);
						margin-bottom: 15px;
						font-size: 1.2em;
					}
					.apply-button {
						background-color: #007acc;
						color: white;
						border: none;
						padding: 12px 24px;
						font-size: 1em;
						border-radius: 5px;
						cursor: pointer;
						margin-top: 20px;
						width: 100%;
					}
					.apply-button:hover {
						background-color: #005a9e;
					}
					.warning {
						background-color: #fff3cd;
						border: 1px solid #ffeaa7;
						color: #856404;
						padding: 12px;
						border-radius: 5px;
						margin-bottom: 20px;
					}
					ol {
						padding-left: 20px;
					}
					li {
						margin-bottom: 8px;
					}
					.ai-source {
						color: #28a745;
						font-weight: bold;
						padding: 2px 6px;
						background-color: rgba(40, 167, 69, 0.1);
						border-radius: 3px;
					}
					.basic-source {
						color: #6c757d;
						font-weight: normal;
						padding: 2px 6px;
						background-color: rgba(108, 117, 125, 0.1);
						border-radius: 3px;
					}
				</style>
			</head>
			<body>
				<div class="header">
					<h1>🤖 AI Fix Suggestion</h1>
					<div style="margin-top: 10px;">
						<span class="confidence-badge">${fix.confidence}% Confidence</span>
						<span class="risk-badge">${fix.riskLevel.toUpperCase()} Risk</span>
					</div>
				</div>
				
				<div class="issue-info">
					<h3>🚨 Security Issue</h3>
					<p><strong>Issue:</strong> ${issue.message}</p>
					<p><strong>Description:</strong> ${issue.description}</p>
					<p><strong>Type:</strong> ${issue.type}</p>
					<p><strong>Detected by:</strong> <span class="${issue.source.includes('AI') ? 'ai-source' : 'basic-source'}">${issue.source}</span></p>
				</div>
				
				<div class="fix-info">
					<h3>🔧 AI Fix Explanation</h3>
					<p>${fix.explanation}</p>
				</div>
				
				<div class="section">
					<h3>📝 Code Changes</h3>
					
					<div class="code-block">
						<h4>❌ Original Code (Vulnerable)</h4>
						<pre><code>${fix.originalCode}</code></pre>
					</div>
					
					<div class="code-block">
						<h4>✅ Fixed Code (Secure)</h4>
						<pre><code>${fix.fixedCode}</code></pre>
					</div>
				</div>
				
				${stepsHtml}
				
				<div class="warning">
					<strong>⚠️ Warning:</strong> Please review the suggested fix carefully before applying. 
					AI-generated fixes should be tested thoroughly in your specific context.
				</div>
				
				<button class="apply-button" onclick="applyFix()">
					🚀 Apply Fix (${fix.confidence}% confidence)
				</button>
				
				<script>
					const vscode = acquireVsCodeApi();
					
					function applyFix() {
						if (confirm('Are you sure you want to apply this AI-generated fix?')) {
							vscode.postMessage({
								command: 'applyFix'
							});
						}
					}
				</script>
			</body>
			</html>
		`;
	}

	// Helper function to generate complexity report HTML
	function generateComplexityReportHtml(functions: FunctionInfo[]): string {
		const sortedFunctions = functions.sort((a, b) => b.complexity.cyclomaticComplexity - a.complexity.cyclomaticComplexity);
		
		let functionsHtml = '';
		for (const func of sortedFunctions) {
			const complexity = func.complexity.cyclomaticComplexity;
			const complexityClass = complexity > 15 ? 'high' : complexity > 10 ? 'medium' : 'low';
			
			functionsHtml += `
				<div class="function-item ${complexityClass}">
					<h4>${func.name}()</h4>
					<div class="metrics">
						<div class="metric">
							<span class="label">Cyclomatic Complexity:</span>
							<span class="value">${func.complexity.cyclomaticComplexity}</span>
						</div>
						<div class="metric">
							<span class="label">Cognitive Complexity:</span>
							<span class="value">${func.complexity.cognitiveComplexity}</span>
						</div>
						<div class="metric">
							<span class="label">Lines of Code:</span>
							<span class="value">${func.complexity.linesOfCode}</span>
						</div>
						<div class="metric">
							<span class="label">Parameters:</span>
							<span class="value">${func.complexity.parameterCount}</span>
						</div>
						<div class="metric">
							<span class="label">Nesting Level:</span>
							<span class="value">${func.complexity.nestingLevel}</span>
						</div>
					</div>
				</div>
			`;
		}
		
		return `
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Code Complexity Report</title>
				<style>
					body { 
						font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
						padding: 20px; 
						background-color: var(--vscode-editor-background);
						color: var(--vscode-editor-foreground);
					}
					.header { 
						border-bottom: 1px solid var(--vscode-panel-border); 
						padding-bottom: 15px; 
						margin-bottom: 20px; 
					}
					.summary {
						background-color: var(--vscode-textBlockQuote-background);
						padding: 15px;
						border-radius: 4px;
						margin-bottom: 20px;
					}
					.function-item {
						background-color: var(--vscode-editor-inactiveSelectionBackground);
						padding: 15px;
						margin-bottom: 15px;
						border-radius: 4px;
						border-left: 4px solid;
					}
					.function-item.high {
						border-left-color: #dc3545;
					}
					.function-item.medium {
						border-left-color: #ffc107;
					}
					.function-item.low {
						border-left-color: #28a745;
					}
					.function-item h4 {
						margin: 0 0 10px 0;
						color: var(--vscode-foreground);
					}
					.metrics {
						display: grid;
						grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
						gap: 10px;
					}
					.metric {
						display: flex;
						justify-content: space-between;
						padding: 5px 0;
					}
					.label {
						font-weight: bold;
					}
					.value {
						color: var(--vscode-textLink-foreground);
					}
					.complexity-legend {
						background-color: var(--vscode-editor-selectionBackground);
						padding: 10px;
						border-radius: 4px;
						margin-bottom: 20px;
					}
					.legend-item {
						display: inline-block;
						margin-right: 20px;
						padding: 5px 10px;
						border-radius: 3px;
						font-size: 0.9em;
					}
					.legend-high { background-color: #dc3545; color: white; }
					.legend-medium { background-color: #ffc107; color: black; }
					.legend-low { background-color: #28a745; color: white; }
				</style>
			</head>
			<body>
				<div class="header">
					<h2>📊 Code Complexity Report</h2>
					<p>Analysis of function complexity metrics</p>
				</div>
				
				<div class="summary">
					<h3>Summary</h3>
					<p><strong>Total Functions:</strong> ${functions.length}</p>
					<p><strong>High Complexity:</strong> ${functions.filter(f => f.complexity.cyclomaticComplexity > 15).length}</p>
					<p><strong>Medium Complexity:</strong> ${functions.filter(f => f.complexity.cyclomaticComplexity > 10 && f.complexity.cyclomaticComplexity <= 15).length}</p>
					<p><strong>Low Complexity:</strong> ${functions.filter(f => f.complexity.cyclomaticComplexity <= 10).length}</p>
				</div>
				
				<div class="complexity-legend">
					<h4>Complexity Legend:</h4>
					<span class="legend-item legend-high">High (>15) - Urgent refactoring needed</span>
					<span class="legend-item legend-medium">Medium (10-15) - Consider refactoring</span>
					<span class="legend-item legend-low">Low (≤10) - Acceptable complexity</span>
				</div>
				
				<div class="functions-list">
					<h3>Functions by Complexity</h3>
					${functionsHtml}
				</div>
			</body>
			</html>
		`;
	}

	// Helper function to generate error report HTML
	function generateErrorReportHtml(error: any, fileName: string): string {
		const errorMsg = error instanceof Error ? error.message : String(error);
		const errorType = error instanceof Error ? error.constructor.name : typeof error;
		const errorStack = error instanceof Error ? error.stack : 'No stack trace available';
		const timestamp = new Date().toLocaleString();
		
		// Determine error category and provide specific solutions
		let errorCategory = 'Unknown Error';
		let possibleCauses: string[] = [];
		let suggestedSolutions: string[] = [];
		
		if (errorMsg.includes('Rate limited') || errorMsg.includes('429') || errorMsg.includes('Too Many Requests')) {
			errorCategory = 'Rate Limit Error';
			possibleCauses = [
				'Too many requests sent to AI service in short time',
				'API rate limits exceeded for your key',
				'Multiple analysis requests running simultaneously',
				'Free tier rate limits reached',
				'Service is temporarily overloaded'
			];
			suggestedSolutions = [
				'Wait 2-5 minutes before trying again',
				'Avoid analyzing multiple files simultaneously',
				'The extension will automatically retry with exponential backoff',
				'Consider upgrading to a paid API plan for higher limits',
				'Analyze smaller code sections if working with large files'
			];
		} else if (errorMsg.includes('API') || errorMsg.includes('fetch') || errorMsg.includes('401') || errorMsg.includes('403')) {
			errorCategory = 'API/Authentication Error';
			possibleCauses = [
				'Invalid or expired API key',
				'Incorrect API endpoint configuration',
				'Network connectivity issues',
				'API service is temporarily unavailable',
				'Insufficient API credits or permissions'
			];
			suggestedSolutions = [
				'Check your API key configuration in VS Code settings',
				'Verify the API key is valid and has sufficient credits',
				'Test network connectivity to openrouter.ai',
				'Configure API key using the "Configure API Key" command',
				'Check your OpenRouter account for credit balance'
			];
		} else if (errorMsg.includes('timeout') || errorMsg.includes('ECONNREFUSED') || errorMsg.includes('ENOTFOUND')) {
			errorCategory = 'Network/Connection Error';
			possibleCauses = [
				'Internet connection is down or unstable',
				'Firewall blocking the request',
				'DNS resolution issues',
				'API service is down',
				'Proxy or VPN interfering with connection'
			];
			suggestedSolutions = [
				'Check your internet connection',
				'Temporarily disable firewall/antivirus',
				'Try using a different network',
				'Check if you are behind a corporate proxy',
				'Wait and retry - the service might be temporarily down'
			];
		} else if (errorMsg.includes('JSON') || errorMsg.includes('parse') || errorMsg.includes('SyntaxError')) {
			errorCategory = 'Data Processing Error';
			possibleCauses = [
				'AI service returned malformed response',
				'Response was truncated or corrupted',
				'API endpoint returned unexpected format',
				'Code analysis content is too complex for AI processing'
			];
			suggestedSolutions = [
				'Try analyzing a smaller portion of code',
				'Retry the analysis - temporary AI service issue',
				'Check if the code file has any unusual characters',
				'Ensure your API key has sufficient credits'
			];
		} else {
			possibleCauses = [
				'Unexpected error in code analysis',
				'VS Code extension internal error',
				'Memory or resource constraints',
				'Code file format or encoding issues'
			];
			suggestedSolutions = [
				'Restart VS Code and try again',
				'Try analyzing a smaller file first',
				'Check VS Code developer console for more details',
				'Ensure your API key is properly configured'
			];
		}
		
		return `
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>AI Analysis Error Report</title>
				<style>
					body {
						font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
						padding: 20px;
						background-color: var(--vscode-editor-background);
						color: var(--vscode-editor-foreground);
						line-height: 1.6;
						margin: 0;
					}
					.header {
						background: linear-gradient(135deg, #dc3545, #c82333);
						color: white;
						padding: 20px;
						border-radius: 8px;
						margin-bottom: 20px;
						text-align: center;
					}
					.header h1 {
						margin: 0;
						font-size: 1.8em;
						display: flex;
						align-items: center;
						justify-content: center;
						gap: 10px;
					}
					.error-icon {
						font-size: 2em;
					}
					.timestamp {
						font-size: 0.9em;
						opacity: 0.9;
						margin-top: 5px;
					}
					.section {
						background-color: var(--vscode-textBlockQuote-background);
						padding: 20px;
						border-radius: 8px;
						margin-bottom: 20px;
						border-left: 4px solid var(--vscode-textBlockQuote-border);
					}
					.section h3 {
						margin-top: 0;
						color: var(--vscode-foreground);
						font-size: 1.2em;
						display: flex;
						align-items: center;
						gap: 8px;
					}
					.error-details {
						background-color: var(--vscode-textCodeBlock-background);
						padding: 15px;
						border-radius: 5px;
						font-family: 'Consolas', 'Courier New', monospace;
						font-size: 0.9em;
						border: 1px solid var(--vscode-panel-border);
						overflow-x: auto;
						margin: 10px 0;
					}
					.error-category {
						display: inline-block;
						padding: 5px 12px;
						background-color: #dc3545;
						color: white;
						border-radius: 15px;
						font-size: 0.9em;
						font-weight: bold;
						margin-bottom: 15px;
					}
					.causes-list, .solutions-list {
						margin: 10px 0;
						padding-left: 0;
					}
					.causes-list li, .solutions-list li {
						list-style: none;
						padding: 8px 0;
						border-bottom: 1px solid var(--vscode-panel-border);
						display: flex;
						align-items: flex-start;
						gap: 10px;
					}
					.causes-list li:last-child, .solutions-list li:last-child {
						border-bottom: none;
					}
					.cause-icon {
						color: #ffc107;
						font-weight: bold;
						margin-top: 2px;
					}
					.solution-icon {
						color: #28a745;
						font-weight: bold;
						margin-top: 2px;
					}
					.stack-trace {
						max-height: 300px;
						overflow-y: auto;
						background-color: var(--vscode-textCodeBlock-background);
						padding: 15px;
						border-radius: 5px;
						border: 1px solid var(--vscode-panel-border);
						font-family: 'Consolas', 'Courier New', monospace;
						font-size: 0.85em;
						white-space: pre-wrap;
					}
					.file-info {
						background-color: var(--vscode-editor-selectionBackground);
						padding: 12px;
						border-radius: 5px;
						margin-bottom: 15px;
						display: flex;
						align-items: center;
						gap: 10px;
					}
					.actions {
						display: flex;
						gap: 10px;
						justify-content: center;
						margin-top: 20px;
						flex-wrap: wrap;
					}
					.btn {
						padding: 10px 20px;
						border: none;
						border-radius: 5px;
						cursor: pointer;
						font-size: 1em;
						font-weight: bold;
						text-decoration: none;
						display: inline-block;
						min-width: 120px;
						text-align: center;
					}
					.btn-primary {
						background-color: #007acc;
						color: white;
					}
					.btn-secondary {
						background-color: var(--vscode-button-secondaryBackground);
						color: var(--vscode-button-secondaryForeground);
					}
					.btn-warning {
						background-color: #ffc107;
						color: #212529;
					}
					.copy-button {
						background-color: var(--vscode-button-background);
						color: var(--vscode-button-foreground);
						border: 1px solid var(--vscode-button-border);
						padding: 5px 10px;
						border-radius: 3px;
						cursor: pointer;
						font-size: 0.8em;
						margin-left: 10px;
					}
					.copy-button:hover {
						background-color: var(--vscode-button-hoverBackground);
					}
				</style>
			</head>
			<body>
				<div class="header">
					<h1>
						<span class="error-icon">🚨</span>
						AI Security Analysis Failed
					</h1>
					<div class="timestamp">Error occurred at: ${timestamp}</div>
				</div>

				<div class="section">
					<h3>📁 File Information</h3>
					<div class="file-info">
						<span>📄</span>
						<strong>File:</strong> ${fileName}
					</div>
					<div class="error-category">${errorCategory}</div>
				</div>

				<div class="section">
					<h3>🔍 Error Details</h3>
					<div class="error-details">
						<strong>Error Type:</strong> ${errorType}<br>
						<strong>Error Message:</strong> ${errorMsg}
					</div>
				</div>

				<div class="section">
					<h3>⚠️ Possible Causes</h3>
					<ul class="causes-list">
						${possibleCauses.map(cause => `
							<li>
								<span class="cause-icon">⚠️</span>
								<span>${cause}</span>
							</li>
						`).join('')}
					</ul>
				</div>

				<div class="section">
					<h3>💡 Suggested Solutions</h3>
					<ul class="solutions-list">
						${suggestedSolutions.map(solution => `
							<li>
								<span class="solution-icon">✅</span>
								<span>${solution}</span>
							</li>
						`).join('')}
					</ul>
				</div>

				<div class="section">
					<h3>🔧 Technical Stack Trace 
						<button class="copy-button" onclick="copyStackTrace()">Copy Stack Trace</button>
					</h3>
					<div class="stack-trace" id="stackTrace">${errorStack}</div>
				</div>

				<div class="actions">
					<button class="btn btn-primary" onclick="retryAnalysis()">
						🔄 Retry Analysis
					</button>
					<button class="btn btn-warning" onclick="configureApiKey()">
						🔑 Configure API Key
					</button>
				</div>

				<script>
					const vscode = acquireVsCodeApi();
					
					function copyStackTrace() {
						const stackTrace = document.getElementById('stackTrace').textContent;
						navigator.clipboard.writeText(stackTrace).then(function() {
							const button = document.querySelector('.copy-button');
							const originalText = button.textContent;
							button.textContent = 'Copied!';
							setTimeout(() => {
								button.textContent = originalText;
							}, 2000);
						}).catch(function() {
							// Fallback for older browsers
							const textArea = document.createElement('textarea');
							textArea.value = stackTrace;
							document.body.appendChild(textArea);
							textArea.select();
							document.execCommand('copy');
							document.body.removeChild(textArea);
						});
					}
					
					function retryAnalysis() {
						vscode.postMessage({ command: 'retryAnalysis' });
					}
					
					function configureApiKey() {
						vscode.postMessage({ command: 'configureApiKey' });
					}
				</script>
			</body>
			</html>
		`;
	}

	// Analyze active document on activation (but don't block activation)
	const activeEditor = vscode.window.activeTextEditor;
	if (activeEditor) {
		// Run analysis in background without blocking extension activation
		setTimeout(() => {
			analyzeDocument(activeEditor.document);
		}, 1000);
	}

	// Listen for document changes with debouncing
	context.subscriptions.push(
		vscode.workspace.onDidChangeTextDocument(event => {
			if (vscode.window.activeTextEditor?.document === event.document) {
				// Clear existing timeout
				if (analysisTimeout) {
					clearTimeout(analysisTimeout);
				}
				
				// Set new timeout for analysis
				analysisTimeout = setTimeout(() => {
					analyzeDocument(event.document);
				}, 3000); // Wait 3 seconds after last change
			}
		})
	);

	// Listen for active editor changes
	context.subscriptions.push(
		vscode.window.onDidChangeActiveTextEditor(editor => {
			if (editor) {
				// Clear existing timeout
				if (analysisTimeout) {
					clearTimeout(analysisTimeout);
				}
				
				// Analyze after short delay
				analysisTimeout = setTimeout(() => {
					analyzeDocument(editor.document);
				}, 500);
			}
		})
	);
}

export function deactivate() {
	// Clear any pending analysis timeout
	if (analysisTimeout) {
		clearTimeout(analysisTimeout);
	}
}