import * as vscode from 'vscode';
import { SecurityIssue } from '../SecurityIssue';
import { OfflineAnalyzer } from './OfflineAnalyzer';
import { SmartAIAnalyzer } from './SmartAIAnalyzer';
import { ComplexityAnalyzer } from '../ComplexityAnalyzer.1';
import { AIProviderManager } from '../core/AIProviderManager';

export interface AnalysisResult {
    issues: SecurityIssue[];
    analysisType: 'offline-only' | 'ai-only' | 'hybrid';
    executionTime: number;
    aiAnalysisUsed: boolean;
    tokenEstimate?: number;
}

export class HybridAnalyzer {
    private static readonly AI_THRESHOLD_CONFIDENCE = 70; // Issues below this will be sent to AI for validation
    private static readonly MAX_AI_VALIDATION_ISSUES = 10; // Max issues to validate with AI

    public static async analyzeDocument(
        document: vscode.TextDocument,
        progressCallback?: (message: string, tooltip?: string) => void
    ): Promise<AnalysisResult> {
        const startTime = Date.now();
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        
        const enableOffline = config.get<boolean>('enableOfflineAnalysis', true);
        const enableAI = config.get<boolean>('enableAIAnalysis', true);
        const hybridMode = config.get<boolean>('hybridMode', true);
        const enableBestPractices = config.get<boolean>('enableBestPractices', true);
        const enableComplexity = config.get<boolean>('enableComplexityAnalysis', true);
        
        let allIssues: SecurityIssue[] = [];
        let analysisType: 'offline-only' | 'ai-only' | 'hybrid';
        let aiAnalysisUsed = false;

        try {
            // Phase 1: AI-first Analysis (if enabled and configured)
            let offlineIssues: SecurityIssue[] = [];
            let aiIssues: SecurityIssue[] = [];

            if (enableAI && AIProviderManager.hasValidConfig()) {
                progressCallback?.('🤖 Running AI-powered analysis...', 'Deep AI analysis starting (AI-first)');
                try {
                    aiIssues = await SmartAIAnalyzer.analyzeDocument(
                        document,
                        [],
                        progressCallback
                    );
                    allIssues.push(...aiIssues);
                    aiAnalysisUsed = true;
                    analysisType = hybridMode ? 'hybrid' : 'ai-only';
                    console.log(`AI-first analysis found ${aiIssues.length} issues`);
                } catch (aiError) {
                    console.warn('AI analysis failed, will fall back to offline:', aiError);
                    analysisType = 'offline-only';
                }
            } else {
                // Prompt user to configure AI provider if AI is enabled but not configured
                if (enableAI && !AIProviderManager.hasValidConfig()) {
                    progressCallback?.('⚠️ AI analysis unavailable', 'Offline basic research will be used');
                    vscode.window
                        .showInformationMessage(
                            'AI analysis is not configured. Configure now for deeper results, or continue in offline mode.',
                            'Open Settings',
                            'Continue Offline'
                        )
                        .then(selection => {
                            if (selection === 'Open Settings') {
                                vscode.commands.executeCommand('codeSecurityAnalyzer.openSettings');
                            }
                        });
                }
                analysisType = 'offline-only';
            }

            // Phase 2: Offline Analysis (as supplement or fallback)
            if (enableOffline) {
                progressCallback?.('🔍 Running offline basic research...', 'Scanning with language-specific vulnerability patterns');
                offlineIssues = await OfflineAnalyzer.analyzeDocument(document, enableBestPractices);
                console.log(`Offline analysis found ${offlineIssues.length} issues`);

                if (aiIssues.length > 0 && hybridMode) {
                    // Merge offline into AI as supplemental
                    allIssues = this.mergeIssues(aiIssues, offlineIssues);
                    analysisType = 'hybrid';
                } else if (aiIssues.length === 0) {
                    // AI not used or failed; use offline issues as primary
                    allIssues.push(...offlineIssues);
                    analysisType = 'offline-only';
                }
            }

            // Phase 3: Complexity Analysis
            if (enableComplexity) {
                progressCallback?.('📊 Analyzing code complexity...', 'Calculating cyclomatic and cognitive complexity');
                const complexityIssues = await this.analyzeComplexity(document);
                allIssues.push(...complexityIssues);
                console.log(`Complexity analysis found ${complexityIssues.length} issues`);
            }

            // Phase 4: Final processing
            progressCallback?.('✨ Finalizing analysis...', 
                'Organizing and prioritizing security findings');
            
            // Sort issues by severity and confidence
            allIssues = this.prioritizeIssues(allIssues);
            
            const executionTime = Date.now() - startTime;
            console.log(`Analysis completed in ${executionTime}ms: ${allIssues.length} total issues`);

            return {
                issues: allIssues,
                analysisType,
                executionTime,
                aiAnalysisUsed,
                tokenEstimate: aiAnalysisUsed ? this.estimateTokenUsage(document) : undefined
            };

        } catch (error) {
            console.error('Hybrid analysis failed:', error);
            
            // Fallback to offline-only analysis
            if (enableOffline && allIssues.length === 0) {
                progressCallback?.('🔄 Falling back to offline analysis...', 
                    'AI analysis failed, using offline pattern detection');
                
                try {
                    const fallbackIssues = await OfflineAnalyzer.analyzeDocument(document, enableBestPractices);
                    if (enableComplexity) {
                        const complexityIssues = await this.analyzeComplexity(document);
                        fallbackIssues.push(...complexityIssues);
                    }
                    
                    return {
                        issues: this.prioritizeIssues(fallbackIssues),
                        analysisType: 'offline-only',
                        executionTime: Date.now() - startTime,
                        aiAnalysisUsed: false
                    };
                } catch (fallbackError) {
                    console.error('Fallback analysis also failed:', fallbackError);
                }
            }

            // Return whatever issues we managed to collect
            return {
                issues: this.prioritizeIssues(allIssues),
                analysisType: aiAnalysisUsed ? 'hybrid' : 'offline-only',
                executionTime: Date.now() - startTime,
                aiAnalysisUsed
            };
        }
    }

    private static async analyzeComplexity(document: vscode.TextDocument): Promise<SecurityIssue[]> {
        try {
            const functions = ComplexityAnalyzer.analyzeFunctions(document);
            const issues: SecurityIssue[] = [];

            for (const func of functions) {
                const complexity = func.complexity.cyclomaticComplexity;
                let severity: vscode.DiagnosticSeverity;
                let message: string;
                
                if (complexity > 15) {
                    severity = vscode.DiagnosticSeverity.Error;
                    message = `High complexity function (${complexity}) - Urgent refactoring needed`;
                } else if (complexity > 10) {
                    severity = vscode.DiagnosticSeverity.Warning;
                    message = `Medium complexity function (${complexity}) - Consider refactoring`;
                } else {
                    continue; // Skip low complexity functions
                }

                const issue: SecurityIssue = {
                    type: 'complexity',
                    severity,
                    message,
                    description: `Function '${func.name}' has high cyclomatic complexity (${complexity}). High complexity increases the likelihood of bugs and security vulnerabilities.`,
                    range: func.range,
                    source: 'Complexity Analyzer',
                    suggestion: complexity > 15 
                        ? 'Break this function into smaller, more focused functions. Consider extracting complex logic into separate methods.'
                        : 'Consider simplifying the logic or breaking into smaller functions.',
                    confidence: 95,
                    complexityScore: complexity,
                    functionName: func.name
                };

                issues.push(issue);
            }

            return issues;
        } catch (error) {
            console.error('Complexity analysis failed:', error);
            return [];
        }
    }

    private static mergeIssues(offlineIssues: SecurityIssue[], aiIssues: SecurityIssue[]): SecurityIssue[] {
        const merged: SecurityIssue[] = [...offlineIssues];
        const seenLocations = new Set<string>();

        // Create location keys for existing offline issues
        for (const issue of offlineIssues) {
            const key = `${issue.range.start.line}-${issue.range.start.character}`;
            seenLocations.add(key);
        }

        // Add AI issues that don't overlap with offline issues
        for (const aiIssue of aiIssues) {
            const key = `${aiIssue.range.start.line}-${aiIssue.range.start.character}`;
            
            if (!seenLocations.has(key)) {
                merged.push(aiIssue);
                seenLocations.add(key);
            } else {
                // Enhance existing offline issue with AI insights
                const existingIssue = merged.find(issue => 
                    issue.range.start.line === aiIssue.range.start.line &&
                    issue.range.start.character === aiIssue.range.start.character
                );
                
                if (existingIssue && aiIssue.confidence > existingIssue.confidence) {
                    // Update with AI's more confident analysis
                    existingIssue.description = `${existingIssue.description}\n\nAI Enhancement: ${aiIssue.description}`;
                    existingIssue.confidence = Math.max(existingIssue.confidence, aiIssue.confidence);
                    existingIssue.source = `${existingIssue.source} + AI Validation`;
                    
                    if (aiIssue.suggestion && aiIssue.suggestion !== existingIssue.suggestion) {
                        existingIssue.suggestion = aiIssue.suggestion;
                    }
                }
            }
        }

        return merged;
    }

    private static prioritizeIssues(issues: SecurityIssue[]): SecurityIssue[] {
        return issues.sort((a, b) => {
            // First by severity (Error > Warning > Info)
            if (a.severity !== b.severity) {
                return a.severity - b.severity;
            }
            
            // Then by confidence (higher first)
            if (a.confidence !== b.confidence) {
                return b.confidence - a.confidence;
            }
            
            // Then by type (vulnerability > error > warning > complexity > best-practice)
            const typeOrder = { 'vulnerability': 0, 'error': 1, 'warning': 2, 'complexity': 3, 'best-practice': 4 };
            const aOrder = typeOrder[a.type] || 5;
            const bOrder = typeOrder[b.type] || 5;
            
            if (aOrder !== bOrder) {
                return aOrder - bOrder;
            }
            
            // Finally by line number
            return a.range.start.line - b.range.start.line;
        });
    }

    private static estimateTokenUsage(document: vscode.TextDocument): number {
        // Rough estimate: 1 token ≈ 4 characters for English text
        // Code might be different, but this gives a ballpark
        const text = document.getText();
        return Math.ceil(text.length / 3.5); // Slightly more conservative estimate for code
    }

    public static async quickAnalysis(
        document: vscode.TextDocument,
        focusOnSecurity: boolean = true
    ): Promise<SecurityIssue[]> {
        // Fast analysis for real-time feedback
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        const enableOffline = config.get<boolean>('enableOfflineAnalysis', true);
        
        if (!enableOffline) {
            return [];
        }

        try {
            const issues = await OfflineAnalyzer.analyzeDocument(document, !focusOnSecurity);
            
            // For quick analysis, only return high-confidence issues
            return issues.filter(issue => 
                issue.confidence >= 80 || 
                issue.severity === vscode.DiagnosticSeverity.Error
            );
        } catch (error) {
            console.error('Quick analysis failed:', error);
            return [];
        }
    }

    public static getAnalysisCapabilities(): {
        offlinePatterns: number;
        aiProviders: number;
        supportedLanguages: string[];
        hybridModeAvailable: boolean;
    } {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        const language = vscode.window.activeTextEditor?.document.languageId || 'javascript';
        
        const capabilities = OfflineAnalyzer.getAnalysisCapabilities(language);
        const providers = AIProviderManager.getProviders();
        
        return {
            offlinePatterns: capabilities.vulnerabilityPatterns + capabilities.bestPracticePatterns,
            aiProviders: providers.length,
            supportedLanguages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php', 'go', 'rust', 'cpp', 'c'],
            hybridModeAvailable: AIProviderManager.hasValidConfig()
        };
    }

    public static async validateAIProvider(): Promise<{
        isValid: boolean;
        provider?: string;
        model?: string;
        error?: string;
    }> {
        if (!AIProviderManager.hasValidConfig()) {
            return {
                isValid: false,
                error: 'No AI provider configured or missing API key'
            };
        }

        const config = AIProviderManager.getCurrentConfig()!;
        
        try {
            // Test with a simple request
            const response = await AIProviderManager.makeRequest([
                {
                    role: 'user',
                    content: 'Respond with just "OK" to confirm the API is working.'
                }
            ], 10);
            
            const content = response.choices?.[0]?.message?.content || '';
            
            return {
                isValid: content.trim().toLowerCase().includes('ok'),
                provider: config.provider.name,
                model: config.model
            };
        } catch (error) {
            return {
                isValid: false,
                provider: config.provider.name,
                model: config.model,
                error: error instanceof Error ? error.message : String(error)
            };
        }
    }
}