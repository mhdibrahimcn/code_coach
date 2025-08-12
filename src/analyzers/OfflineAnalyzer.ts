import * as vscode from 'vscode';
import { SecurityIssue } from '../SecurityIssue';
import { LanguagePatterns, VulnerabilityPattern, BestPracticePattern } from '../core/LanguagePatterns';

export class OfflineAnalyzer {
    private static readonly CONFIDENCE_BOOST = {
        'xss': 0.14,
        'sql-injection': 0.20,
        'command-injection': 0.20,
        'crypto': 0.25,
        'auth': 0.14,
        'path-traversal': 0.15,
        'other': 0.09
    };

    public static async analyzeDocument(
        document: vscode.TextDocument,
        enableBestPractices: boolean = true
    ): Promise<SecurityIssue[]> {
        const issues: SecurityIssue[] = [];
        const language = document.languageId;
        const text = document.getText();

        // Get patterns for current language
        const vulnerabilityPatterns = LanguagePatterns.getVulnerabilityPatterns(language);
        const bestPracticePatterns = enableBestPractices ? 
            LanguagePatterns.getBestPracticePatterns(language) : [];

        // Analyze vulnerability patterns
        for (const pattern of vulnerabilityPatterns) {
            const matches = this.findPatternMatches(text, pattern.pattern);
            
            for (const match of matches) {
                const line = document.lineAt(document.positionAt(match.index).line);
                const startPos = document.positionAt(match.index);
                const endPos = document.positionAt(match.index + match.length);
                
                // Skip if it's in a comment (basic check)
                if (this.isInComment(line.text, startPos.character)) {
                    continue;
                }

                const confidence = this.calculateConfidence(pattern, match.text, line.text);
                
                const issue: SecurityIssue = {
                    type: 'vulnerability',
                    severity: pattern.severity,
                    message: `${pattern.name}`,
                    description: this.withContextLine(document, startPos.line, this.enhanceDescription(pattern, match.text)),
                    range: new vscode.Range(startPos, endPos),
                    source: 'Offline Pattern Analysis',
                    suggestion: pattern.suggestion,
                    confidence: Math.min(100, confidence),
                    cveReference: pattern.cweId ? `CWE-${pattern.cweId.replace('CWE-', '')}` : undefined
                };

                issues.push(issue);
            }
        }

        // Analyze best practice patterns
        for (const pattern of bestPracticePatterns) {
            const matches = this.findPatternMatches(text, pattern.pattern);
            
            for (const match of matches) {
                const startPos = document.positionAt(match.index);
                const endPos = document.positionAt(match.index + match.length);
                const line = document.lineAt(startPos.line);
                
                // Skip if it's in a comment (basic check)
                if (this.isInComment(line.text, startPos.character)) {
                    continue;
                }

                const issue: SecurityIssue = {
                    type: 'best-practice',
                    severity: pattern.severity,
                    message: `${pattern.name}`,
                    description: this.withContextLine(document, startPos.line, pattern.description),
                    range: new vscode.Range(startPos, endPos),
                    source: 'Offline Best Practice Analysis',
                    suggestion: pattern.suggestion,
                    confidence: 75
                };

                issues.push(issue);
            }
        }

        return this.deduplicateIssues(issues);
    }

    private static withContextLine(document: vscode.TextDocument, lineIndex: number, baseDescription: string): string {
        const contextLineIndex = Math.max(0, lineIndex - 1);
        const contextText = document.lineAt(contextLineIndex).text.trim();
        const prefix = contextText ? `Line ${contextLineIndex + 1}: ${contextText}\n` : '';
        return `${prefix}${baseDescription}`;
    }

    private static findPatternMatches(text: string, pattern: RegExp): Array<{ index: number; length: number; text: string }> {
        const matches: Array<{ index: number; length: number; text: string }> = [];
        let match;
        
        // Reset pattern to search from beginning
        pattern.lastIndex = 0;
        
        while ((match = pattern.exec(text)) !== null) {
            matches.push({
                index: match.index,
                length: match[0].length,
                text: match[0]
            });
            
            // Prevent infinite loop with global patterns
            if (!pattern.global) {
                break;
            }
        }
        
        return matches;
    }

    private static isInComment(lineText: string, position: number): boolean {
        // Heuristic comment detection
        const beforePosition = lineText.substring(0, position);
        const trimmed = beforePosition.trim();

        // Single-line comments: // in JS/TS/C-like, # in Python
        if (beforePosition.includes('//')) {
            return true;
        }
        if (trimmed.startsWith('#')) {
            return true;
        }

        // Multi-line comment start without closing on same line
        if (beforePosition.includes('/*') && !beforePosition.includes('*/')) {
            return true;
        }

        return false;
    }

    private static calculateConfidence(pattern: VulnerabilityPattern, matchText: string, lineText: string): number {
        let confidence = pattern.confidence;

        // Category baseline boost
        const categoryBoost = this.CONFIDENCE_BOOST[pattern.category as keyof typeof this.CONFIDENCE_BOOST] || 0;
        confidence += categoryBoost * 100;

        const lowerLineText = lineText.toLowerCase();
        const lowerMatchText = matchText.toLowerCase();

        // Input-source context boost
        const userInputSignals = ['user', 'input', 'request', 'param', 'body', 'query', 'headers', 'form', 'stdin'];
        if (userInputSignals.some(sig => lowerLineText.includes(sig))) {
            confidence += 12;
        }

        // Sanitization or validation presence reduces confidence slightly
        const mitigationSignals = ['sanitize', 'escape', 'validate', 'paramet', 'prepared', 'orm', 'safe_load', 'verify', 'dompurify', 'helmet', 'argon2', 'bcrypt', 'pbkdf2', 'scrypt'];
        if (mitigationSignals.some(sig => lowerLineText.includes(sig))) {
            confidence -= 18;
        }

        // High-risk keywords per category
        if (pattern.category === 'crypto') {
            if (/(password|hash|token)/i.test(lineText)) {
                confidence += 12;
            }
            // Additional auth/crypto context signals
            const authSignals = ['jwt', 'token', 'cookie', 'authorization', 'session', 'localstorage'];
            if (authSignals.some(sig => lowerLineText.includes(sig))) {
                confidence += 8;
            }
        } else if (pattern.category === 'xss') {
            if (/(innerhtml|outerhtml|html\(|dangerouslysetinnerhtml)/i.test(lowerMatchText)) {
                confidence += 8;
            }
        } else if (pattern.category === 'command-injection') {
            if (/(shell\s*=\s*true|exec|spawn|os\.system|subprocess)/i.test(lowerLineText)) {
                confidence += 10;
            }
        } else if (pattern.category === 'sql-injection') {
            if (/(select|insert|update|delete|where)/i.test(lowerLineText)) {
                confidence += 10;
            }
        } else if (pattern.category === 'path-traversal') {
            if (/(\.\.|resolve|join|basename)/i.test(lowerLineText)) {
                confidence += 6;
            }
        }

        // Dangerous function usage boosts
        const dangerousExecutionSignals = ['eval(', 'new function', 'settimeout(', 'setinterval('];
        if (dangerousExecutionSignals.some(sig => lowerLineText.includes(sig))) {
            confidence += 6;
        }

        // Likely non-production/test context reduces confidence
        if (/(test|spec|example|demo|mock)/i.test(lowerLineText)) {
            confidence -= 20;
        }

        return Math.max(10, Math.min(100, confidence));
    }

    private static enhanceDescription(pattern: VulnerabilityPattern, matchText: string): string {
        let description = pattern.description;

        // Add specific details based on the match
        switch (pattern.category) {
            case 'sql-injection':
                if (matchText.includes('${') || matchText.includes('+')) {
                    description += ' This code uses string concatenation to build SQL queries, which is vulnerable to injection attacks.';
                }
                break;
            case 'xss':
                if (matchText.includes('innerHTML')) {
                    description += ' Using innerHTML with unsanitized content allows attackers to inject malicious scripts.';
                }
                break;
            case 'crypto':
                if (matchText.toLowerCase().includes('md5')) {
                    description += ' MD5 is cryptographically broken due to collision vulnerabilities.';
                } else if (matchText.toLowerCase().includes('sha1')) {
                    description += ' SHA1 is deprecated and vulnerable to collision attacks.';
                }
                break;
            case 'command-injection':
                description += ' Executing system commands with user-controlled input can lead to arbitrary code execution.';
                break;
        }

        return description;
    }

    private static deduplicateIssues(issues: SecurityIssue[]): SecurityIssue[] {
        const seen = new Set<string>();
        const deduplicated: SecurityIssue[] = [];

        for (const issue of issues) {
            // Create a unique key for the issue
            const key = `${issue.range.start.line}-${issue.range.start.character}-${issue.message}`;
            
            if (!seen.has(key)) {
                seen.add(key);
                deduplicated.push(issue);
            }
        }

        return deduplicated;
    }

    public static async analyzeCodeSnippet(
        code: string, 
        language: string,
        enableBestPractices: boolean = true
    ): Promise<SecurityIssue[]> {
        // Create a temporary document for analysis
        const uri = vscode.Uri.parse(`untitled:temp.${this.getFileExtension(language)}`);
        
        try {
            const document = await vscode.workspace.openTextDocument({
                language,
                content: code
            });
            
            return this.analyzeDocument(document, enableBestPractices);
        } catch (error) {
            console.error('Error analyzing code snippet:', error);
            return [];
        }
    }

    private static getFileExtension(language: string): string {
        const extensions: Record<string, string> = {
            'javascript': 'js',
            'typescript': 'ts',
            'python': 'py',
            'java': 'java',
            'csharp': 'cs',
            'php': 'php',
            'go': 'go',
            'rust': 'rs',
            'cpp': 'cpp',
            'c': 'c'
        };
        
        return extensions[language] || 'txt';
    }

    public static getAnalysisCapabilities(language: string): {
        vulnerabilityPatterns: number;
        bestPracticePatterns: number;
        supportedCategories: string[];
    } {
        const vulnPatterns = LanguagePatterns.getVulnerabilityPatterns(language);
        const bpPatterns = LanguagePatterns.getBestPracticePatterns(language);
        
        const categories = new Set<string>();
        vulnPatterns.forEach(p => categories.add(p.category));
        bpPatterns.forEach(p => categories.add(p.category));

        return {
            vulnerabilityPatterns: vulnPatterns.length,
            bestPracticePatterns: bpPatterns.length,
            supportedCategories: Array.from(categories)
        };
    }
}