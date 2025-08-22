import * as vscode from 'vscode';
import { SecurityIssue, FunctionVulnerability, VulnerabilityDetails, DeepAnalysisResult } from '../SecurityIssue';
import { AIProviderManager } from '../core/AIProviderManager';
import { SecurityRuleEngine } from '../rules/SecurityRuleEngine';
import { logger } from '../core/DebugLogger';

export class DeepSecurityAnalyzer {
    private static readonly FUNCTION_PATTERNS = {
        javascript: [
            /function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g,
            /const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:function\s*)?\(/g,
            /let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:function\s*)?\(/g,
            /var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:function\s*)?\(/g,
            /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*(?:async\s+)?(?:function\s*)?\(/g,
            /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)\s*=>|\([^)]*\)\s*=>\s*{)/g,
            /async\s+function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g,
            /class\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*{[^}]*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g
        ],
        typescript: [
            /function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g,
            /const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:function\s*)?\(/g,
            /let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:function\s*)?\(/g,
            /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*(?:async\s+)?(?:function\s*)?\(/g,
            /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)\s*=>|\([^)]*\)\s*=>\s*{)/g,
            /async\s+function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g,
            /(?:public|private|protected|readonly)?\s*(?:static\s+)?(?:async\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g
        ],
        python: [
            /def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /async\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /@\w+\s*\n\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /class\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(?:\([^)]*\))?\s*:[^{]*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g
        ],
        java: [
            /(?:public|private|protected|final|static|abstract|synchronized|native|strictfp|\s)+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g,
            /@\w+\s*\n\s*(?:public|private|protected)?\s*(?:static)?\s*[a-zA-Z_<>\[\]]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g
        ],
        csharp: [
            /(?:public|private|protected|internal|override|virtual|abstract|static|async|\s)+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /\[[\w\s,()]*\]\s*(?:public|private|protected|internal)?\s*(?:static)?\s*[a-zA-Z_<>\[\]]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g
        ],
        php: [
            /function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /(?:public|private|protected)?\s*(?:static)?\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /class\s+[a-zA-Z_][a-zA-Z0-9_]*\s*{[^}]*(?:public|private|protected)?\s*(?:static)?\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g
        ],
        go: [
            /func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /func\s+\([^)]*\)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g
        ],
        rust: [
            /fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /impl\s+[^{]*\s*{\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g
        ],
        cpp: [
            /(?:inline|virtual|static|explicit|constexpr|\s)*[a-zA-Z_<>\[\]~]+\s+(?:[a-zA-Z_:]+::)*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /class\s+[a-zA-Z_][a-zA-Z0-9_]*\s*{[^}]*(?:public|private|protected):\s*[^}]*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g
        ],
        c: [
            /(?:static|inline|extern|\s)*[a-zA-Z_]+\s*\*?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g,
            /typedef\s+[^;]*\(\*([a-zA-Z_][a-zA-Z0-9_]*)\)\s*\(/g
        ]
    };

    public static async analyzeDocument(
        document: vscode.TextDocument,
        progressCallback?: (message: string) => void
    ): Promise<DeepAnalysisResult> {
        const startTime = Date.now();
        logger.logAnalysisStart(document, 'Deep Security Analysis');
        progressCallback?.('🔍 Starting deep security analysis...');

        // Phase 1: Rule-based analysis (fast)
        progressCallback?.('📋 Running rule-based security checks...');
        const ruleBasedIssues = SecurityRuleEngine.analyzeDocument(document);
        logger.info(`Rule-based analysis found ${ruleBasedIssues.length} issues`);

        // Phase 2: Function extraction and analysis
        const functions = this.extractFunctions(document);
        progressCallback?.(`📊 Found ${functions.length} functions to analyze...`);
        logger.info(`Extracted ${functions.length} functions for analysis`, {
            functions: functions.map(f => ({ name: f.functionName, lines: `${f.startLine}-${f.endLine}` }))
        });

        const functionVulnerabilities: FunctionVulnerability[] = [];
        const allIssues: SecurityIssue[] = [...ruleBasedIssues];

        // Analyze each function independently
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        const maxFunctions = config.get<number>('maxFunctionsToAnalyze', 20);
        const functionsToAnalyze = functions.slice(0, maxFunctions);
        
        if (functions.length > maxFunctions) {
            logger.warn(`Limiting analysis to ${maxFunctions} functions (found ${functions.length})`);
            progressCallback?.(`⚠️ Analyzing first ${maxFunctions} of ${functions.length} functions...`);
        }

        for (let i = 0; i < functionsToAnalyze.length; i++) {
            const func = functionsToAnalyze[i];
            const functionStartTime = Date.now();
            progressCallback?.(`🔍 Analyzing function ${i + 1}/${functionsToAnalyze.length}: ${func.functionName}...`);
            
            logger.debug(`Starting analysis of function: ${func.functionName}`, {
                lines: `${func.startLine}-${func.endLine}`,
                codeLength: func.codeChunk.length
            });

            try {
                const funcVulns = await this.analyzeFunctionSecurity(func, document);
                const functionDuration = Date.now() - functionStartTime;
                
                logger.logFunctionAnalysis(func.functionName, func.startLine, func.endLine, funcVulns.vulnerabilities.length);
                logger.logPerformanceMetric(`Function ${func.functionName} analysis`, functionDuration);
                
                // Always add function analysis (even if no vulnerabilities for tracking)
                functionVulnerabilities.push(funcVulns);
                
                if (funcVulns.vulnerabilities.length > 0) {
                    // Convert function vulnerabilities to SecurityIssues
                    const functionIssues = this.convertToSecurityIssues(funcVulns, document);
                    allIssues.push(...functionIssues);
                    
                    logger.info(`Function ${func.functionName} has ${funcVulns.vulnerabilities.length} vulnerabilities`, {
                        risk: funcVulns.securityRisk,
                        complexity: funcVulns.complexity
                    });
                }
                
                // Dynamic delay based on function analysis time
                const delay = Math.min(500, Math.max(200, functionDuration * 0.1));
                if (i < functionsToAnalyze.length - 1) {
                    await this.delay(delay);
                }
            } catch (error) {
                logger.logError(`Function analysis for ${func.functionName}`, error, {
                    functionLocation: `${func.startLine}-${func.endLine}`,
                    codeLength: func.codeChunk.length
                });
                
                // Create a failed analysis result
                const failedAnalysis: FunctionVulnerability = {
                    functionName: func.functionName,
                    startLine: func.startLine,
                    endLine: func.endLine,
                    vulnerabilities: [],
                    complexity: 1,
                    securityRisk: 'low',
                    codeChunk: func.codeChunk
                };
                functionVulnerabilities.push(failedAnalysis);
            }
        }

        // Phase 3: Perform whole-file analysis for complex vulnerabilities
        progressCallback?.('🔍 Performing comprehensive file analysis...');
        try {
            const globalIssues = await this.performGlobalAnalysis(document);
            allIssues.push(...globalIssues);
            logger.info(`Global analysis found ${globalIssues.length} additional issues`);
        } catch (error) {
            logger.logError('Global analysis', error);
            progressCallback?.('⚠️ Global analysis failed, continuing with function results...');
        }

        // Phase 4: Calculate overall risk assessment
        progressCallback?.('📊 Calculating risk assessment...');
        const overallRisk = this.calculateOverallRisk(allIssues, functionVulnerabilities);
        const summary = this.generateSummary(allIssues, functionVulnerabilities);

        const executionTime = Date.now() - startTime;
        const deduplicatedIssues = this.deduplicateIssues(allIssues);
        
        logger.logAnalysisEnd(document, 'Deep Security Analysis', executionTime, deduplicatedIssues.length);
        progressCallback?.(`✅ Deep analysis completed in ${executionTime}ms`);

        const aiConfig = AIProviderManager.getCurrentConfig();
        
        const result: DeepAnalysisResult = {
            issues: deduplicatedIssues,
            functionVulnerabilities,
            overallRisk,
            summary,
            analysisMetadata: {
                analysisType: 'deep',
                executionTime,
                aiProvider: aiConfig ? `${aiConfig.provider.name} (${aiConfig.model})` : undefined,
                timestamp: Date.now()
            }
        };

        logger.info('Deep analysis completed successfully', {
            totalIssues: result.issues.length,
            overallRisk: result.overallRisk,
            functionsAnalyzed: result.functionVulnerabilities.length,
            ruleBasedIssues: ruleBasedIssues.length,
            aiAnalyzedFunctions: functionsToAnalyze.length,
            executionTime
        });

        return result;
    }

    private static extractFunctions(document: vscode.TextDocument): Array<{functionName: string, startLine: number, endLine: number, codeChunk: string}> {
        const language = document.languageId;
        const patterns = this.FUNCTION_PATTERNS[language as keyof typeof this.FUNCTION_PATTERNS];
        
        if (!patterns) {
            return [];
        }

        const functions: Array<{functionName: string, startLine: number, endLine: number, codeChunk: string}> = [];
        const text = document.getText();
        const lines = text.split('\n');

        for (const pattern of patterns) {
            let match;
            while ((match = pattern.exec(text)) !== null) {
                const functionName = match[1];
                const matchIndex = match.index;
                
                // Find the line number
                const beforeMatch = text.substring(0, matchIndex);
                const lineNumber = beforeMatch.split('\n').length - 1;
                
                // Find function boundaries
                const boundaries = this.findFunctionBoundaries(lines, lineNumber, language);
                
                if (boundaries.endLine > boundaries.startLine) {
                    const codeChunk = lines.slice(boundaries.startLine, boundaries.endLine + 1).join('\n');
                    
                    functions.push({
                        functionName,
                        startLine: boundaries.startLine,
                        endLine: boundaries.endLine,
                        codeChunk
                    });
                }
            }
        }

        return functions;
    }

    private static findFunctionBoundaries(lines: string[], startLine: number, language: string): {startLine: number, endLine: number} {
        let braceCount = 0;
        let inFunction = false;
        let functionStartLine = startLine;
        let functionEndLine = startLine;

        // Find actual function start (handle multi-line declarations)
        for (let i = Math.max(0, startLine - 3); i <= Math.min(lines.length - 1, startLine + 3); i++) {
            if (lines[i].includes('function') || lines[i].includes('def ') || lines[i].includes('func ') || 
                lines[i].includes('fn ') || lines[i].match(/\w+\s*\(/)) {
                functionStartLine = i;
                break;
            }
        }

        // Find function end by tracking braces/indentation
        for (let i = functionStartLine; i < lines.length; i++) {
            const line = lines[i];
            
            if (language === 'python') {
                // Python uses indentation
                if (i > functionStartLine && line.trim() && !line.startsWith(' ') && !line.startsWith('\t')) {
                    functionEndLine = i - 1;
                    break;
                }
            } else {
                // Brace-based languages
                const openBraces = (line.match(/\{/g) || []).length;
                const closeBraces = (line.match(/\}/g) || []).length;
                
                if (openBraces > 0) {
                    inFunction = true;
                }
                
                braceCount += openBraces - closeBraces;
                
                if (inFunction && braceCount <= 0) {
                    functionEndLine = i;
                    break;
                }
            }
            
            // Prevent infinite loops
            if (i - functionStartLine > 200) {
                functionEndLine = i;
                break;
            }
        }

        return { startLine: functionStartLine, endLine: functionEndLine };
    }

    private static async analyzeFunctionSecurity(
        func: {functionName: string, startLine: number, endLine: number, codeChunk: string},
        document: vscode.TextDocument
    ): Promise<FunctionVulnerability> {
        if (!AIProviderManager.hasValidConfig()) {
            return {
                functionName: func.functionName,
                startLine: func.startLine,
                endLine: func.endLine,
                vulnerabilities: [],
                complexity: 1,
                securityRisk: 'low',
                codeChunk: func.codeChunk
            };
        }

        const prompt = this.buildFunctionAnalysisPrompt(func, document.languageId);
        
        try {
            const response = await AIProviderManager.makeRequest([
                {
                    role: 'system',
                    content: 'You are a senior security engineer specializing in function-level vulnerability analysis. Provide detailed, actionable security assessment with OWASP and CWE mappings.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ], 3000);

            return this.parseFunctionAnalysisResponse(response, func);
        } catch (error) {
            console.error(`Function analysis failed for ${func.functionName}:`, error);
            return {
                functionName: func.functionName,
                startLine: func.startLine,
                endLine: func.endLine,
                vulnerabilities: [],
                complexity: 1,
                securityRisk: 'low',
                codeChunk: func.codeChunk
            };
        }
    }

    private static buildFunctionAnalysisPrompt(
        func: {functionName: string, startLine: number, endLine: number, codeChunk: string},
        language: string
    ): string {
        return `Perform a comprehensive security analysis of this ${language} function. Focus on vulnerability detection and risk assessment.

Function: ${func.functionName}
Lines: ${func.startLine + 1}-${func.endLine + 1}

Provide JSON response with this exact structure:
{
  "vulnerabilities": [
    {
      "type": "vulnerability type (e.g., SQL Injection, XSS, etc.)",
      "severity": "critical|high|medium|low",
      "description": "brief description",
      "explanation": "detailed technical explanation",
      "mitigation": "specific mitigation strategy",
      "cweId": "CWE-XXX (if applicable)",
      "owaspCategory": "OWASP category (if applicable)",
      "affectedLines": [relative line numbers within function],
      "confidence": number (0-100)
    }
  ],
  "complexity": number (1-10 complexity score),
  "securityRisk": "critical|high|medium|low",
  "analysis": "overall security assessment"
}

Focus on these security areas:
1. Input validation and sanitization (missing/insufficient validation)
2. SQL injection vulnerabilities (string concatenation, dynamic queries)
3. XSS (Cross-Site Scripting) - stored, reflected, and DOM-based
4. Command injection (system calls with user input)
5. Path traversal (../../../etc/passwd style attacks)
6. Authentication/authorization bypass (missing checks, weak tokens)
7. Cryptographic weaknesses (weak algorithms, hardcoded keys, improper usage)
8. Race conditions (time-of-check-time-of-use, shared state)
9. Buffer overflows (unsafe string operations, array bounds)
10. Deserialization vulnerabilities (unsafe object deserialization)
11. SSRF (Server-Side Request Forgery) - internal network access
12. XXE (XML External Entity) injection - external entity processing
13. LDAP injection (unescaped LDAP queries)
14. NoSQL injection (MongoDB, CouchDB query injection)
15. Prototype pollution (JS/TS) - __proto__ manipulation
16. Memory safety issues (use-after-free, double-free, null dereference)
17. Insecure random number generation (predictable randomness)
18. Information disclosure (logging secrets, error messages, debug info)
19. Privilege escalation (improper permission checks)
20. Business logic vulnerabilities (workflow bypass, rate limiting)
21. File upload vulnerabilities (unrestricted file types, path manipulation)
22. CSRF (Cross-Site Request Forgery) - missing tokens
23. Session management flaws (insecure cookies, session fixation)
24. HTTP header injection (CRLF injection)
25. Template injection (server-side template injection)
26. Regular expression DoS (ReDoS)
27. Integer overflow/underflow
28. Timing attacks (password comparison, cryptographic operations)
29. Mass assignment vulnerabilities
30. Insecure direct object references (IDOR)

Code to analyze:
\`\`\`${language}
${func.codeChunk}
\`\`\`

Return only the JSON response, no additional text.`;
    }

    private static async performGlobalAnalysis(document: vscode.TextDocument): Promise<SecurityIssue[]> {
        if (!AIProviderManager.hasValidConfig()) {
            return [];
        }

        const content = document.getText();
        const prompt = this.buildGlobalAnalysisPrompt(content, document.languageId);
        
        try {
            const response = await AIProviderManager.makeRequest([
                {
                    role: 'system',
                    content: 'You are a security expert performing comprehensive file-level security analysis. Focus on architecture, data flow, and cross-function vulnerabilities.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ], 4000);

            return this.parseGlobalAnalysisResponse(response, document);
        } catch (error) {
            console.error('Global analysis failed:', error);
            return [];
        }
    }

    private static buildGlobalAnalysisPrompt(content: string, language: string): string {
        return `Perform a comprehensive file-level security analysis of this ${language} code. Focus on architectural vulnerabilities, data flow issues, and cross-function security concerns.

Provide JSON response:
{
  "issues": [
    {
      "type": "vulnerability|error|warning",
      "severity": "error|warning|info",
      "message": "brief description",
      "description": "detailed explanation",
      "suggestion": "fix recommendation",
      "lineNumber": number,
      "columnStart": number,
      "columnEnd": number,
      "confidence": number (0-100),
      "cweId": "CWE-XXX (if applicable)",
      "owaspCategory": "OWASP category (if applicable)",
      "category": "security|performance|maintainability|reliability|style",
      "riskLevel": "critical|high|medium|low"
    }
  ]
}

Focus on:
1. Architecture-level security flaws (insecure design patterns)
2. Data flow vulnerabilities (unvalidated data propagation)
3. Configuration issues (insecure defaults, missing security headers)
4. Dependency vulnerabilities (outdated packages, known CVEs)
5. Security misconfigurations (exposed debug endpoints, weak settings)
6. Cross-function data leakage (shared mutable state, global variables)
7. Global state vulnerabilities (singleton pattern abuse, static data)
8. Import/export security issues (unsafe imports, exposed internals)
9. Environment variable exposure (hardcoded secrets, config leaks)
10. Secret management problems (plain text storage, weak encryption)
11. API security issues (missing rate limiting, exposed endpoints)
12. Error handling flaws (information disclosure in errors)
13. Logging security issues (sensitive data in logs)
14. Concurrency issues (thread safety, shared resource access)
15. Network security problems (unencrypted communications)
16. File system security (unsafe file operations, permission issues)
17. Memory management issues (resource leaks, unsafe allocations)
18. Third-party integration security (unsafe API calls)
19. Data validation at application boundaries
20. Security monitoring and alerting gaps

Code:
\`\`\`${language}
${content.length > 8000 ? content.substring(0, 8000) + '\n...[truncated]' : content}
\`\`\`

Return only JSON, no additional text.`;
    }

    private static parseFunctionAnalysisResponse(
        response: any,
        func: {functionName: string, startLine: number, endLine: number, codeChunk: string}
    ): FunctionVulnerability {
        try {
            const content = response.choices?.[0]?.message?.content || '';
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            
            if (!jsonMatch) {
                throw new Error('No JSON found in response');
            }

            const parsed = JSON.parse(this.fixJsonEscaping(jsonMatch[0]));
            
            const vulnerabilities: VulnerabilityDetails[] = (parsed.vulnerabilities || []).map((vuln: any) => ({
                type: vuln.type || 'Unknown Vulnerability',
                severity: vuln.severity || 'medium',
                description: vuln.description || '',
                explanation: vuln.explanation || '',
                mitigation: vuln.mitigation || '',
                cweId: vuln.cweId,
                owaspCategory: vuln.owaspCategory,
                affectedLines: Array.isArray(vuln.affectedLines) ? vuln.affectedLines.map((line: number) => func.startLine + line) : [],
                confidence: Math.min(100, Math.max(0, vuln.confidence || 75))
            }));

            return {
                functionName: func.functionName,
                startLine: func.startLine,
                endLine: func.endLine,
                vulnerabilities,
                complexity: Math.min(10, Math.max(1, parsed.complexity || 1)),
                securityRisk: parsed.securityRisk || 'low',
                codeChunk: func.codeChunk
            };
        } catch (error) {
            console.error('Error parsing function analysis response:', error);
            return {
                functionName: func.functionName,
                startLine: func.startLine,
                endLine: func.endLine,
                vulnerabilities: [],
                complexity: 1,
                securityRisk: 'low',
                codeChunk: func.codeChunk
            };
        }
    }

    private static parseGlobalAnalysisResponse(response: any, document: vscode.TextDocument): SecurityIssue[] {
        try {
            const content = response.choices?.[0]?.message?.content || '';
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            
            if (!jsonMatch) {
                return [];
            }

            const parsed = JSON.parse(this.fixJsonEscaping(jsonMatch[0]));
            const issues: SecurityIssue[] = [];

            if (parsed.issues && Array.isArray(parsed.issues)) {
                for (const issue of parsed.issues) {
                    try {
                        const lineNumber = Math.max(0, (issue.lineNumber || 1) - 1);
                        const line = lineNumber < document.lineCount ? document.lineAt(lineNumber) : null;
                        
                        if (!line) continue;

                        const startChar = Math.max(0, issue.columnStart || 0);
                        const endChar = Math.min(line.text.length, issue.columnEnd || line.text.length);

                        const securityIssue: SecurityIssue = {
                            type: issue.type || 'vulnerability',
                            severity: this.mapSeverity(issue.severity),
                            message: issue.message || 'Security Issue Detected',
                            description: issue.description || '',
                            range: new vscode.Range(lineNumber, startChar, lineNumber, endChar),
                            source: 'Deep Security Analysis',
                            suggestion: issue.suggestion,
                            confidence: Math.min(100, Math.max(0, issue.confidence || 80)),
                            cveReference: issue.cweId,
                            category: issue.category || 'security',
                            owaspCategory: issue.owaspCategory,
                            cweId: issue.cweId,
                            riskLevel: issue.riskLevel || 'medium',
                            isDeepAnalysis: true
                        };

                        issues.push(securityIssue);
                    } catch (issueError) {
                        console.warn('Error processing issue:', issueError);
                    }
                }
            }

            return issues;
        } catch (error) {
            console.error('Error parsing global analysis response:', error);
            return [];
        }
    }

    private static convertToSecurityIssues(funcVuln: FunctionVulnerability, document: vscode.TextDocument): SecurityIssue[] {
        const issues: SecurityIssue[] = [];

        for (const vuln of funcVuln.vulnerabilities) {
            for (const lineNumber of vuln.affectedLines) {
                if (lineNumber < 0 || lineNumber >= document.lineCount) continue;

                const line = document.lineAt(lineNumber);
                
                const issue: SecurityIssue = {
                    type: 'vulnerability',
                    severity: this.mapSeverityString(vuln.severity),
                    message: `${vuln.type} in function '${funcVuln.functionName}'`,
                    description: vuln.explanation,
                    range: new vscode.Range(lineNumber, 0, lineNumber, line.text.length),
                    source: 'Deep Function Analysis',
                    suggestion: vuln.mitigation,
                    confidence: vuln.confidence,
                    cveReference: vuln.cweId,
                    functionName: funcVuln.functionName,
                    category: 'security',
                    owaspCategory: vuln.owaspCategory,
                    cweId: vuln.cweId,
                    functionStartLine: funcVuln.startLine,
                    functionEndLine: funcVuln.endLine,
                    riskLevel: vuln.severity,
                    vulnerabilityType: vuln.type,
                    affectedLines: vuln.affectedLines,
                    complexityScore: funcVuln.complexity,
                    isDeepAnalysis: true
                };

                issues.push(issue);
            }
        }

        // Add function-level complexity warning if needed
        if (funcVuln.complexity > 7 || funcVuln.securityRisk === 'high' || funcVuln.securityRisk === 'critical') {
            const issue: SecurityIssue = {
                type: 'complexity',
                severity: funcVuln.securityRisk === 'critical' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning,
                message: `High complexity function '${funcVuln.functionName}' (risk: ${funcVuln.securityRisk})`,
                description: `This function has high complexity (${funcVuln.complexity}/10) and ${funcVuln.securityRisk} security risk with ${funcVuln.vulnerabilities.length} potential vulnerabilities.`,
                range: new vscode.Range(funcVuln.startLine, 0, funcVuln.endLine, 0),
                source: 'Deep Function Analysis - Complexity',
                suggestion: 'Consider refactoring this function to reduce complexity and improve security.',
                confidence: 90,
                functionName: funcVuln.functionName,
                category: 'maintainability',
                functionStartLine: funcVuln.startLine,
                functionEndLine: funcVuln.endLine,
                riskLevel: funcVuln.securityRisk,
                complexityScore: funcVuln.complexity,
                isDeepAnalysis: true
            };

            issues.push(issue);
        }

        return issues;
    }

    private static calculateOverallRisk(issues: SecurityIssue[], functionVulns: FunctionVulnerability[]): 'low' | 'medium' | 'high' | 'critical' {
        const criticalCount = issues.filter(i => i.riskLevel === 'critical').length;
        const highCount = issues.filter(i => i.riskLevel === 'high').length;
        const criticalFunctions = functionVulns.filter(f => f.securityRisk === 'critical').length;
        const highRiskFunctions = functionVulns.filter(f => f.securityRisk === 'high').length;

        if (criticalCount > 0 || criticalFunctions > 0) {
            return 'critical';
        } else if (highCount > 2 || highRiskFunctions > 1) {
            return 'high';
        } else if (highCount > 0 || issues.length > 5) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    private static generateSummary(issues: SecurityIssue[], functionVulns: FunctionVulnerability[]) {
        return {
            totalVulnerabilities: issues.filter(i => i.type === 'vulnerability').length,
            criticalCount: issues.filter(i => i.riskLevel === 'critical').length,
            highCount: issues.filter(i => i.riskLevel === 'high').length,
            mediumCount: issues.filter(i => i.riskLevel === 'medium').length,
            lowCount: issues.filter(i => i.riskLevel === 'low').length,
            functionsAnalyzed: functionVulns.length
        };
    }

    private static mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity?.toLowerCase()) {
            case 'error': return vscode.DiagnosticSeverity.Error;
            case 'warning': return vscode.DiagnosticSeverity.Warning;
            case 'info': return vscode.DiagnosticSeverity.Information;
            default: return vscode.DiagnosticSeverity.Warning;
        }
    }

    private static mapSeverityString(severity: string): vscode.DiagnosticSeverity {
        switch (severity?.toLowerCase()) {
            case 'critical': return vscode.DiagnosticSeverity.Error;
            case 'high': return vscode.DiagnosticSeverity.Error;
            case 'medium': return vscode.DiagnosticSeverity.Warning;
            case 'low': return vscode.DiagnosticSeverity.Information;
            default: return vscode.DiagnosticSeverity.Warning;
        }
    }

    private static fixJsonEscaping(jsonString: string): string {
        try {
            return jsonString
                .replace(/\\(?!["\\/bfnrt])/g, '\\\\')
                .replace(/,(\s*[}\]])/g, '$1')
                .replace(/[\x00-\x1F\x7F]/g, (match) => {
                    const controlChars: Record<string, string> = {
                        '\b': '\\b',
                        '\f': '\\f',
                        '\n': '\\n',
                        '\r': '\\r',
                        '\t': '\\t'
                    };
                    return controlChars[match] || '';
                });
        } catch (error) {
            console.warn('Error fixing JSON escaping:', error);
            return jsonString;
        }
    }

    private static deduplicateIssues(issues: SecurityIssue[]): SecurityIssue[] {
        const seen = new Set<string>();
        const deduplicated: SecurityIssue[] = [];

        for (const issue of issues) {
            const key = `${issue.range.start.line}-${issue.range.start.character}-${issue.message}-${issue.type}`;
            
            if (!seen.has(key)) {
                seen.add(key);
                deduplicated.push(issue);
            }
        }

        return deduplicated.sort((a, b) => a.range.start.line - b.range.start.line);
    }

    private static delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}