import * as vscode from 'vscode';
import { SecurityIssue } from '../SecurityIssue';
import { AIProviderManager } from '../core/AIProviderManager';
import { AIFixSuggestion } from '../extension';

export interface CodeChunk {
    content: string;
    startLine: number;
    endLine: number;
    priority: number; // Higher = more likely to contain vulnerabilities
}

export class SmartAIAnalyzer {
    private static readonly MAX_CHUNK_SIZE = 3000;
    private static readonly OVERLAP_SIZE = 200;
    private static analysisCache = new Map<string, { result: SecurityIssue[]; timestamp: number }>();
    private static readonly CACHE_DURATION = 10 * 60 * 1000; // 10 minutes

    public static async analyzeDocument(
        document: vscode.TextDocument,
        offlineIssues: SecurityIssue[] = [],
        progressCallback?: (message: string) => void
    ): Promise<SecurityIssue[]> {
        if (!AIProviderManager.hasValidConfig()) {
            throw new Error('No valid AI provider configuration');
        }

        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        const maxFileSize = config.get<number>('maxFileSize', 10000);
        const chunkSize = config.get<number>('chunkSize', 3000);
        
        const text = document.getText();
        const contentHash = this.generateContentHash(text);
        
        // Check cache first
        const cached = this.analysisCache.get(contentHash);
        if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
            return cached.result;
        }

        progressCallback?.('🧠 Preparing AI analysis...');

        let issues: SecurityIssue[] = [];

        if (text.length <= maxFileSize) {
            // Single analysis for small files
            issues = await this.analyzeSingleChunk(document, text, offlineIssues, progressCallback);
        } else {
            // Smart chunking for large files
            issues = await this.analyzeWithChunking(document, text, chunkSize, offlineIssues, progressCallback);
        }

        // Cache the results
        this.analysisCache.set(contentHash, {
            result: issues,
            timestamp: Date.now()
        });

        return issues;
    }

    private static async analyzeSingleChunk(
        document: vscode.TextDocument,
        content: string,
        offlineIssues: SecurityIssue[],
        progressCallback?: (message: string) => void
    ): Promise<SecurityIssue[]> {
        progressCallback?.('🤖 Running AI security analysis...');

        const prompt = this.buildAnalysisPrompt(content, document.languageId, offlineIssues);
        
        try {
            const response = await AIProviderManager.makeRequest([
                {
                    role: 'system',
                    content: 'You are a senior security engineer specializing in code vulnerability detection. Provide detailed, actionable security analysis.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ], 2000);

            return this.parseAIResponse(response, document);
        } catch (error) {
            console.error('AI analysis failed:', error);
            throw error;
        }
    }

    private static async analyzeWithChunking(
        document: vscode.TextDocument,
        content: string,
        chunkSize: number,
        offlineIssues: SecurityIssue[],
        progressCallback?: (message: string) => void
    ): Promise<SecurityIssue[]> {
        const chunks = this.createSmartChunks(content, chunkSize, document.languageId);
        const allIssues: SecurityIssue[] = [];

        for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];
            progressCallback?.(`🔍 Analyzing chunk ${i + 1}/${chunks.length}...`);

            // Filter offline issues relevant to this chunk
            const relevantOfflineIssues = offlineIssues.filter(issue =>
                issue.range.start.line >= chunk.startLine && issue.range.end.line <= chunk.endLine
            );

            try {
                const chunkIssues = await this.analyzeChunk(chunk, document, relevantOfflineIssues, progressCallback);
                allIssues.push(...chunkIssues);
                
                // Small delay to avoid rate limiting
                await this.delay(500);
            } catch (error) {
                console.warn(`Failed to analyze chunk ${i + 1}:`, error);
                // Continue with next chunk instead of failing completely
            }
        }

        return this.deduplicateIssues(allIssues);
    }

    private static createSmartChunks(content: string, maxSize: number, language: string): CodeChunk[] {
        const lines = content.split('\n');
        const chunks: CodeChunk[] = [];
        
        let currentChunk = '';
        let currentStartLine = 0;
        let currentLineCount = 0;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const potentialChunk = currentChunk + line + '\n';
            
            // Check if adding this line would exceed the chunk size
            if (potentialChunk.length > maxSize && currentChunk.length > 0) {
                // Create chunk with current content
                const priority = this.calculateChunkPriority(currentChunk, language);
                chunks.push({
                    content: currentChunk,
                    startLine: currentStartLine,
                    endLine: currentStartLine + currentLineCount - 1,
                    priority
                });
                
                // Start new chunk with overlap
                const overlapLines = this.getOverlapLines(lines, Math.max(0, i - 5), i);
                currentChunk = overlapLines + line + '\n';
                currentStartLine = Math.max(0, i - 5);
                currentLineCount = overlapLines.split('\n').length;
            } else {
                currentChunk = potentialChunk;
                if (currentLineCount === 0) {
                    currentStartLine = i;
                }
                currentLineCount++;
            }
        }

        // Add the last chunk if it has content
        if (currentChunk.trim().length > 0) {
            const priority = this.calculateChunkPriority(currentChunk, language);
            chunks.push({
                content: currentChunk,
                startLine: currentStartLine,
                endLine: currentStartLine + currentLineCount - 1,
                priority
            });
        }

        // Sort chunks by priority (analyze high-priority chunks first)
        return chunks.sort((a, b) => b.priority - a.priority);
    }

    private static getOverlapLines(lines: string[], startIndex: number, endIndex: number): string {
        return lines.slice(startIndex, endIndex).join('\n') + (endIndex > startIndex ? '\n' : '');
    }

    private static calculateChunkPriority(chunk: string, language: string): number {
        let priority = 0;
        const lowerChunk = chunk.toLowerCase();

        // High priority indicators
        const highPriorityKeywords = [
            'password', 'secret', 'api', 'key', 'token', 'auth', 'login',
            'sql', 'query', 'execute', 'select', 'insert', 'update', 'delete',
            'eval', 'exec', 'system', 'shell', 'command',
            'innerhtml', 'outerhtml', 'document.write', 'dangerouslysetinnerhtml',
            'crypto', 'hash', 'encrypt', 'decrypt', 'random',
            'file', 'path', 'directory', 'upload', 'download'
        ];

        for (const keyword of highPriorityKeywords) {
            if (lowerChunk.includes(keyword)) {
                priority += 10;
            }
        }

        // Language-specific high-priority patterns
        if (language === 'javascript' || language === 'typescript') {
            if (lowerChunk.includes('fetch') || lowerChunk.includes('xhr') || lowerChunk.includes('ajax')) {
                priority += 15;
            }
        } else if (language === 'python') {
            if (lowerChunk.includes('subprocess') || lowerChunk.includes('os.system')) {
                priority += 15;
            }
        }

        // Function/method definitions get medium priority
        const functionPatterns = [
            /function\s+\w+/gi,
            /def\s+\w+/gi,
            /class\s+\w+/gi,
            /public\s+\w+/gi,
            /private\s+\w+/gi
        ];

        for (const pattern of functionPatterns) {
            const matches = chunk.match(pattern);
            if (matches) {
                priority += matches.length * 5;
            }
        }

        return priority;
    }

    private static async analyzeChunk(
        chunk: CodeChunk,
        document: vscode.TextDocument,
        relevantOfflineIssues: SecurityIssue[],
        progressCallback?: (message: string) => void
    ): Promise<SecurityIssue[]> {
        const prompt = this.buildChunkAnalysisPrompt(chunk.content, document.languageId, relevantOfflineIssues, chunk.startLine);
        
        try {
            const response = await AIProviderManager.makeRequest([
                {
                    role: 'system',
                    content: 'You are a senior security engineer. Analyze this code chunk for security vulnerabilities. Focus on the most critical issues.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ], 1500);

            return this.parseAIResponse(response, document, chunk.startLine);
        } catch (error) {
            console.error('Chunk analysis failed:', error);
            throw error;
        }
    }

    private static buildAnalysisPrompt(content: string, language: string, offlineIssues: SecurityIssue[]): string {
        const config = AIProviderManager.getCurrentConfig();
        const providerInfo = config ? `${config.provider.name} (${config.model})` : 'AI';
        
        let prompt = `Analyze this ${language} code for security vulnerabilities and provide a JSON response with the following structure:

        {
          "issues": [
        {
          "type": "vulnerability|error|warning",
          "severity": "error|warning|info",
          "message": "Brief description",
          "description": "Detailed explanation",
          "suggestion": "How to fix this issue",
          "lineNumber": number,
          "columnStart": number,
          "columnEnd": number,
          "confidence": number (0-100),
          "cveReference": "CWE-XXX (optional)",
          "category": "xss|sql-injection|command-injection|crypto|auth|type-safety|best-practices|latest-vuln|other"
        }
          ],
          "summary": "Overall analysis summary",
          "analyzedBy": "${providerInfo}"
        }

${this.getSecurityFocusChecklist()}

        `;

        if (offlineIssues.length > 0) {
            prompt += `\nOffline analysis already found ${offlineIssues.length} issues. Please provide additional insights and validate these findings:\n`;
            offlineIssues.slice(0, 5).forEach(issue => {
                prompt += `- Line ${issue.range.start.line + 1}: ${issue.message}\n`;
            });
        }

        prompt += `\nCode to analyze:\n\`\`\`${language}\n${content}\n\`\`\``;
        
        // Also include instruction to provide the previous line above each issue (for UI context display)
        prompt += `\n\nFor each issue, ensure the description begins with the exact previous line from the file in the form: "Line (N-1): <code>" followed by the detailed description.`;

        return prompt;
    }

    private static buildChunkAnalysisPrompt(content: string, language: string, offlineIssues: SecurityIssue[], startLine: number): string {
        const config = AIProviderManager.getCurrentConfig();
        const providerInfo = config ? `${config.provider.name} (${config.model})` : 'AI';
        
        let prompt = `Analyze this ${language} code chunk (starts at line ${startLine + 1}) for security vulnerabilities. Provide JSON response:

{
  "issues": [
    {
      "type": "vulnerability|error|warning",
      "severity": "error|warning|info", 
      "message": "Brief description",
      "description": "Detailed explanation",
      "suggestion": "How to fix",
      "lineNumber": number (relative to original file),
      "columnStart": number,
      "columnEnd": number,
      "confidence": number (0-100),
      "cveReference": "CWE-XXX (optional)"
    }
  ],
  "analyzedBy": "${providerInfo}"
}

IMPORTANT: Line numbers should be relative to the original file (add ${startLine} to chunk-relative line numbers).

${this.getSecurityFocusChecklist()}
`;

        if (offlineIssues.length > 0) {
            prompt += `Offline analysis found issues in this chunk:\n`;
            offlineIssues.forEach(issue => {
                prompt += `- Line ${issue.range.start.line + 1}: ${issue.message}\n`;
            });
            prompt += `\nProvide additional analysis and validation.\n`;
        }

        prompt += `\nCode chunk:\n\`\`\`${language}\n${content}\n\`\`\``;
        
        // Require previous-line prefix for each issue in description
        prompt += `\n\nFor each issue, start description with the previous source line in the format: "Line <absoluteLine-1>: <code>" then provide your explanation.`;

        return prompt;
    }
    private static getSecurityFocusChecklist(): string {
        return `Focus on:
    1. SQL injection vulnerabilities
    2. XSS (Cross-Site Scripting)
    3. Command injection
    4. Insecure cryptography
    5. Authentication/authorization issues
    6. Path traversal
    7. Deserialization vulnerabilities
    8. Code injection (eval, Function, etc.)
    9. Hardcoded credentials and secrets
    10. Insufficient input validation and sanitization
    11. Insecure file operations and permissions
    12. Race conditions and concurrency issues
    13. Memory safety vulnerabilities
    14. Insecure random number generation
    15. Information disclosure via logs/errors
    16. Type confusion / unsafe casts
    17. Language-specific best practices violations
    18. Recent CVE patterns where applicable
    19. Prototype pollution (JS/TS)
    20. SSRF (Server-Side Request Forgery)
    21. XXE (XML External Entity) injection
    22. LDAP injection
    23. NoSQL injection
    24. Dependency confusion and supply chain risks
    25. Language-specific security best practices and coding standards`;
    }

    private static parseAIResponse(response: any, document: vscode.TextDocument, lineOffset: number = 0): SecurityIssue[] {
        try {
            const content = response.choices?.[0]?.message?.content || '';
            console.log('Raw AI response:', content);

            // Extract JSON from response
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            if (!jsonMatch) {
                throw new Error('No JSON found in AI response');
            }

            let jsonString = jsonMatch[0];
            jsonString = this.fixJsonEscaping(jsonString);

            const parsed = JSON.parse(jsonString);
            const issues: SecurityIssue[] = [];

            if (parsed.issues && Array.isArray(parsed.issues)) {
                for (const issue of parsed.issues) {
                    try {
                        const lineNumber = Math.max(0, (issue.lineNumber || 1) - 1 + lineOffset);
                        const line = lineNumber < document.lineCount ? document.lineAt(lineNumber) : null;
                        
                        if (!line) {
                            continue; // Skip invalid line numbers
                        }

                        const startChar = Math.max(0, issue.columnStart || 0);
                        const endChar = Math.min(line.text.length, issue.columnEnd || line.text.length);

                        const config = AIProviderManager.getCurrentConfig();
                        const providerName = config ? config.provider.name : 'AI';
                        const modelName = config ? config.model : 'Unknown';

                        const securityIssue: SecurityIssue = {
                            type: issue.type || 'vulnerability',
                            severity: this.mapSeverity(issue.severity),
                            message: issue.message || 'Security Issue Detected',
                            description: issue.description || 'AI detected a potential security vulnerability.',
                            range: new vscode.Range(lineNumber, startChar, lineNumber, endChar),
                            source: `AI Analysis (${providerName} ${modelName})`,
                            suggestion: issue.suggestion || 'Review this code for security issues.',
                            confidence: Math.min(100, Math.max(0, issue.confidence || 85)),
                            cveReference: issue.cveReference
                        };

                        issues.push(securityIssue);
                    } catch (issueError) {
                        console.warn('Error processing individual issue:', issueError);
                    }
                }
            }

            return issues;
        } catch (error) {
            console.error('Error parsing AI response:', error);
            throw new Error(`Failed to parse AI response: ${error}`);
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

    private static mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity?.toLowerCase()) {
            case 'error': return vscode.DiagnosticSeverity.Error;
            case 'warning': return vscode.DiagnosticSeverity.Warning;
            case 'info': return vscode.DiagnosticSeverity.Information;
            default: return vscode.DiagnosticSeverity.Warning;
        }
    }

    private static generateContentHash(content: string): string {
        let hash = 0;
        for (let i = 0; i < content.length; i++) {
            const char = content.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(36);
    }

    private static deduplicateIssues(issues: SecurityIssue[]): SecurityIssue[] {
        const seen = new Set<string>();
        const deduplicated: SecurityIssue[] = [];

        for (const issue of issues) {
            const key = `${issue.range.start.line}-${issue.range.start.character}-${issue.message}`;
            
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

    public static async generateFixSuggestion(issue: SecurityIssue, document: vscode.TextDocument): Promise<AIFixSuggestion | null> {
        if (!AIProviderManager.hasValidConfig()) {
            return null;
        }

        try {
            const config = AIProviderManager.getCurrentConfig()!;
            const context = this.getIssueContext(issue, document);
            
            const prompt = `Generate a secure code fix for this vulnerability:

Issue: ${issue.message}
Description: ${issue.description}
Language: ${document.languageId}

Current vulnerable code:
\`\`\`${document.languageId}
${context}
\`\`\`

Provide a JSON response with:
{
  "originalCode": "exact vulnerable code",
  "fixedCode": "secure replacement code",
  "explanation": "detailed explanation of the fix",
  "confidence": number (0-100),
  "riskLevel": "low|medium|high",
  "steps": ["step 1", "step 2", ...],
  "fixedBy": "${config.provider.name} (${config.model})"
}`;

            const response = await AIProviderManager.makeRequest([
                {
                    role: 'system',
                    content: 'You are a security expert. Provide secure, practical code fixes with detailed explanations.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ], 1000);

            return this.parseFixResponse(response);
        } catch (error) {
            console.error('Error generating fix suggestion:', error);
            return null;
        }
    }

    private static getIssueContext(issue: SecurityIssue, document: vscode.TextDocument, contextLines: number = 3): string {
        const startLine = Math.max(0, issue.range.start.line - contextLines);
        const endLine = Math.min(document.lineCount - 1, issue.range.end.line + contextLines);
        
        let context = '';
        for (let i = startLine; i <= endLine; i++) {
            const linePrefix = i === issue.range.start.line ? '>>> ' : '    ';
            context += `${linePrefix}${document.lineAt(i).text}\n`;
        }
        
        return context;
    }

    private static parseFixResponse(response: any): AIFixSuggestion | null {
        try {
            const content = response.choices?.[0]?.message?.content || '';
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            
            if (!jsonMatch) {
                return null;
            }

            const parsed = JSON.parse(this.fixJsonEscaping(jsonMatch[0]));
            
            return {
                originalCode: parsed.originalCode || '',
                fixedCode: parsed.fixedCode || '',
                explanation: parsed.explanation || 'AI-generated fix',
                confidence: Math.min(100, Math.max(0, parsed.confidence || 75)),
                riskLevel: parsed.riskLevel || 'medium',
                steps: parsed.steps || []
            };
        } catch (error) {
            console.error('Error parsing fix response:', error);
            return null;
        }
    }

    public static clearCache(): void {
        this.analysisCache.clear();
    }

    public static getCacheStats(): { size: number; oldestEntry: number | null } {
        const now = Date.now();
        let oldestTimestamp: number | null = null;

        for (const entry of this.analysisCache.values()) {
            if (oldestTimestamp === null || entry.timestamp < oldestTimestamp) {
                oldestTimestamp = entry.timestamp;
            }
        }

        return {
            size: this.analysisCache.size,
            oldestEntry: oldestTimestamp ? Math.floor((now - oldestTimestamp) / 1000) : null
        };
    }
}