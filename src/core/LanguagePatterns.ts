import * as vscode from 'vscode';

export interface VulnerabilityPattern {
    id: string;
    name: string;
    description: string;
    pattern: RegExp;
    severity: vscode.DiagnosticSeverity;
    confidence: number;
    cweId?: string;
    suggestion: string;
    languages: string[];
    category: 'xss' | 'sql-injection' | 'command-injection' | 'path-traversal' | 'crypto' | 'auth' | 'other';
}

export interface BestPracticePattern {
    id: string;
    name: string;
    description: string;
    pattern: RegExp;
    severity: vscode.DiagnosticSeverity;
    suggestion: string;
    languages: string[];
    category: 'debugging' | 'error-handling' | 'performance' | 'maintainability' | 'other';
}

export class LanguagePatterns {
    private static readonly VULNERABILITY_PATTERNS: VulnerabilityPattern[] = [
        // JavaScript/TypeScript XSS
        {
            id: 'js-dom-xss',
            name: 'DOM XSS Vulnerability',
            description: 'Direct assignment to innerHTML or outerHTML without sanitization',
            pattern: /\.(?:innerHTML|outerHTML)\s*=\s*(?!['"`])[^;\n]+/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-79',
            suggestion: 'Use textContent instead of innerHTML, or sanitize input with DOMPurify',
            languages: ['javascript', 'typescript'],
            category: 'xss'
        },
        {
            id: 'js-eval-xss',
            name: 'Code Injection via eval()',
            description: 'Use of eval() function which can execute arbitrary code',
            pattern: /\beval\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-95',
            suggestion: 'Avoid eval(). Use JSON.parse() for JSON data or Function constructor if absolutely necessary',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        {
            id: 'js-document-write-xss',
            name: 'XSS via document.write()',
            description: 'Use of document.write() with unsanitized content',
            pattern: /document\.write\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-79',
            suggestion: 'Use modern DOM methods like createElement() and appendChild()',
            languages: ['javascript', 'typescript'],
            category: 'xss'
        },

        // SQL Injection patterns
        {
            id: 'js-sql-injection',
            name: 'SQL Injection Risk',
            description: 'SQL query construction using string concatenation',
            pattern: /(?:query|execute|select|insert|update|delete)\s*\(\s*['"`].*?\$\{|(?:query|execute|select|insert|update|delete)\s*\(\s*['"`].*?\+/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-89',
            suggestion: 'Use parameterized queries or prepared statements instead of string concatenation',
            languages: ['javascript', 'typescript', 'php', 'python', 'java', 'csharp'],
            category: 'sql-injection'
        },
        {
            id: 'python-sql-injection',
            name: 'Python SQL Injection Risk',
            description: 'SQL query with % formatting or f-strings',
            pattern: /(?:cursor\.execute|execute|executemany)\s*\(\s*f?['"`].*?(?:%s|%d|\{.*?\})/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-89',
            suggestion: 'Use parameterized queries with ? placeholders or named parameters',
            languages: ['python'],
            category: 'sql-injection'
        },

        // Weak Cryptography
        {
            id: 'weak-hash-md5',
            name: 'Weak Cryptographic Hash (MD5)',
            description: 'MD5 is cryptographically broken and should not be used',
            pattern: /\b(?:md5|MD5|createHash\s*\(\s*['"`]md5['"`]\))/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-327',
            suggestion: 'Use SHA-256 or stronger hashing algorithms like bcrypt for passwords',
            languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp', 'go', 'rust'],
            category: 'crypto'
        },
        {
            id: 'weak-hash-sha1',
            name: 'Weak Cryptographic Hash (SHA1)',
            description: 'SHA1 is deprecated and vulnerable to collision attacks',
            pattern: /\b(?:sha1|SHA1|createHash\s*\(\s*['"`]sha1['"`]\))/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 90,
            cweId: 'CWE-327',
            suggestion: 'Use SHA-256 or stronger hashing algorithms',
            languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp', 'go', 'rust'],
            category: 'crypto'
        },
        {
            id: 'insecure-random',
            name: 'Cryptographically Insecure Random',
            description: 'Math.random() is not cryptographically secure',
            pattern: /Math\.random\s*\(\s*\).*(?:token|password|key|secret|salt|nonce)/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 85,
            cweId: 'CWE-338',
            suggestion: 'Use crypto.getRandomValues() or crypto.randomBytes() for security-sensitive random values',
            languages: ['javascript', 'typescript'],
            category: 'crypto'
        },

        // Command Injection
        {
            id: 'js-command-injection',
            name: 'Command Injection Risk',
            description: 'Executing system commands with user input',
            pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"`].*?\$\{|(?:exec|execSync|spawn|spawnSync)\s*\(\s*.*?\+/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-78',
            suggestion: 'Validate and sanitize input, use parameterized commands or avoid shell execution',
            languages: ['javascript', 'typescript'],
            category: 'command-injection'
        },
        {
            id: 'python-command-injection',
            name: 'Python Command Injection Risk',
            description: 'Executing system commands with user input',
            pattern: /(?:os\.system|subprocess\.call|subprocess\.run|os\.popen)\s*\(\s*f?['"`].*?\{|(?:os\.system|subprocess\.call|subprocess\.run|os\.popen)\s*\(\s*.*?\+/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-78',
            suggestion: 'Use subprocess with shell=False and list arguments, validate input',
            languages: ['python'],
            category: 'command-injection'
        },

        // Path Traversal
        {
            id: 'path-traversal',
            name: 'Path Traversal Vulnerability',
            description: 'File path contains directory traversal sequences',
            pattern: /['"`][^'"`]*\.\.\/|['"`][^'"`]*\\\.\.\\|path\.join\s*\([^)]*\.\.\/|path\.join\s*\([^)]*\\\.\.\\/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 85,
            cweId: 'CWE-22',
            suggestion: 'Validate and sanitize file paths, use path.resolve() and check if result is within allowed directory',
            languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp'],
            category: 'path-traversal'
        },

        // Hardcoded Secrets (Enhanced)
        {
            id: 'hardcoded-password',
            name: 'Hardcoded Password',
            description: 'Password appears to be hardcoded in source code',
            pattern: /(?:password|pwd|pass)\s*[:=]\s*['"`][^'"`\s]{6,}['"`]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 80,
            cweId: 'CWE-798',
            suggestion: 'Store passwords in environment variables or secure configuration files',
            languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp', 'go', 'rust'],
            category: 'auth'
        },
        {
            id: 'hardcoded-api-key',
            name: 'Hardcoded API Key',
            description: 'API key appears to be hardcoded in source code',
            pattern: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"`][a-zA-Z0-9._-]{16,}['"`]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-798',
            suggestion: 'Store API keys in environment variables or secure configuration',
            languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp', 'go', 'rust'],
            category: 'auth'
        },

        // Language-specific patterns
        {
            id: 'php-include-injection',
            name: 'PHP File Inclusion Vulnerability',
            description: 'Dynamic file inclusion without validation',
            pattern: /(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-98',
            suggestion: 'Validate and whitelist included files, avoid user input in include statements',
            languages: ['php'],
            category: 'other'
        },
        {
            id: 'java-deserialization',
            name: 'Java Deserialization Risk',
            description: 'Unsafe deserialization of objects',
            pattern: /ObjectInputStream\.readObject|readUnshared|XMLDecoder\.readObject/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-502',
            suggestion: 'Validate and whitelist deserializable classes, consider using safer serialization formats like JSON',
            languages: ['java'],
            category: 'other'
        },
        {
            id: 'csharp-xxe',
            name: 'C# XML External Entity (XXE)',
            description: 'XML processing without XXE protection',
            pattern: /new\s+XmlDocument\(\)|XmlDocument\.Load|XmlReader\.Create.*DtdProcessing\.Parse/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 75,
            cweId: 'CWE-611',
            suggestion: 'Disable DTD processing or use XmlReaderSettings with DtdProcessing.Prohibit',
            languages: ['csharp'],
            category: 'other'
        }
    ];

    private static readonly BEST_PRACTICE_PATTERNS: BestPracticePattern[] = [
        {
            id: 'console-log',
            name: 'Console.log in Production',
            description: 'Console.log statements should be removed before production',
            pattern: /console\.(?:log|debug|info|warn|error)\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Remove console.log statements or replace with proper logging framework',
            languages: ['javascript', 'typescript'],
            category: 'debugging'
        },
        {
            id: 'debugger-statement',
            name: 'Debugger Statement',
            description: 'Debugger statements should be removed before production',
            pattern: /\bdebugger\b/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Remove debugger statements before deploying to production',
            languages: ['javascript', 'typescript'],
            category: 'debugging'
        },
        {
            id: 'empty-catch',
            name: 'Empty Catch Block',
            description: 'Empty catch blocks suppress errors and make debugging difficult',
            pattern: /catch\s*\([^)]*\)\s*\{\s*\}/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Add error handling or logging in catch blocks',
            languages: ['javascript', 'typescript', 'java', 'csharp'],
            category: 'error-handling'
        },
        {
            id: 'magic-numbers',
            name: 'Magic Numbers',
            description: 'Consider using named constants instead of magic numbers',
            pattern: /(?<![\w.])\d{3,}(?![\w.])/g,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Replace magic numbers with named constants for better readability',
            languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'go', 'rust'],
            category: 'maintainability'
        },
        {
            id: 'todo-comments',
            name: 'TODO Comments',
            description: 'TODO comments indicate incomplete work',
            pattern: /\/\/\s*(?:TODO|FIXME|HACK|XXX|BUG)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Address TODO comments before production deployment',
            languages: ['javascript', 'typescript', 'java', 'csharp', 'go', 'rust', 'cpp', 'c'],
            category: 'maintainability'
        },
        {
            id: 'python-print',
            name: 'Print Statement in Production',
            description: 'Print statements should be removed or replaced with logging',
            pattern: /\bprint\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Replace print statements with proper logging (logging.info, etc.)',
            languages: ['python'],
            category: 'debugging'
        },
        {
            id: 'var-declaration',
            name: 'Use of var instead of let/const',
            description: 'var has function scope which can cause issues, use let/const',
            pattern: /\bvar\s+/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Use let for mutable variables or const for constants instead of var',
            languages: ['javascript', 'typescript'],
            category: 'maintainability'
        }
    ];

    public static getVulnerabilityPatterns(language: string): VulnerabilityPattern[] {
        return this.VULNERABILITY_PATTERNS.filter(p => 
            p.languages.includes(language) || p.languages.includes('*')
        );
    }

    public static getBestPracticePatterns(language: string): BestPracticePattern[] {
        return this.BEST_PRACTICE_PATTERNS.filter(p => 
            p.languages.includes(language) || p.languages.includes('*')
        );
    }

    public static getAllPatterns(): { vulnerabilities: VulnerabilityPattern[]; bestPractices: BestPracticePattern[] } {
        return {
            vulnerabilities: [...this.VULNERABILITY_PATTERNS],
            bestPractices: [...this.BEST_PRACTICE_PATTERNS]
        };
    }

    public static getPatternById(id: string): VulnerabilityPattern | BestPracticePattern | undefined {
        return [...this.VULNERABILITY_PATTERNS, ...this.BEST_PRACTICE_PATTERNS]
            .find(p => p.id === id);
    }

    public static getSupportedLanguages(): string[] {
        const languages = new Set<string>();
        
        [...this.VULNERABILITY_PATTERNS, ...this.BEST_PRACTICE_PATTERNS]
            .forEach(p => p.languages.forEach(lang => languages.add(lang)));
        
        return Array.from(languages).sort();
    }
}