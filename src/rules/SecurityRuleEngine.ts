import * as vscode from 'vscode';
import { SecurityIssue } from '../SecurityIssue';
import { logger } from '../core/DebugLogger';

export interface SecurityRule {
    id: string;
    name: string;
    description: string;
    category: 'security' | 'performance' | 'maintainability' | 'reliability' | 'style';
    severity: 'critical' | 'high' | 'medium' | 'low';
    languages: string[];
    pattern: RegExp;
    cweId?: string;
    owaspCategory?: string;
    example: string;
    fixSuggestion: string;
    confidence: number;
    enabled: boolean;
}

export class SecurityRuleEngine {
    private static rules: Map<string, SecurityRule[]> = new Map();
    private static initialized = false;

    public static initialize(): void {
        if (this.initialized) return;

        this.loadJavaScriptRules();
        this.loadTypeScriptRules();
        this.loadPythonRules();
        this.loadJavaRules();
        this.loadCSharpRules();
        this.loadPHPRules();
        this.loadGoRules();
        this.loadRustRules();
        this.loadCppRules();

        this.initialized = true;
        logger.info('Security Rule Engine initialized', { 
            totalRules: Array.from(this.rules.values()).reduce((sum, rules) => sum + rules.length, 0),
            languages: Array.from(this.rules.keys())
        });
    }

    public static analyzeDocument(document: vscode.TextDocument): SecurityIssue[] {
        this.initialize();
        
        const language = document.languageId;
        const rules = this.rules.get(language) || [];
        const text = document.getText();
        const lines = text.split('\n');
        const issues: SecurityIssue[] = [];

        logger.debug(`Analyzing document with ${rules.length} rules`, { 
            language, 
            fileSize: text.length,
            lineCount: lines.length 
        });

        for (const rule of rules) {
            if (!rule.enabled) continue;

            try {
                const ruleIssues = this.applyRule(rule, lines, document);
                issues.push(...ruleIssues);
                
                if (ruleIssues.length > 0) {
                    logger.debug(`Rule ${rule.id} found ${ruleIssues.length} issues`);
                }
            } catch (error) {
                logger.error(`Error applying rule ${rule.id}`, error);
            }
        }

        logger.info(`Rule engine analysis completed`, {
            language,
            rulesApplied: rules.filter(r => r.enabled).length,
            issuesFound: issues.length
        });

        return issues;
    }

    private static applyRule(rule: SecurityRule, lines: string[], document: vscode.TextDocument): SecurityIssue[] {
        const issues: SecurityIssue[] = [];

        lines.forEach((line, lineIndex) => {
            const matches = line.matchAll(rule.pattern);
            
            for (const match of matches) {
                const startChar = match.index || 0;
                const endChar = startChar + match[0].length;
                
                const issue: SecurityIssue = {
                    type: rule.category === 'security' ? 'vulnerability' : 'warning',
                    severity: this.mapSeverity(rule.severity),
                    message: rule.name,
                    description: rule.description,
                    range: new vscode.Range(lineIndex, startChar, lineIndex, endChar),
                    source: 'Security Rule Engine',
                    suggestion: rule.fixSuggestion,
                    confidence: rule.confidence,
                    category: rule.category,
                    riskLevel: rule.severity,
                    cweId: rule.cweId,
                    owaspCategory: rule.owaspCategory,
                    vulnerabilityType: rule.name,
                    affectedLines: [lineIndex],
                    contextCode: line.trim()
                };

                issues.push(issue);
            }
        });

        return issues;
    }

    private static mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'critical': return vscode.DiagnosticSeverity.Error;
            case 'high': return vscode.DiagnosticSeverity.Error;
            case 'medium': return vscode.DiagnosticSeverity.Warning;
            case 'low': return vscode.DiagnosticSeverity.Information;
            default: return vscode.DiagnosticSeverity.Warning;
        }
    }

    public static getRulesForLanguage(language: string): SecurityRule[] {
        this.initialize();
        return this.rules.get(language) || [];
    }

    public static getAllRules(): SecurityRule[] {
        this.initialize();
        const allRules: SecurityRule[] = [];
        for (const rules of this.rules.values()) {
            allRules.push(...rules);
        }
        return allRules;
    }

    public static toggleRule(ruleId: string, enabled: boolean): void {
        for (const rules of this.rules.values()) {
            const rule = rules.find(r => r.id === ruleId);
            if (rule) {
                rule.enabled = enabled;
                logger.info(`Rule ${ruleId} ${enabled ? 'enabled' : 'disabled'}`);
                break;
            }
        }
    }

    private static addRule(language: string, rule: SecurityRule): void {
        if (!this.rules.has(language)) {
            this.rules.set(language, []);
        }
        this.rules.get(language)!.push(rule);
    }

    private static loadJavaScriptRules(): void {
        const rules: SecurityRule[] = [
            {
                id: 'js-eval-usage',
                name: 'Dangerous eval() usage',
                description: 'Use of eval() can lead to code injection vulnerabilities',
                category: 'security',
                severity: 'critical',
                languages: ['javascript'],
                pattern: /\beval\s*\(/gi,
                cweId: 'CWE-95',
                owaspCategory: 'A03:2021 - Injection',
                example: 'eval(userInput); // Dangerous!',
                fixSuggestion: 'Avoid using eval(). Use JSON.parse() for data or safer alternatives.',
                confidence: 95,
                enabled: true
            },
            {
                id: 'js-innerhtml-xss',
                name: 'Potential XSS via innerHTML',
                description: 'Direct assignment to innerHTML with user data can lead to XSS',
                category: 'security',
                severity: 'high',
                languages: ['javascript'],
                pattern: /\.innerHTML\s*=\s*[^;]*\+|\.innerHTML\s*=\s*.*\$\{/gi,
                cweId: 'CWE-79',
                owaspCategory: 'A03:2021 - Injection',
                example: 'element.innerHTML = userInput;',
                fixSuggestion: 'Use textContent or sanitize HTML input with a library like DOMPurify.',
                confidence: 85,
                enabled: true
            },
            {
                id: 'js-document-write',
                name: 'Dangerous document.write usage',
                description: 'document.write can be exploited for XSS attacks',
                category: 'security',
                severity: 'high',
                languages: ['javascript'],
                pattern: /document\.write\s*\(/gi,
                cweId: 'CWE-79',
                owaspCategory: 'A03:2021 - Injection',
                example: 'document.write(userInput);',
                fixSuggestion: 'Use DOM manipulation methods like createElement and appendChild.',
                confidence: 90,
                enabled: true
            },
            {
                id: 'js-console-log',
                name: 'Console.log in production',
                description: 'Console statements should be removed from production code',
                category: 'style',
                severity: 'low',
                languages: ['javascript'],
                pattern: /console\.(log|info|warn|error|debug)\s*\(/gi,
                example: 'console.log("Debug info");',
                fixSuggestion: 'Remove console statements or use a proper logging library.',
                confidence: 80,
                enabled: true
            },
            {
                id: 'js-sql-injection',
                name: 'Potential SQL Injection',
                description: 'String concatenation in SQL queries can lead to SQL injection',
                category: 'security',
                severity: 'critical',
                languages: ['javascript'],
                pattern: /(SELECT|INSERT|UPDATE|DELETE).*\+.*\+.*(WHERE|VALUES)/gi,
                cweId: 'CWE-89',
                owaspCategory: 'A03:2021 - Injection',
                example: 'query = "SELECT * FROM users WHERE id = " + userId;',
                fixSuggestion: 'Use parameterized queries or prepared statements.',
                confidence: 85,
                enabled: true
            },
            {
                id: 'js-hardcoded-secrets',
                name: 'Hardcoded secrets',
                description: 'Hardcoded passwords or API keys detected',
                category: 'security',
                severity: 'critical',
                languages: ['javascript'],
                pattern: /(password|pwd|secret|token|key|api_key)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
                cweId: 'CWE-798',
                owaspCategory: 'A07:2021 - Identification and Authentication Failures',
                example: 'const apiKey = "sk-1234567890abcdef";',
                fixSuggestion: 'Use environment variables or secure configuration management.',
                confidence: 90,
                enabled: true
            },
            {
                id: 'js-prototype-pollution',
                name: 'Prototype pollution vulnerability',
                description: 'Direct access to __proto__ or constructor.prototype can lead to prototype pollution',
                category: 'security',
                severity: 'high',
                languages: ['javascript'],
                pattern: /(__proto__|constructor\.prototype)\s*\[|\.(__proto__|constructor\.prototype)/gi,
                cweId: 'CWE-1321',
                owaspCategory: 'A03:2021 - Injection',
                example: 'obj.__proto__.polluted = "value";',
                fixSuggestion: 'Use Map instead of objects for dynamic properties or validate keys.',
                confidence: 85,
                enabled: true
            },
            {
                id: 'js-unsafe-regex',
                name: 'ReDoS vulnerable regex',
                description: 'Regular expression may be vulnerable to ReDoS attacks',
                category: 'security',
                severity: 'medium',
                languages: ['javascript'],
                pattern: /new\s+RegExp\s*\(.*[\+\*]\s*[\+\*]|\/.*[\+\*]\s*[\+\*].*\//gi,
                cweId: 'CWE-1333',
                owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
                example: '/^(a+)+$/.test(userInput)',
                fixSuggestion: 'Avoid nested quantifiers and use more specific patterns.',
                confidence: 70,
                enabled: true
            },
            {
                id: 'js-weak-random',
                name: 'Weak random number generation',
                description: 'Math.random() is not cryptographically secure',
                category: 'security',
                severity: 'medium',
                languages: ['javascript'],
                pattern: /Math\.random\s*\(\)/gi,
                cweId: 'CWE-338',
                owaspCategory: 'A02:2021 - Cryptographic Failures',
                example: 'const token = Math.random().toString(36);',
                fixSuggestion: 'Use crypto.getRandomValues() or crypto.randomUUID() for security-sensitive purposes.',
                confidence: 80,
                enabled: true
            },
            {
                id: 'js-unsafe-json-parse',
                name: 'Unsafe JSON parsing',
                description: 'JSON.parse without error handling can cause application crashes',
                category: 'reliability',
                severity: 'medium',
                languages: ['javascript'],
                pattern: /JSON\.parse\s*\([^)]*\)\s*(?![;\s]*catch)/gi,
                example: 'const data = JSON.parse(userInput);',
                fixSuggestion: 'Wrap JSON.parse in try-catch block and validate input.',
                confidence: 75,
                enabled: true
            }
        ];

        rules.forEach(rule => this.addRule('javascript', rule));
    }

    private static loadTypeScriptRules(): void {
        // Include JavaScript rules for TypeScript
        this.loadJavaScriptRules();
        const jsRules = this.rules.get('javascript') || [];
        jsRules.forEach(rule => {
            const tsRule = { ...rule, languages: [...rule.languages, 'typescript'] };
            this.addRule('typescript', tsRule);
        });

        // TypeScript-specific rules
        const tsSpecificRules: SecurityRule[] = [
            {
                id: 'ts-any-usage',
                name: 'Dangerous any type usage',
                description: 'Using any type defeats TypeScript\'s type safety',
                category: 'reliability',
                severity: 'medium',
                languages: ['typescript'],
                pattern: /:\s*any\b|as\s+any\b/gi,
                example: 'const data: any = response;',
                fixSuggestion: 'Use specific types or unknown instead of any.',
                confidence: 75,
                enabled: true
            },
            {
                id: 'ts-non-null-assertion',
                name: 'Risky non-null assertion',
                description: 'Non-null assertion operator can cause runtime errors',
                category: 'reliability',
                severity: 'medium',
                languages: ['typescript'],
                pattern: /!(?=\s*[\.\[;,\)])/g,
                example: 'const value = obj.prop!.value;',
                fixSuggestion: 'Use optional chaining or proper null checks.',
                confidence: 70,
                enabled: true
            }
        ];

        tsSpecificRules.forEach(rule => this.addRule('typescript', rule));
    }

    private static loadPythonRules(): void {
        const rules: SecurityRule[] = [
            {
                id: 'py-exec-usage',
                name: 'Dangerous exec() usage',
                description: 'Use of exec() can lead to code injection vulnerabilities',
                category: 'security',
                severity: 'critical',
                languages: ['python'],
                pattern: /\bexec\s*\(/gi,
                cweId: 'CWE-95',
                owaspCategory: 'A03:2021 - Injection',
                example: 'exec(user_input)',
                fixSuggestion: 'Avoid using exec(). Consider safer alternatives like ast.literal_eval().',
                confidence: 95,
                enabled: true
            },
            {
                id: 'py-eval-usage',
                name: 'Dangerous eval() usage',
                description: 'Use of eval() can lead to code injection vulnerabilities',
                category: 'security',
                severity: 'critical',
                languages: ['python'],
                pattern: /\beval\s*\(/gi,
                cweId: 'CWE-95',
                owaspCategory: 'A03:2021 - Injection',
                example: 'eval(user_input)',
                fixSuggestion: 'Avoid using eval(). Use ast.literal_eval() for safe evaluation.',
                confidence: 95,
                enabled: true
            },
            {
                id: 'py-sql-injection',
                name: 'Potential SQL Injection',
                description: 'String formatting in SQL queries can lead to SQL injection',
                category: 'security',
                severity: 'critical',
                languages: ['python'],
                pattern: /(SELECT|INSERT|UPDATE|DELETE).*%.*%(.*WHERE|.*VALUES)/gi,
                cweId: 'CWE-89',
                owaspCategory: 'A03:2021 - Injection',
                example: 'query = "SELECT * FROM users WHERE id = %s" % user_id',
                fixSuggestion: 'Use parameterized queries with cursor.execute(query, params).',
                confidence: 85,
                enabled: true
            },
            {
                id: 'py-hardcoded-secrets',
                name: 'Hardcoded secrets',
                description: 'Hardcoded passwords or API keys detected',
                category: 'security',
                severity: 'critical',
                languages: ['python'],
                pattern: /(password|pwd|secret|token|key|api_key)\s*=\s*['"][^'"]{8,}['"]/gi,
                cweId: 'CWE-798',
                owaspCategory: 'A07:2021 - Identification and Authentication Failures',
                example: 'API_KEY = "sk-1234567890abcdef"',
                fixSuggestion: 'Use environment variables or secure configuration management.',
                confidence: 90,
                enabled: true
            },
            {
                id: 'py-subprocess-shell',
                name: 'Dangerous subprocess with shell=True',
                description: 'Using shell=True can lead to command injection',
                category: 'security',
                severity: 'high',
                languages: ['python'],
                pattern: /subprocess\.(call|run|Popen).*shell\s*=\s*True/gi,
                cweId: 'CWE-78',
                owaspCategory: 'A03:2021 - Injection',
                example: 'subprocess.call(cmd, shell=True)',
                fixSuggestion: 'Use shell=False and pass commands as lists.',
                confidence: 90,
                enabled: true
            },
            {
                id: 'py-pickle-load',
                name: 'Unsafe pickle deserialization',
                description: 'pickle.load() can execute arbitrary code from untrusted sources',
                category: 'security',
                severity: 'critical',
                languages: ['python'],
                pattern: /pickle\.loads?\s*\(/gi,
                cweId: 'CWE-502',
                owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
                example: 'data = pickle.load(untrusted_file)',
                fixSuggestion: 'Use json.load() or implement safe deserialization with restricted classes.',
                confidence: 95,
                enabled: true
            },
            {
                id: 'py-yaml-unsafe-load',
                name: 'Unsafe YAML loading',
                description: 'yaml.load() without safe_load can execute arbitrary Python code',
                category: 'security',
                severity: 'critical',
                languages: ['python'],
                pattern: /yaml\.load\s*\([^,)]*\)\s*(?!.*Loader\s*=)/gi,
                cweId: 'CWE-502',
                owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
                example: 'config = yaml.load(file)',
                fixSuggestion: 'Use yaml.safe_load() instead of yaml.load().',
                confidence: 95,
                enabled: true
            },
            {
                id: 'py-weak-hash',
                name: 'Weak cryptographic hash',
                description: 'MD5 and SHA1 are cryptographically weak hash functions',
                category: 'security',
                severity: 'medium',
                languages: ['python'],
                pattern: /hashlib\.(md5|sha1)\s*\(/gi,
                cweId: 'CWE-327',
                owaspCategory: 'A02:2021 - Cryptographic Failures',
                example: 'hash = hashlib.md5(data).hexdigest()',
                fixSuggestion: 'Use SHA-256 or stronger: hashlib.sha256(), hashlib.sha3_256().',
                confidence: 90,
                enabled: true
            },
            {
                id: 'py-assert-statement',
                name: 'Assert statement in production',
                description: 'Assert statements are removed when Python is optimized (-O flag)',
                category: 'reliability',
                severity: 'medium',
                languages: ['python'],
                pattern: /^\s*assert\s+/gm,
                example: 'assert user.is_admin, "Access denied"',
                fixSuggestion: 'Use explicit if statements and raise exceptions for security checks.',
                confidence: 80,
                enabled: true
            },
            {
                id: 'py-random-crypto',
                name: 'Weak random for cryptography',
                description: 'random module is not cryptographically secure',
                category: 'security',
                severity: 'medium',
                languages: ['python'],
                pattern: /import\s+random|from\s+random\s+import|random\.(choice|randint|random)\s*\(/gi,
                cweId: 'CWE-338',
                owaspCategory: 'A02:2021 - Cryptographic Failures',
                example: 'token = random.choice(string.ascii_letters)',
                fixSuggestion: 'Use secrets module: secrets.choice(), secrets.randbelow().',
                confidence: 75,
                enabled: true
            }
        ];

        rules.forEach(rule => this.addRule('python', rule));
    }

    private static loadJavaRules(): void {
        const rules: SecurityRule[] = [
            {
                id: 'java-sql-injection',
                name: 'Potential SQL Injection',
                description: 'String concatenation in SQL queries can lead to SQL injection',
                category: 'security',
                severity: 'critical',
                languages: ['java'],
                pattern: /(SELECT|INSERT|UPDATE|DELETE).*\+.*\+.*(WHERE|VALUES)/gi,
                cweId: 'CWE-89',
                owaspCategory: 'A03:2021 - Injection',
                example: 'String query = "SELECT * FROM users WHERE id = " + userId;',
                fixSuggestion: 'Use PreparedStatement with parameterized queries.',
                confidence: 85,
                enabled: true
            },
            {
                id: 'java-deserialization',
                name: 'Unsafe deserialization',
                description: 'Unsafe deserialization can lead to remote code execution',
                category: 'security',
                severity: 'critical',
                languages: ['java'],
                pattern: /ObjectInputStream.*readObject\s*\(/gi,
                cweId: 'CWE-502',
                owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
                example: 'Object obj = objectInputStream.readObject();',
                fixSuggestion: 'Validate and sanitize serialized data or use safer alternatives.',
                confidence: 85,
                enabled: true
            },
            {
                id: 'java-hardcoded-secrets',
                name: 'Hardcoded secrets',
                description: 'Hardcoded passwords or API keys detected',
                category: 'security',
                severity: 'critical',
                languages: ['java'],
                pattern: /(password|pwd|secret|token|key|apiKey)\s*=\s*"[^"]{8,}"/gi,
                cweId: 'CWE-798',
                owaspCategory: 'A07:2021 - Identification and Authentication Failures',
                example: 'String apiKey = "sk-1234567890abcdef";',
                fixSuggestion: 'Use configuration files or environment variables.',
                confidence: 90,
                enabled: true
            }
        ];

        rules.forEach(rule => this.addRule('java', rule));
    }

    private static loadCSharpRules(): void {
        const rules: SecurityRule[] = [
            {
                id: 'cs-sql-injection',
                name: 'Potential SQL Injection',
                description: 'String concatenation in SQL queries can lead to SQL injection',
                category: 'security',
                severity: 'critical',
                languages: ['csharp'],
                pattern: /(SELECT|INSERT|UPDATE|DELETE).*\+.*\+.*(WHERE|VALUES)/gi,
                cweId: 'CWE-89',
                owaspCategory: 'A03:2021 - Injection',
                example: 'string query = "SELECT * FROM users WHERE id = " + userId;',
                fixSuggestion: 'Use parameterized queries with SqlCommand.Parameters.',
                confidence: 85,
                enabled: true
            },
            {
                id: 'cs-hardcoded-secrets',
                name: 'Hardcoded secrets',
                description: 'Hardcoded passwords or API keys detected',
                category: 'security',
                severity: 'critical',
                languages: ['csharp'],
                pattern: /(password|pwd|secret|token|key|apiKey)\s*=\s*"[^"]{8,}"/gi,
                cweId: 'CWE-798',
                owaspCategory: 'A07:2021 - Identification and Authentication Failures',
                example: 'string apiKey = "sk-1234567890abcdef";',
                fixSuggestion: 'Use configuration files or Azure Key Vault.',
                confidence: 90,
                enabled: true
            }
        ];

        rules.forEach(rule => this.addRule('csharp', rule));
    }

    private static loadPHPRules(): void {
        const rules: SecurityRule[] = [
            {
                id: 'php-eval-usage',
                name: 'Dangerous eval() usage',
                description: 'Use of eval() can lead to code injection vulnerabilities',
                category: 'security',
                severity: 'critical',
                languages: ['php'],
                pattern: /\beval\s*\(/gi,
                cweId: 'CWE-95',
                owaspCategory: 'A03:2021 - Injection',
                example: 'eval($user_input);',
                fixSuggestion: 'Avoid using eval(). Consider safer alternatives.',
                confidence: 95,
                enabled: true
            },
            {
                id: 'php-sql-injection',
                name: 'Potential SQL Injection',
                description: 'String concatenation in SQL queries can lead to SQL injection',
                category: 'security',
                severity: 'critical',
                languages: ['php'],
                pattern: /(SELECT|INSERT|UPDATE|DELETE).*\..*\..*(WHERE|VALUES)/gi,
                cweId: 'CWE-89',
                owaspCategory: 'A03:2021 - Injection',
                example: '$query = "SELECT * FROM users WHERE id = " . $userId;',
                fixSuggestion: 'Use prepared statements with PDO or MySQLi.',
                confidence: 85,
                enabled: true
            }
        ];

        rules.forEach(rule => this.addRule('php', rule));
    }

    private static loadGoRules(): void {
        const rules: SecurityRule[] = [
            {
                id: 'go-sql-injection',
                name: 'Potential SQL Injection',
                description: 'String concatenation in SQL queries can lead to SQL injection',
                category: 'security',
                severity: 'critical',
                languages: ['go'],
                pattern: /(SELECT|INSERT|UPDATE|DELETE).*\+.*\+.*(WHERE|VALUES)/gi,
                cweId: 'CWE-89',
                owaspCategory: 'A03:2021 - Injection',
                example: 'query := "SELECT * FROM users WHERE id = " + userId',
                fixSuggestion: 'Use parameterized queries with database/sql package.',
                confidence: 85,
                enabled: true
            }
        ];

        rules.forEach(rule => this.addRule('go', rule));
    }

    private static loadRustRules(): void {
        const rules: SecurityRule[] = [
            {
                id: 'rust-unsafe-block',
                name: 'Unsafe code block',
                description: 'Unsafe blocks bypass Rust\'s safety guarantees',
                category: 'security',
                severity: 'high',
                languages: ['rust'],
                pattern: /unsafe\s*\{/gi,
                example: 'unsafe { *ptr = value; }',
                fixSuggestion: 'Ensure unsafe code is necessary and properly documented.',
                confidence: 80,
                enabled: true
            }
        ];

        rules.forEach(rule => this.addRule('rust', rule));
    }

    private static loadCppRules(): void {
        const rules: SecurityRule[] = [
            {
                id: 'cpp-buffer-overflow',
                name: 'Potential buffer overflow',
                description: 'strcpy and strcat can cause buffer overflows',
                category: 'security',
                severity: 'critical',
                languages: ['cpp', 'c'],
                pattern: /\b(strcpy|strcat|gets|sprintf)\s*\(/gi,
                cweId: 'CWE-120',
                owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
                example: 'strcpy(dest, src);',
                fixSuggestion: 'Use safer alternatives like strncpy, strncat, or std::string.',
                confidence: 90,
                enabled: true
            },
            {
                id: 'cpp-memory-leak',
                name: 'Potential memory leak',
                description: 'malloc/new without corresponding free/delete',
                category: 'reliability',
                severity: 'medium',
                languages: ['cpp', 'c'],
                pattern: /\b(malloc|calloc|new\s+\w+)\s*\(/gi,
                example: 'int* ptr = new int[100]; // Missing delete[]',
                fixSuggestion: 'Ensure every malloc/new has corresponding free/delete, or use smart pointers.',
                confidence: 60,
                enabled: true
            }
        ];

        rules.forEach(rule => {
            this.addRule('cpp', rule);
            this.addRule('c', rule);
        });
    }
}