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
    category: 'xss' | 'sql-injection' | 'command-injection' | 'path-traversal' | 'crypto' | 'auth' | 'supply-chain' | 'api-security' | 'container-security' | 'race-condition' | 'memory-safety' | 'ai-ml-security' | 'other';
}

export interface BestPracticePattern {
    id: string;
    name: string;
    description: string;
    pattern: RegExp;
    severity: vscode.DiagnosticSeverity;
    suggestion: string;
    languages: string[];
    category: 'debugging' | 'error-handling' | 'performance' | 'maintainability' | 'security' | 'supply-chain' | 'container' | 'ai-ml' | 'other';
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
        {
            id: 'jquery-html-xss',
            name: 'Potential XSS via jQuery .html()',
            description: 'Using jQuery .html() can inject unsanitized HTML into the DOM',
            pattern: /\$\([^)]*\)\.html\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-79',
            suggestion: 'Avoid using .html() with untrusted input. Prefer text() or sanitize input with DOMPurify',
            languages: ['javascript', 'typescript'],
            category: 'xss'
        },
        {
            id: 'react-dangerously-set-inner-html',
            name: 'React dangerouslySetInnerHTML',
            description: 'dangerouslySetInnerHTML renders raw HTML and can introduce XSS',
            pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*\}\s*\}/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-79',
            suggestion: 'Avoid dangerouslySetInnerHTML or sanitize content before usage (e.g., DOMPurify)',
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
        {
            id: 'mongodb-nosql-injection',
            name: 'NoSQL Injection Risk ($where/regex)',
            description: 'Untrusted input in MongoDB queries (e.g., $where or dynamic RegExp)',
            pattern: /\$where\s*:\s*(?:['"`][^'"`]*\+|.*\$\{)|new\s+RegExp\s*\([^)]*\+[^)]*\)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-943',
            suggestion: 'Avoid $where. Validate and sanitize inputs; use field queries and parameterization',
            languages: ['javascript', 'typescript'],
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
            pattern: /Math\.random\s*\(\s*\).*?(?:token|password|key|secret|salt|nonce)/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 85,
            cweId: 'CWE-338',
            suggestion: 'Use crypto.getRandomValues() or crypto.randomBytes() for security-sensitive random values',
            languages: ['javascript', 'typescript'],
            category: 'crypto'
        },
        {
            id: 'legacy-node-cipher',
            name: 'Legacy/Deprecated Node.js Cipher API',
            description: 'crypto.createCipher/createDecipher are deprecated and may encourage weak crypto usage',
            pattern: /crypto\.(?:createCipher|createDecipher)\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-327',
            suggestion: 'Use crypto.createCipheriv/createDecipheriv with modern algorithms (AES-256-GCM) and secure key/IV handling',
            languages: ['javascript', 'typescript'],
            category: 'crypto'
        },
        {
            id: 'weak-cipher-ecb',
            name: 'Insecure Block Cipher Mode (ECB)',
            description: 'ECB mode is deterministic and leaks patterns in plaintext',
            pattern: /createCipher(?:iv)?\s*\(\s*['"`](?:[^'"`]*ecb)[^'"`]*['"`]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-327',
            suggestion: 'Use an authenticated mode like AES-GCM or at minimum CBC with random IVs; prefer AES-256-GCM',
            languages: ['javascript', 'typescript'],
            category: 'crypto'
        },
        {
            id: 'pbkdf2-low-iterations',
            name: 'PBKDF2 with Low Iteration Count',
            description: 'PBKDF2 iteration count is below recommended thresholds',
            pattern: /crypto\.pbkdf2(?:Sync)?\s*\([^,]+,[^,]+,\s*(?:[1-9]\d{0,3})\s*,/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 90,
            cweId: 'CWE-916',
            suggestion: 'Increase iterations (>= 10,000; modern guidance often >= 100,000) or use Argon2/bcrypt/scrypt',
            languages: ['javascript', 'typescript'],
            category: 'crypto'
        },
        {
            id: 'bcrypt-low-rounds',
            name: 'bcrypt with Low Cost Factor',
            description: 'bcrypt cost factor (rounds) is below secure recommendations',
            pattern: /bcrypt\.hash(?:Sync)?\s*\([^,]+,\s*(?:[1-9])\s*\)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 88,
            cweId: 'CWE-916',
            suggestion: 'Use at least 10-12 rounds for bcrypt; consider 12+ in modern environments',
            languages: ['javascript', 'typescript'],
            category: 'crypto'
        },
        {
            id: 'sha-for-passwords',
            name: 'Raw SHA used for password hashing',
            description: 'General-purpose hashes like SHA-256 are not suitable for password hashing',
            pattern: /createHash\s*\(\s*['"`]sha(?:256|512)['"`]\s*\)\s*\.update\s*\([^)]*(?:password|pwd)[^)]*\)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 92,
            cweId: 'CWE-916',
            suggestion: 'Use a password hashing function like Argon2, bcrypt, scrypt, or PBKDF2 with high iteration count',
            languages: ['javascript', 'typescript'],
            category: 'crypto'
        },
        {
            id: 'node-ssrf',
            name: 'Potential SSRF in outbound request',
            description: 'HTTP client called with variable/unsanitized URL',
            pattern: /(?:axios\.(?:get|post|put|delete)\s*\(\s*(?!['"`])[^)\n]+|fetch\s*\(\s*(?!['"`])[^)\n]+|https?\.(?:get|request)\s*\(\s*(?!['"`])[^)\n]+)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 75,
            cweId: 'CWE-918',
            suggestion: 'Validate/allowlist URLs and hosts; prevent access to internal metadata endpoints (e.g., 169.254.169.254)',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        // New: Open redirect via Express using untrusted target
        {
            id: 'express-open-redirect',
            name: 'Open Redirect via unvalidated target',
            description: 'Redirect target derived from user input can cause open redirect',
            pattern: /res\.redirect\s*\(\s*(req\.(query|body|params)|[a-zA-Z_$][\w$]*\s*\?|\+\s*req\.)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-601',
            suggestion: 'Validate redirect targets against an allowlist or use fixed relative paths.',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        // New: Insecure deserialization in Node (serialize-javascript eval, JSON.parse on untrusted with reviver doing eval)
        {
            id: 'insecure-deserialization-js',
            name: 'Insecure Deserialization Pattern',
            description: 'Deserializing untrusted data in a dangerous way',
            pattern: /(eval\s*\(\s*JSON\.parse|require\(\s*['"`]serialize-javascript['"`]\s*\)|vm\.(runInNewContext|runInThisContext)\s*\()/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 80,
            cweId: 'CWE-502',
            suggestion: 'Avoid eval with parsed JSON; use safe parsers and strict schema validation (e.g., zod/ajv).',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        // New: Path injection in child_process with template/concat
        {
            id: 'child-process-injection',
            name: 'Command Injection in child_process',
            description: 'Dynamic shell command construction with user-controlled input',
            pattern: /child_process\.(?:exec|execSync)\s*\(\s*[`'"].*(\$\{|\+).*[)`'"\)]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-78',
            suggestion: 'Use execFile/spawn with fixed argv list; validate inputs; avoid shell.',
            languages: ['javascript', 'typescript'],
            category: 'command-injection'
        },
        // New: Unsanitized HTML in React dangerouslySetInnerHTML from props/state
        {
            id: 'react-dangerous-prop',
            name: 'dangerouslySetInnerHTML from untrusted source',
            description: 'Rendering HTML from props/state can introduce XSS',
            pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(this\.props|props|this\.state|state)/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 85,
            cweId: 'CWE-79',
            suggestion: 'Sanitize HTML with DOMPurify and validate sources; prefer text rendering.',
            languages: ['javascript', 'typescript'],
            category: 'xss'
        },
        {
            id: 'python-ssrf',
            name: 'Potential SSRF in requests call',
            description: 'requests.* called with variable/unsanitized URL',
            pattern: /requests\.(?:get|post|put|delete)\s*\(\s*(?!['"`])[^)\n]+/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 75,
            cweId: 'CWE-918',
            suggestion: 'Validate/allowlist URLs and hosts; block internal network access in SSRF-prone contexts',
            languages: ['python'],
            category: 'other'
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
            id: 'function-constructor-eval',
            name: 'Dynamic code execution via Function constructor',
            description: 'new Function(...) can evaluate arbitrary code and is unsafe with untrusted input',
            pattern: /new\s+Function\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-94',
            suggestion: 'Avoid dynamic code execution; use safer parsing/logic instead',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        {
            id: 'settimeout-string-eval',
            name: 'String argument to setTimeout/setInterval',
            description: 'Passing a string causes implicit eval and code execution risk',
            pattern: /set(?:Timeout|Interval)\s*\(\s*['"]/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-94',
            suggestion: 'Pass a function reference instead of a string: setTimeout(() => fn(), delay)',
            languages: ['javascript', 'typescript'],
            category: 'other'
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
        {
            id: 'python-shell-true',
            name: 'subprocess with shell=True',
            description: 'Using shell=True executes through a shell and increases injection risk',
            pattern: /subprocess\.(?:Popen|call|run)\s*\([^)]*shell\s*=\s*True/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 92,
            cweId: 'CWE-78',
            suggestion: 'Set shell=False and pass a list of arguments; never pass untrusted input to the shell',
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
        {
            id: 'open-redirect-node',
            name: 'Open Redirect',
            description: 'Redirection to a user-controlled URL',
            pattern: /res\.redirect\s*\(\s*(?!['"`])[^)\n]+\)|window\.location(?:\.href)?\s*=\s*(?!['"`])[^;\n]+/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-601',
            suggestion: 'Validate redirect targets against an allowlist of domains/paths',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        {
            id: 'jwt-none-algorithm',
            name: 'JWT using "none" algorithm',
            description: 'Using the "none" algorithm disables signature verification and allows token forgery',
            pattern: /jwt\.(?:sign|verify)\s*\([^)]*algorithm\s*:\s*['"`]none['"`]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-347',
            suggestion: 'Use strong algorithms (RS256/ES256) and verify with expected audience/issuer and algorithm allowlist',
            languages: ['javascript', 'typescript'],
            category: 'auth'
        },
        {
            id: 'localstorage-sensitive',
            name: 'Sensitive data in localStorage',
            description: 'Storing tokens or passwords in localStorage exposes them to XSS theft',
            pattern: /localStorage\.(?:setItem|getItem)\s*\(\s*['"`](?:token|auth|password|jwt|session)['"`]/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-922',
            suggestion: 'Avoid storing sensitive data in localStorage; prefer httpOnly, secure cookies with SameSite=Strict',
            languages: ['javascript', 'typescript'],
            category: 'auth'
        },
        {
            id: 'insecure-cookie-flags',
            name: 'Potential insecure cookie flags',
            description: 'Session/auth cookies should set httpOnly, secure, and SameSite=Strict',
            pattern: /res\.cookie\s*\(\s*['"`](?:token|session|jwt)['"`][^)]*\)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-614',
            suggestion: 'Set secure cookie flags: res.cookie(name, val, { httpOnly: true, secure: true, sameSite: "Strict" })',
            languages: ['javascript', 'typescript'],
            category: 'auth'
        },
        {
            id: 'dynamic-regexp',
            name: 'Dynamic RegExp from variable input',
            description: 'Creating regular expressions from untrusted input can enable ReDoS or injection-like issues',
            pattern: /new\s+RegExp\s*\(\s*(?!['"`])/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 75,
            cweId: 'CWE-400',
            suggestion: 'Avoid constructing regex from untrusted input or validate/escape input and use timeouts',
            languages: ['javascript', 'typescript'],
            category: 'other'
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
        {
            id: 'prototype-pollution',
            name: 'Prototype Pollution Assignment',
            description: 'Writing to __proto__ or constructor.prototype can lead to prototype pollution',
            pattern: /(__proto__|constructor\.prototype)\s*=/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-915',
            suggestion: 'Do not assign to object prototypes based on untrusted input; deep-clone and validate inputs',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        {
            id: 'jwt-decode-without-verify',
            name: 'JWT decode without verify',
            description: 'Using jwt.decode without verifying signature allows forged tokens',
            pattern: /jwt\.decode\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-347',
            suggestion: 'Use jwt.verify with the expected algorithm and audience/issuer checks',
            languages: ['javascript', 'typescript'],
            category: 'auth'
        },
        {
            id: 'python-yaml-unsafe-load',
            name: 'Unsafe YAML load',
            description: 'yaml.load without specifying SafeLoader can be unsafe',
            pattern: /yaml\.load\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-502',
            suggestion: 'Use yaml.safe_load or specify a safe loader',
            languages: ['python'],
            category: 'other'
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

        // 2025 Latest Security Vulnerabilities - Supply Chain Attacks
        {
            id: 'npm-dependency-confusion',
            name: 'Potential Dependency Confusion Attack',
            description: 'Package name could be vulnerable to dependency confusion attacks',
            pattern: /require\s*\(\s*['"`](?![@a-z0-9-_.]+\/)[a-z0-9-_.]+['"`]\s*\)|import\s+.*?from\s+['"`](?![@a-z0-9-_.]+\/)[a-z0-9-_.]+['"`]/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 70,
            cweId: 'CWE-494',
            suggestion: 'Use scoped packages (@org/package), verify package authenticity, and implement package-lock.json',
            languages: ['javascript', 'typescript'],
            category: 'supply-chain'
        },
        {
            id: 'typosquatting-detection',
            name: 'Potential Typosquatting Package',
            description: 'Package name resembles popular packages but with slight variations',
            pattern: /require\s*\(\s*['"`](?:loadsh|expresss|nodemailer|mongose|requestt|axio)['"`]\s*\)/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-494',
            suggestion: 'Verify package names against official registries; use tools like npm-audit',
            languages: ['javascript', 'typescript'],
            category: 'supply-chain'
        },
        {
            id: 'postinstall-script-risk',
            name: 'Suspicious postinstall script',
            description: 'Package.json postinstall scripts can execute arbitrary code during installation',
            pattern: /"postinstall"\s*:\s*['"`](?:curl|wget|bash|sh|powershell|cmd)[^'"` ]*['"`]/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-94',
            suggestion: 'Review postinstall scripts; consider using --ignore-scripts during npm install',
            languages: ['javascript', 'typescript'],
            category: 'supply-chain'
        },

        // 2025 API Security Vulnerabilities
        {
            id: 'graphql-introspection-enabled',
            name: 'GraphQL Introspection Enabled in Production',
            description: 'GraphQL introspection can expose sensitive schema information',
            pattern: /introspection\s*:\s*true|graphqlHTTP\s*\([^)]*introspection\s*:\s*true/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 90,
            cweId: 'CWE-200',
            suggestion: 'Disable introspection in production: { introspection: false }',
            languages: ['javascript', 'typescript'],
            category: 'api-security'
        },
        {
            id: 'graphql-query-depth-missing',
            name: 'GraphQL Missing Query Depth Limiting',
            description: 'GraphQL without depth limiting is vulnerable to DoS attacks',
            pattern: /(?:buildSchema|makeExecutableSchema|GraphQLSchema)(?![\s\S]*depthLimit|[\s\S]*queryDepth)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 75,
            cweId: 'CWE-400',
            suggestion: 'Implement query depth limiting with libraries like graphql-depth-limit',
            languages: ['javascript', 'typescript'],
            category: 'api-security'
        },
        {
            id: 'api-rate-limiting-missing',
            name: 'Missing API Rate Limiting',
            description: 'API endpoints without rate limiting are vulnerable to abuse',
            pattern: /app\.(?:get|post|put|delete|patch)\s*\([^)]*\)\s*,\s*(?!.*rateLimit|.*express-rate-limit)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            confidence: 65,
            cweId: 'CWE-770',
            suggestion: 'Implement rate limiting with express-rate-limit or similar middleware',
            languages: ['javascript', 'typescript'],
            category: 'api-security'
        },
        {
            id: 'rest-api-verb-tampering',
            name: 'HTTP Method Override Vulnerability',
            description: 'Method override middleware can bypass security controls',
            pattern: /methodOverride\s*\(|app\.use\s*\(\s*methodOverride/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-436',
            suggestion: 'Restrict method override to specific methods and validate origin',
            languages: ['javascript', 'typescript'],
            category: 'api-security'
        },

        // 2025 Container Security Vulnerabilities
        {
            id: 'docker-privileged-container',
            name: 'Privileged Docker Container',
            description: 'Running containers in privileged mode grants excessive permissions',
            pattern: /--privileged|privileged\s*:\s*true/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-250',
            suggestion: 'Remove --privileged flag; use specific capabilities with --cap-add instead',
            languages: ['dockerfile', 'yaml', 'json'],
            category: 'container-security'
        },
        {
            id: 'docker-root-user',
            name: 'Container Running as Root User',
            description: 'Containers should not run as root user for security',
            pattern: /USER\s+(?:0|root)\s*$|"user"\s*:\s*['"`](?:0|root)['"`]/gmi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-250',
            suggestion: 'Create and use a non-root user: USER 1001 or USER appuser',
            languages: ['dockerfile'],
            category: 'container-security'
        },
        {
            id: 'kubernetes-hostnetwork',
            name: 'Kubernetes hostNetwork Enabled',
            description: 'hostNetwork: true bypasses network policies and exposes host network',
            pattern: /hostNetwork\s*:\s*true/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-250',
            suggestion: 'Remove hostNetwork: true; use proper service networking instead',
            languages: ['yaml'],
            category: 'container-security'
        },
        {
            id: 'docker-secret-in-env',
            name: 'Secret in Docker Environment Variable',
            description: 'Secrets in environment variables are visible in process lists',
            pattern: /ENV\s+(?:.*(?:PASSWORD|SECRET|TOKEN|KEY|API_KEY).*=|.*=.*(?:password|secret|token|key))/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-200',
            suggestion: 'Use Docker secrets or Kubernetes secrets instead of environment variables',
            languages: ['dockerfile'],
            category: 'container-security'
        },

        // 2025 Race Condition Vulnerabilities
        {
            id: 'file-race-condition',
            name: 'Time-of-Check Time-of-Use (TOCTOU) Race Condition',
            description: 'Checking file existence separately from usage creates race condition',
            pattern: /(?:fs\.existsSync|fs\.access)\s*\([^)]+\)[\s\S]*?(?:fs\.readFileSync|fs\.writeFileSync|fs\.unlinkSync)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 75,
            cweId: 'CWE-367',
            suggestion: 'Use atomic operations or proper file locking; handle errors instead of checking existence',
            languages: ['javascript', 'typescript'],
            category: 'race-condition'
        },
        {
            id: 'shared-state-race',
            name: 'Shared State Race Condition',
            description: 'Concurrent access to shared variables without synchronization',
            pattern: /let\s+\w+\s*=\s*0[\s\S]*?\+\+|var\s+\w+\s*=\s*0[\s\S]*?\+\+/gi,
            severity: vscode.DiagnosticSeverity.Information,
            confidence: 60,
            cweId: 'CWE-362',
            suggestion: 'Use atomic operations, locks, or message passing for shared state',
            languages: ['javascript', 'typescript'],
            category: 'race-condition'
        },

        // 2025 Memory Safety Issues
        {
            id: 'buffer-overflow-risk',
            name: 'Potential Buffer Overflow',
            description: 'Buffer operations without bounds checking can cause overflow',
            pattern: /Buffer\.(?:alloc|allocUnsafe)\s*\(\s*(?!\d+\s*\))\w+|Buffer\.from\s*\([^,)]*\w+[^,)]*\)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 70,
            cweId: 'CWE-120',
            suggestion: 'Use Buffer.alloc with fixed sizes; validate input length before Buffer.from',
            languages: ['javascript', 'typescript'],
            category: 'memory-safety'
        },
        {
            id: 'memory-leak-listener',
            name: 'Potential Memory Leak - Event Listener',
            description: 'Event listeners without cleanup can cause memory leaks',
            pattern: /\.addEventListener\s*\(|on\s*\(\s*['"`]\w+['"`]\s*,(?![\s\S]*removeEventListener|[\s\S]*off\s*\()/gi,
            severity: vscode.DiagnosticSeverity.Information,
            confidence: 65,
            cweId: 'CWE-401',
            suggestion: 'Add corresponding removeEventListener or use AbortController for cleanup',
            languages: ['javascript', 'typescript'],
            category: 'memory-safety'
        },

        // 2025 AI/ML Security Vulnerabilities
        {
            id: 'model-injection-risk',
            name: 'AI Model Injection Vulnerability',
            description: 'Loading models from untrusted sources can execute arbitrary code',
            pattern: /(?:tensorflow|torch|sklearn)\.(?:load|load_model)\s*\(\s*(?!['"` ])/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-502',
            suggestion: 'Validate model sources; use model signing and integrity checks',
            languages: ['python', 'javascript', 'typescript'],
            category: 'ai-ml-security'
        },
        {
            id: 'prompt-injection',
            name: 'Potential AI Prompt Injection',
            description: 'Concatenating user input with prompts can lead to prompt injection',
            pattern: /(?:openai|anthropic|claude|gpt).*?\+.*?(?:input|user_input|req\.body|request)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 75,
            cweId: 'CWE-94',
            suggestion: 'Sanitize user input; use structured prompts with clear delimiters',
            languages: ['javascript', 'typescript', 'python'],
            category: 'ai-ml-security'
        },
        {
            id: 'model-data-exposure',
            name: 'AI Model Training Data Exposure',
            description: 'Model outputs may expose sensitive training data',
            pattern: /(?:model\.predict|model\.generate)(?![\s\S]*sanitize|[\s\S]*filter)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            confidence: 60,
            cweId: 'CWE-200',
            suggestion: 'Implement output filtering and sanitization for model responses',
            languages: ['python', 'javascript', 'typescript'],
            category: 'ai-ml-security'
        },

        // 2025 Zero-Day Style Patterns
        {
            id: 'prototype-pollution-2025',
            name: 'Advanced Prototype Pollution Vector',
            description: 'Object merge operations without prototype pollution protection',
            pattern: /(?:Object\.assign|\.\.\.|lodash\.merge|merge)\s*\([^)]*\w+[^)]*\)(?![\s\S]*hasOwnProperty|[\s\S]*Object\.create\(null\))/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 70,
            cweId: 'CWE-1321',
            suggestion: 'Use Map instead of objects or validate keys with hasOwnProperty checks',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        {
            id: 'web-cache-poisoning',
            name: 'Web Cache Poisoning Vulnerability',
            description: 'Unvalidated headers can poison web caches',
            pattern: /req\.headers\[.*\](?![\s\S]*validate|[\s\S]*sanitize)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 65,
            cweId: 'CWE-436',
            suggestion: 'Validate and sanitize all headers; implement header allowlists',
            languages: ['javascript', 'typescript'],
            category: 'other'
        },
        {
            id: 'server-side-request-forgery-2025',
            name: 'Enhanced SSRF via URL Constructor',
            description: 'URL constructor with user input can bypass basic SSRF protections',
            pattern: /new\s+URL\s*\(\s*(?!['"` ])[^,)]*\w+[^,)]*\)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 75,
            cweId: 'CWE-918',
            suggestion: 'Validate URLs against allowlists; check for private IP ranges and metadata endpoints',
            languages: ['javascript', 'typescript'],
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
        },

        // Dart-specific security vulnerabilities
        {
            id: 'dart-eval-injection',
            name: 'Dart Dynamic Code Execution',
            description: 'Dynamic code execution using eval or similar mechanisms',
            pattern: /dart:mirrors|MirrorSystem\.(?:getName|invoke)|eval\s*\(|Function\.apply/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-94',
            suggestion: 'Avoid dynamic code execution; use safe alternatives or proper validation',
            languages: ['dart'],
            category: 'other'
        },
        {
            id: 'dart-file-path-traversal',
            name: 'Dart Path Traversal Vulnerability',
            description: 'File operations with unvalidated path input',
            pattern: /File\s*\(\s*[^)]*\.\.[\\\/]|Directory\s*\(\s*[^)]*\.\.[\\\/]|\.readAsString\(\)|\.writeAsString\(/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-22',
            suggestion: 'Validate and sanitize file paths; use path.join() and check bounds',
            languages: ['dart'],
            category: 'path-traversal'
        },
        {
            id: 'dart-http-injection',
            name: 'Dart HTTP Injection Risk',
            description: 'HTTP requests with unvalidated user input',
            pattern: /http\.(?:get|post|put|delete)\s*\(\s*Uri\.parse\s*\(\s*[^)]*\$|HttpClient\(\)\.(?:get|post).*\$\{/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-918',
            suggestion: 'Validate URLs and use allowlists; sanitize user input in HTTP requests',
            languages: ['dart'],
            category: 'other'
        },
        {
            id: 'dart-sql-injection',
            name: 'Dart SQL Injection Risk',
            description: 'SQL query construction using string interpolation',
            pattern: /(?:query|execute|rawQuery)\s*\(\s*['"` ]*.*\$\{[^}]*\}|(?:query|execute|rawQuery)\s*\(\s*['"` ]*.*\+/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 95,
            cweId: 'CWE-89',
            suggestion: 'Use parameterized queries or prepared statements instead of string interpolation',
            languages: ['dart'],
            category: 'sql-injection'
        },
        {
            id: 'dart-xss-web',
            name: 'Dart Web XSS Vulnerability',
            description: 'DOM manipulation with unsanitized content',
            pattern: /\.innerHtml\s*=\s*[^"'`\s]|setInnerHtml\s*\(|element\.append.*\$\{/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 85,
            cweId: 'CWE-79',
            suggestion: 'Use text content instead of HTML or sanitize with a trusted library',
            languages: ['dart'],
            category: 'xss'
        },
        {
            id: 'dart-insecure-random',
            name: 'Dart Weak Random Number Generation',
            description: 'Random class is not cryptographically secure',
            pattern: /Random\s*\(\s*\)\.nextInt|Random\(\)\.nextDouble(?!.*secure)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 80,
            cweId: 'CWE-338',
            suggestion: 'Use Random.secure() for cryptographically secure random numbers',
            languages: ['dart'],
            category: 'crypto'
        },
        {
            id: 'dart-hardcoded-secrets',
            name: 'Dart Hardcoded Secrets',
            description: 'Hardcoded API keys or passwords in Dart code',
            pattern: /(?:apiKey|password|secret|token)\s*[:=]\s*['"`][a-zA-Z0-9._-]{8,}['"`]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            confidence: 90,
            cweId: 'CWE-798',
            suggestion: 'Store secrets in environment variables or secure configuration',
            languages: ['dart'],
            category: 'auth'
        },
        {
            id: 'dart-unsafe-cast',
            name: 'Dart Unsafe Type Cast',
            description: 'Unsafe casting without null checks can cause runtime errors',
            pattern: /as\s+(?!String|int|double|bool|List|Map)\w+(?!\?)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 70,
            cweId: 'CWE-704',
            suggestion: 'Use safe casting with is operator or add null checks',
            languages: ['dart'],
            category: 'other'
        },
        {
            id: 'dart-flutter-debug-mode',
            name: 'Flutter Debug Mode in Production',
            description: 'Debug mode should be disabled in production builds',
            pattern: /kDebugMode\s*==\s*true|debugPrint\s*\(|assert\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Information,
            confidence: 75,
            cweId: 'CWE-489',
            suggestion: 'Remove debug code or wrap in kDebugMode checks for production',
            languages: ['dart'],
            category: 'other'
        },
        {
            id: 'dart-flutter-webview-security',
            name: 'Flutter WebView Security Issues',
            description: 'WebView with JavaScript enabled without security controls',
            pattern: /WebView\s*\([^)]*javascriptMode\s*:\s*JavascriptMode\.unrestricted/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            confidence: 85,
            cweId: 'CWE-79',
            suggestion: 'Restrict JavaScript mode and validate URLs; implement content security policy',
            languages: ['dart'],
            category: 'xss'
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
        },

        // 2025 Best Practices
        {
            id: 'missing-dependency-pinning',
            name: 'Unpinned Package Dependencies',
            description: 'Package.json dependencies should be pinned to specific versions',
            pattern: /"[^"]+"\s*:\s*"[^\d"]*[~^][^"]*"/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Pin dependencies to exact versions to prevent supply chain attacks',
            languages: ['json'],
            category: 'supply-chain'
        },
        {
            id: 'missing-security-headers',
            name: 'Missing Security Headers Configuration',
            description: 'Web applications should implement security headers',
            pattern: /app\.listen|server\.listen(?![\s\S]*helmet|[\s\S]*security-headers)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Add security headers with helmet.js or equivalent middleware',
            languages: ['javascript', 'typescript'],
            category: 'security'
        },
        {
            id: 'dockerfile-best-practices',
            name: 'Dockerfile Security Best Practices',
            description: 'Dockerfile should follow security best practices',
            pattern: /FROM\s+[^:\s]+(?:latest|:[^:\s]*latest)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Use specific image tags instead of latest for reproducible builds',
            languages: ['dockerfile'],
            category: 'container'
        },
        {
            id: 'ai-input-validation',
            name: 'AI/ML Input Validation Missing',
            description: 'AI model inputs should be validated and sanitized',
            pattern: /(?:model\.predict|openai|anthropic)(?![\s\S]*validate|[\s\S]*sanitize)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Implement input validation and sanitization for AI/ML model inputs',
            languages: ['python', 'javascript', 'typescript'],
            category: 'ai-ml'
        },
        {
            id: 'api-versioning-missing',
            name: 'API Versioning Best Practice',
            description: 'APIs should implement proper versioning strategy',
            pattern: /app\.(?:get|post|put|delete)\s*\(\s*['"`]\/(?!v\d+|api\/v\d+)[^'"` ]*['"`]/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Implement API versioning: /api/v1/endpoint or /v1/endpoint',
            languages: ['javascript', 'typescript'],
            category: 'maintainability'
        },
        {
            id: 'async-error-handling',
            name: 'Async Function Missing Error Handling',
            description: 'Async functions should have proper error handling',
            pattern: /async\s+(?:function|\w+)\s*\([^)]*\)\s*\{(?![\s\S]*try|[\s\S]*catch|[\s\S]*\.catch)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Add try-catch blocks or .catch() handlers for async operations',
            languages: ['javascript', 'typescript'],
            category: 'error-handling'
        },

        // Dart-specific best practices
        {
            id: 'dart-print-statements',
            name: 'Dart Print Statements in Production',
            description: 'Print statements should be removed or replaced with proper logging',
            pattern: /\bprint\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Replace print statements with proper logging or remove for production',
            languages: ['dart'],
            category: 'debugging'
        },
        {
            id: 'dart-nullable-types',
            name: 'Dart Non-Nullable Type Usage',
            description: 'Consider using nullable types for better null safety',
            pattern: /\w+\s+\w+(?!\?)\s*;(?!.*\?\s*;)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Use nullable types (Type?) where appropriate for null safety',
            languages: ['dart'],
            category: 'maintainability'
        },
        {
            id: 'dart-magic-numbers',
            name: 'Dart Magic Numbers',
            description: 'Avoid magic numbers; use named constants instead',
            pattern: /(?<![a-zA-Z_])\d{2,}(?![.\d])/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Replace magic numbers with named constants for better maintainability',
            languages: ['dart'],
            category: 'maintainability'
        },
        {
            id: 'dart-todo-comments',
            name: 'Dart TODO Comments',
            description: 'TODO comments indicate incomplete work',
            pattern: /\/\/\s*(?:TODO|FIXME|HACK|XXX|BUG)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Address TODO comments before production deployment',
            languages: ['dart'],
            category: 'maintainability'
        },
        {
            id: 'dart-async-error-handling',
            name: 'Dart Async Function Missing Error Handling',
            description: 'Async functions should have proper error handling',
            pattern: /Future<[^>]*>\s+\w+\s*\([^)]*\)\s*async\s*\{(?![\s\S]*try|[\s\S]*catch|[\s\S]*\.catchError)/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Add try-catch blocks or .catchError() handlers for async operations',
            languages: ['dart'],
            category: 'error-handling'
        },
        {
            id: 'dart-flutter-dispose',
            name: 'Flutter Widget Missing Dispose',
            description: 'StatefulWidget should dispose controllers and streams',
            pattern: /class\s+\w+\s+extends\s+StatefulWidget[\s\S]*?Controller\s+\w+(?![\s\S]*dispose\(\))/gi,
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Implement dispose() method to clean up controllers and prevent memory leaks',
            languages: ['dart'],
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