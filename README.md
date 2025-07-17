# Code Security Analyzer

A comprehensive VS Code extension that analyzes code for security vulnerabilities, errors, and best practices violations using both pattern-based detection and AI-powered analysis.

## Features

🔍 **Real-time Security Analysis**
- Automatic vulnerability detection as you type
- Support for 10+ programming languages
- Pattern-based and AI-powered analysis

🎯 **Inline Visual Feedback** 
- CodeLens indicators showing security issues directly in code
- Confidence ratings with color-coded indicators
- Hover tooltips with detailed explanations

🤖 **AI-Enhanced Detection**
- OpenAI GPT-4 integration for sophisticated analysis
- Language-specific security best practices
- Actionable remediation suggestions

📊 **Comprehensive Reporting**
- Detailed webview panels for each security issue
- CVE references and security standards compliance
- Confidence scoring and risk assessment

## Supported Languages

- JavaScript/TypeScript
- Python
- Java
- C#
- PHP
- Go
- Rust
- C/C++

## Security Issues Detected

### High Priority Vulnerabilities
- **SQL Injection** - Parameterized query recommendations
- **Cross-Site Scripting (XSS)** - Input sanitization guidance
- **Command Injection** - Safe execution patterns
- **Path Traversal** - File access validation

### Authentication & Authorization
- **Hardcoded Credentials** - Environment variable migration
- **Weak Cryptography** - Strong algorithm recommendations
- **Session Management** - Secure configuration patterns

### Code Quality & Best Practices
- **Insecure Random Generation** - Cryptographically secure alternatives
- **Information Disclosure** - Logging and error handling
- **Unsafe Deserialization** - Safe parsing methods
- **Open Redirects** - URL validation techniques

## Installation & Setup

1. **Install the Extension** (when published to VS Code Marketplace)
   ```
   ext install code-security-analyzer
   ```

2. **Configure OpenAI API Key** (Optional but recommended)
   - Open Command Palette (`Ctrl+Shift+P`)
   - Run: `Code Security Analyzer: Configure OpenAI API Key`
   - Enter your OpenAI API key for enhanced AI analysis

3. **Start Using**
   - Open any supported code file
   - Extension automatically activates and analyzes code
   - View issues through CodeLens indicators and hover tooltips

## Usage

### Automatic Analysis
- Extension analyzes code automatically when files are opened or changed
- Issues appear as inline CodeLens indicators
- Hover over highlighted code for detailed information

### Manual Analysis
- Right-click in editor → "Analyze Active File for Security Issues"
- Command Palette: `Code Security Analyzer: Analyze Active File`
- Uses `Ctrl+Shift+P` → search for "security"

### Configuration Options

```json
{
  "codeSecurityAnalyzer.enableAIAnalysis": true,
  "codeSecurityAnalyzer.maxFileSize": 8000,
  "codeSecurityAnalyzer.analysisDelay": 2000
}
```

## Example Detections

### SQL Injection
```javascript
// ❌ Vulnerable
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ Secure Alternative
const query = 'SELECT * FROM users WHERE id = ?';
db.execute(query, [userId]);
```

### XSS Prevention
```javascript
// ❌ Vulnerable
element.innerHTML = userInput;

// ✅ Secure Alternative
element.textContent = userInput;
// or
element.innerHTML = DOMPurify.sanitize(userInput);
```

### Hardcoded Credentials
```javascript
// ❌ Vulnerable
const apiKey = "sk-1234567890abcdef";

// ✅ Secure Alternative
const apiKey = process.env.API_KEY;
```

## Requirements

- VS Code 1.102.0 or later
- OpenAI API key (optional, for enhanced AI analysis)
- Internet connection (for AI features)

## Extension Settings

This extension contributes the following settings:

* `codeSecurityAnalyzer.apiKey`: OpenAI API key for enhanced AI analysis
* `codeSecurityAnalyzer.enableAIAnalysis`: Enable/disable AI-powered analysis
* `codeSecurityAnalyzer.maxFileSize`: Maximum file size for AI analysis (characters)
* `codeSecurityAnalyzer.analysisDelay`: Delay before triggering analysis after changes (ms)

## Development

### Building from Source

```bash
# Clone repository
git clone <repository-url>
cd code-security-analyzer

# Install dependencies
npm install

# Compile extension
npm run compile

# Run in development mode
npm run watch
```

## Known Issues

- AI analysis limited to files under 8,000 characters (configurable)
- API rate limits may apply based on OpenAI plan
- Some complex vulnerabilities may require manual code review

## Release Notes

### 0.0.1

Initial release with comprehensive security analysis features:
- Pattern-based vulnerability detection
- AI-powered analysis with OpenAI integration
- Multi-language support
- Real-time CodeLens and hover providers
- Detailed security issue reporting

---

**Stay Secure!** 🔒 Remember that automated tools are helpers, not replacements for security expertise and thorough code reviews.
