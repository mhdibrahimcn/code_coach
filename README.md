# Code Security Analyzer with AI Fix Suggestions

A comprehensive VS Code extension that analyzes code for security vulnerabilities and provides AI-powered fix suggestions similar to GitHub Copilot.

## Features

### 🔍 Security Analysis
- **Real-time vulnerability detection** for multiple programming languages
- **Complexity analysis** with detailed metrics
- **Best practices checking** to improve code quality
- **Code lens integration** showing issues directly in the editor
- **Hover information** with detailed explanations

### 🤖 AI-Powered Fix Suggestions
- **Intelligent fix generation** using advanced AI models
- **Context-aware solutions** that understand your codebase
- **Confidence scoring** for each suggested fix
- **Step-by-step implementation** guidance
- **One-click fix application** with safety confirmations

### 🛡️ Security Coverage
- SQL Injection detection and prevention
- Cross-Site Scripting (XSS) vulnerabilities
- Hardcoded credentials and secrets
- Insecure cryptographic practices
- Command injection vulnerabilities
- Path traversal issues
- And many more...

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

## How It Works

### 1. Automatic Analysis
The extension continuously analyzes your code in the background, detecting:
- **Vulnerabilities** (🚨 High priority security issues)
- **Complexity issues** (📊 Code maintainability problems)
- **Best practice violations** (💡 Code quality improvements)

### 2. AI Fix Suggestions
When you hover over a security issue, the extension:
- Shows detailed information about the vulnerability
- Provides an AI-generated fix suggestion
- Displays confidence levels and risk assessments
- Offers step-by-step implementation guidance

### 3. One-Click Fixes
Through code actions or the hover UI, you can:
- **Get AI Fix** - Generate a secure solution for the issue
- **Apply Fix** - Automatically replace vulnerable code with secure alternatives
- **Review Changes** - See before/after code comparisons

## Usage

### Setup
1. Install the extension
2. Configure your OpenRouter API key:
   - Open Command Palette (`Ctrl+Shift+P`)
   - Run "Configure OpenAI API Key"
   - Enter your API key

### Getting Fix Suggestions
1. **Hover over issues** - See AI fix suggestions in tooltips
2. **Use code actions** - Right-click on issues for quick fixes
3. **Command palette** - Search for "Get AI Fix" commands

### Applying Fixes
1. Review the suggested fix in the detailed UI
2. Check the confidence level and risk assessment
3. Click "Apply Fix" to replace the vulnerable code
4. The extension will re-analyze to confirm the fix

### Configuration Options

```json
{
  "codeSecurityAnalyzer.enableAIAnalysis": true,
  "codeSecurityAnalyzer.maxFileSize": 8000,
  "codeSecurityAnalyzer.analysisDelay": 2000
}
```

## Example: SQL Injection Fix

**Original vulnerable code:**
```javascript
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

**AI-generated secure fix:**
```javascript
const query = 'SELECT * FROM users WHERE id = ?';
const result = database.execute(query, [userId]);
```

## Configuration

### Settings
- `codeSecurityAnalyzer.apiKey` - Your OpenRouter API key
- `codeSecurityAnalyzer.enableAIAnalysis` - Enable/disable AI features
- `codeSecurityAnalyzer.maxFileSize` - Maximum file size for AI analysis
- `codeSecurityAnalyzer.analysisDelay` - Delay before triggering analysis

### Commands
- `🔍 Analyze Active File` - Run full security analysis
- `📊 Show Complexity Report` - View detailed complexity metrics
- `🤖 Get AI Fix Suggestion` - Generate AI fix for selected issue
- `🚀 Apply AI Fix` - Apply suggested security fix
- `⚙️ Configure OpenAI API Key` - Set up API access

## Privacy & Security
- Code is sent to OpenRouter/AI service only for fix generation
- No code is stored or logged by the extension
- All communication is encrypted (HTTPS)
- You maintain full control over which fixes to apply

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
