# Copilot Instructions

<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

This is a VS Code extension project for advanced code security analysis. Please use the get_vscode_api with a query as input to fetch the latest VS Code API references.

## Project Overview
This extension provides comprehensive security analysis for code, featuring:
- AI-powered vulnerability detection using OpenAI's GPT-4
- Real-time code analysis with pattern matching
- Language-specific security best practices
- Inline inspection lenses for immediate feedback
- Detailed hover information with remediation suggestions
- CVE references and security standards compliance

## Key Features
- **Multi-Language Support**: JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust, C/C++
- **AI Integration**: Enhanced analysis using OpenAI API with custom security-focused prompts
- **Real-time Analysis**: Automatic scanning on file changes with debouncing
- **Visual Indicators**: CodeLens providers with confidence ratings and severity icons
- **Detailed Reporting**: Comprehensive webview panels with actionable recommendations
- **Configuration**: User-configurable API keys and analysis settings

## Security Focus Areas
- SQL Injection vulnerabilities
- Cross-Site Scripting (XSS) attacks
- Authentication and authorization flaws
- Cryptographic weaknesses
- Input validation issues
- Command injection risks
- Insecure deserialization
- Information disclosure
- Path traversal vulnerabilities
- Hardcoded credentials

## Technical Implementation
- Uses VS Code Extension API effectively
- Implements diagnostic collections for error reporting
- Creates efficient pattern-based basic analysis
- Integrates with OpenAI API for advanced AI analysis
- Handles multiple file types and programming languages
- Provides clear, actionable security recommendations
- Includes confidence scoring and CVE references

## Development Guidelines
- Follow VS Code extension best practices
- Implement proper error handling for API failures
- Use TypeScript strictly for type safety
- Optimize performance for large files
- Provide fallback analysis when AI is unavailable
- Include comprehensive security pattern detection
