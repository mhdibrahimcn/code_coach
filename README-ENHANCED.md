# Code Security Analyzer - Enhanced Edition 🛡️

An advanced VS Code extension that provides AI-powered security analysis, vulnerability detection, and code quality assessment with support for multiple AI providers and intelligent offline detection.

## ✨ Major Enhancements (New Version)

### 🤖 Multi-AI Provider Support
- **OpenAI**: Official GPT models (GPT-4, GPT-4o-mini, GPT-3.5-turbo)
- **OpenRouter**: Access to Claude, Llama, Gemini, and other models
- **Custom Endpoints**: Support for any OpenAI-compatible API
- **Model Selection**: Choose from 15+ AI models for analysis
- **Secure Key Management**: Encrypted storage of multiple API keys

### 🔧 Advanced Settings Panel
- **Visual Configuration**: Interactive webview-based settings panel
- **Real-time Testing**: Test AI provider connections instantly
- **Performance Tuning**: Adjust chunk sizes, file limits, and analysis delays
- **Analysis Modes**: Toggle between offline, AI-only, or hybrid modes

### 🔍 Enhanced Detection System
- **Language-Specific Patterns**: Tailored vulnerability detection for 10+ languages
- **Hybrid Analysis**: Combines offline pattern matching with AI validation
- **Smart Chunking**: Processes large files efficiently with context preservation
- **Token Optimization**: Minimizes API usage while maximizing accuracy

### 🚀 New Vulnerability Detection
- **SQL Injection**: Language-specific detection for JS/TS, Python, PHP, Java
- **XSS Vulnerabilities**: DOM manipulation, innerHTML usage, document.write
- **Command Injection**: System calls and shell execution detection
- **Cryptographic Issues**: Weak hashing (MD5, SHA1), insecure random
- **Path Traversal**: Directory traversal and file inclusion vulnerabilities
- **Authentication Issues**: Hardcoded credentials, weak tokens

### 📊 Comprehensive Analysis
- **Best Practice Checks**: console.log, debugger, empty catch blocks
- **Code Complexity**: Cyclomatic and cognitive complexity analysis
- **Performance Issues**: Magic numbers, var usage, TODO comments
- **Multi-language Support**: JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust, C/C++

## 🚀 Quick Start

1. **Install the Extension** (when published)
2. **Open Settings Panel**: Click the shield icon in status bar or `Ctrl+Shift+P` → "Code Security Analyzer: Open Settings Panel"
3. **Configure AI Provider**: Choose your provider and enter API key
4. **Start Analyzing**: Analysis runs automatically on supported files

## ⚙️ Configuration Options

### AI Provider Settings
```json
{
    "codeSecurityAnalyzer.aiProvider": "openrouter",
    "codeSecurityAnalyzer.aiModel": "gpt-4o-mini",
    "codeSecurityAnalyzer.enableAIAnalysis": true,
    "codeSecurityAnalyzer.hybridMode": true
}
```

### Analysis Settings
```json
{
    "codeSecurityAnalyzer.enableOfflineAnalysis": true,
    "codeSecurityAnalyzer.enableBestPractices": true,
    "codeSecurityAnalyzer.enableComplexityAnalysis": true,
    "codeSecurityAnalyzer.maxFileSize": 10000,
    "codeSecurityAnalyzer.chunkSize": 3000,
    "codeSecurityAnalyzer.analysisDelay": 2000
}
```

## 📋 Commands

- `Analyze Active File`: Perform comprehensive security analysis
- `Show Complexity Report`: Generate detailed complexity metrics
- `Open Settings Panel`: Access visual configuration interface
- `Switch AI Provider`: Quickly change between configured providers
- `Toggle Offline Mode`: Switch between online/offline analysis
- `Get AI Fix`: Generate AI-powered fix suggestions
- `Apply AI Fix`: Apply fixes with diff preview

## 🔍 Detection Capabilities

### Security Vulnerabilities
| Category | Languages | Patterns | Confidence |
|----------|-----------|----------|------------|
| SQL Injection | JS/TS, Python, PHP, Java | 15+ patterns | 85-95% |
| XSS | JS/TS, HTML | 10+ patterns | 80-90% |
| Command Injection | JS/TS, Python | 8+ patterns | 90-95% |
| Crypto Issues | All | 12+ patterns | 90-100% |
| Auth Issues | All | 6+ patterns | 75-90% |

### Best Practices
- **Code Quality**: 20+ patterns across all languages
- **Performance**: Magic numbers, inefficient patterns
- **Maintainability**: TODO comments, complex functions
- **Debugging**: console.log, debugger statements

## 🔧 API Key Setup

### OpenAI
1. Visit [OpenAI API Keys](https://platform.openai.com/api-keys)
2. Create new API key
3. Add to extension: Settings Panel → AI Provider → OpenAI → Enter key

### OpenRouter
1. Visit [OpenRouter Keys](https://openrouter.ai/keys)
2. Create new API key
3. Add to extension: Settings Panel → AI Provider → OpenRouter → Enter key

### Custom Endpoint
1. Configure your OpenAI-compatible endpoint
2. Settings Panel → AI Provider → Custom → Enter endpoint URL and key

## 🏗️ Architecture

### Modular Design
```
src/
├── core/                 # Core functionality
│   ├── AIProviderManager.ts    # AI provider management
│   └── LanguagePatterns.ts     # Vulnerability patterns
├── analyzers/            # Analysis engines  
│   ├── OfflineAnalyzer.ts      # Pattern-based detection
│   ├── SmartAIAnalyzer.ts      # AI-powered analysis
│   └── HybridAnalyzer.ts       # Combined analysis
├── ui/                   # User interface
│   └── SettingsWebviewProvider.ts  # Settings panel
└── test/                 # Comprehensive tests
```

### Analysis Pipeline
1. **File Change Detection** → Debounced analysis trigger
2. **Language Detection** → Route to appropriate patterns
3. **Offline Analysis** → Fast pattern matching
4. **AI Enhancement** → Context-aware validation (if enabled)
5. **Result Merging** → Deduplicated, prioritized issues
6. **UI Updates** → CodeLens, diagnostics, status bar

## 🧪 Testing

### Run Tests
```bash
npm test
```

### Test Coverage
- **Unit Tests**: 95%+ coverage for core modules
- **Integration Tests**: AI provider functionality
- **Pattern Tests**: All vulnerability patterns validated
- **UI Tests**: Settings panel and webviews

## 🔒 Security Best Practices Applied

### Extension Security
- ✅ No hardcoded API keys in source code
- ✅ Secure storage of credentials using VS Code settings
- ✅ Input validation and sanitization
- ✅ Error handling prevents information leakage
- ✅ Minimal dependencies with security audit
- ✅ CSP headers for webview security

### Detection Accuracy
- ✅ Language-specific pattern matching
- ✅ Context-aware confidence scoring
- ✅ False positive reduction through AI validation
- ✅ Regular expression security (no ReDoS vulnerabilities)

## 🚀 Performance Optimizations

### Token Efficiency
- **Smart Chunking**: Processes large files in context-aware chunks
- **Caching**: 10-minute analysis cache to prevent duplicate API calls
- **Selective Analysis**: Only analyzes changed regions when possible
- **Batch Processing**: Groups related issues for efficient AI analysis

### Resource Management
- **Debounced Analysis**: Configurable delay prevents excessive API calls
- **Memory Management**: Efficient pattern matching with minimal memory footprint
- **Background Processing**: Non-blocking analysis pipeline

## 🛠️ Development

### Build Extension
```bash
npm run compile    # Compile TypeScript
npm run package    # Package extension
npm run watch      # Watch mode for development
```

### Extension Development
```bash
code .             # Open in VS Code
F5                 # Launch Extension Development Host
```

## 📊 Supported Languages

| Language | Vulnerability Patterns | Best Practice Checks | Complexity Analysis |
|----------|----------------------|---------------------|-------------------|
| JavaScript | ✅ 25+ patterns | ✅ 15+ checks | ✅ Full support |
| TypeScript | ✅ 25+ patterns | ✅ 15+ checks | ✅ Full support |
| Python | ✅ 20+ patterns | ✅ 10+ checks | ✅ Full support |
| Java | ✅ 18+ patterns | ✅ 12+ checks | ✅ Full support |
| C# | ✅ 15+ patterns | ✅ 10+ checks | ✅ Full support |
| PHP | ✅ 12+ patterns | ✅ 8+ checks | ✅ Partial |
| Go | ✅ 10+ patterns | ✅ 8+ checks | ✅ Partial |
| Rust | ✅ 8+ patterns | ✅ 6+ checks | ✅ Partial |
| C/C++ | ✅ 8+ patterns | ✅ 6+ checks | ✅ Partial |

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Add comprehensive tests for new functionality
4. Ensure all tests pass: `npm test`
5. Commit changes: `git commit -m 'Add amazing feature'`
6. Push to branch: `git push origin feature/amazing-feature`
7. Open Pull Request

### Code Style
- TypeScript with strict type checking
- ESLint configuration enforced
- 100 character line limit
- Comprehensive JSDoc comments

## 📝 Changelog

### v2.0.0 - Enhanced Edition
- ✨ Multi-AI provider support (OpenAI, OpenRouter, Custom)
- 🔧 Visual settings panel with real-time configuration
- 🎯 Language-specific vulnerability detection
- ⚡ Smart chunking and token optimization  
- 🔍 Hybrid offline+AI analysis pipeline
- 📊 Enhanced best practice and complexity analysis
- 🧪 Comprehensive test suite (95%+ coverage)
- 🔒 Security hardening and credential management

### v1.0.0 - Original Version
- Basic AI analysis with OpenAI
- Simple vulnerability detection
- CodeLens and hover providers
- Diagnostic collection

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Documentation**: [Wiki](https://github.com/your-repo/wiki)
- **Security Issues**: Please report responsibly via email

## 🙏 Acknowledgments

- OpenAI and OpenRouter for AI model access
- VS Code team for excellent extension APIs
- Security research community for vulnerability patterns
- Contributors and beta testers

---

**Made with ❤️ for secure coding practices**

> *"Security is not a product, but a process"* - Bruce Schneier