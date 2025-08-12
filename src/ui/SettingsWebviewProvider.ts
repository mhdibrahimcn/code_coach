import * as vscode from 'vscode';
import { AIProviderManager } from '../core/AIProviderManager';

export class SettingsWebviewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'codeSecurityAnalyzer.settingsView';

    private _view?: vscode.WebviewView;

    constructor(private readonly _extensionUri: vscode.Uri) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

        webviewView.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'setApiKey':
                        await this.handleSetApiKey(message.provider, message.apiKey);
                        break;
                    case 'setProvider':
                        await this.handleSetProvider(message.provider, message.model);
                        break;
                    case 'testConnection':
                        await this.handleTestConnection();
                        break;
                    case 'clearCache':
                        await this.handleClearCache();
                        break;
                    case 'loadSettings':
                        await this.sendCurrentSettings();
                        break;
                    case 'updateSetting':
                        await this.handleUpdateSetting(message.setting, message.value);
                        break;
                    case 'setCustomEndpoint':
                        await this.handleSetCustomEndpoint(message.endpoint);
                        break;
                    case 'setCustomModel':
                        await this.handleSetCustomModel(message.model);
                        break;
                    case 'setTemperature':
                        await this.handleSetTemperature(message.temperature);
                        break;
                    case 'setMaxTokens':
                        await this.handleSetMaxTokens(message.maxTokens);
                        break;
                }
            }
        );

        // Send initial settings when view is opened
        this.sendCurrentSettings();
    }

    private async handleSetApiKey(providerId: string, apiKey: string): Promise<void> {
        try {
            await AIProviderManager.setApiKey(providerId, apiKey);
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'success',
                text: `API key set for ${providerId}`
            });
            await this.sendCurrentSettings();
        } catch (error) {
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `Failed to set API key: ${error}`
            });
        }
    }

    private async handleSetProvider(providerId: string, model?: string): Promise<void> {
        try {
            await AIProviderManager.setProvider(providerId, model);
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'success',
                text: `Provider set to ${providerId}${model ? ` (${model})` : ''}`
            });
            await this.sendCurrentSettings();
        } catch (error) {
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `Failed to set provider: ${error}`
            });
        }
    }

    private async handleSetCustomEndpoint(endpoint: string): Promise<void> {
        try {
            // Validate URL format
            if (endpoint && endpoint.trim()) {
                const trimmedEndpoint = endpoint.trim();
                if (!trimmedEndpoint.startsWith('http://') && !trimmedEndpoint.startsWith('https://')) {
                    throw new Error('Endpoint must start with http:// or https://');
                }
                
                // Validate URL structure
                try {
                    new URL(trimmedEndpoint);
                } catch {
                    throw new Error('Invalid URL format. Please enter a valid HTTP/HTTPS URL.');
                }
            }
            
            await AIProviderManager.setCustomEndpoint(endpoint);
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'success',
                text: endpoint ? 'Custom endpoint updated successfully' : 'Custom endpoint cleared'
            });
            await this.sendCurrentSettings();
        } catch (error) {
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `Failed to set endpoint: ${error}`
            });
        }
    }

    private async handleSetCustomModel(model: string): Promise<void> {
        try {
            await AIProviderManager.setCustomModel(model);
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'success',
                text: 'Custom model updated'
            });
            await this.sendCurrentSettings();
        } catch (error) {
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `Failed to set model: ${error}`
            });
        }
    }

    private async handleSetTemperature(temperature: number): Promise<void> {
        try {
            if (temperature < 0 || temperature > 2) {
                throw new Error('Temperature must be between 0 and 2');
            }
            
            await AIProviderManager.setTemperature(temperature);
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'success',
                text: 'Temperature updated'
            });
            await this.sendCurrentSettings();
        } catch (error) {
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `Failed to set temperature: ${error}`
            });
        }
    }

    private async handleSetMaxTokens(maxTokens: number): Promise<void> {
        try {
            if (maxTokens < 100 || maxTokens > 8000) {
                throw new Error('Max tokens must be between 100 and 8000');
            }
            
            await AIProviderManager.setMaxTokens(maxTokens);
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'success',
                text: 'Max tokens updated'
            });
            await this.sendCurrentSettings();
        } catch (error) {
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `Failed to set max tokens: ${error}`
            });
        }
    }

    private async handleTestConnection(): Promise<void> {
        try {
            // Get current configuration
            const config = AIProviderManager.getCurrentConfig();
            
            if (!config) {
                this._view?.webview.postMessage({
                    command: 'showMessage',
                    type: 'error',
                    text: 'No AI provider configured. Please select a provider first.'
                });
                return;
            }

            // Validate configuration before testing
            if (config.provider.requiresApiKey && !config.apiKey) {
                this._view?.webview.postMessage({
                    command: 'showMessage',
                    type: 'error',
                    text: `API key required for ${config.provider.name}. Please enter your API key.`
                });
                return;
            }

            if (config.provider.id === 'custom') {
                if (!config.provider.endpoint) {
                    this._view?.webview.postMessage({
                        command: 'showMessage',
                        type: 'error',
                        text: 'Custom endpoint URL is required. Please enter your endpoint URL.'
                    });
                    return;
                }
                if (!config.model) {
                    this._view?.webview.postMessage({
                        command: 'showMessage',
                        type: 'error',
                        text: 'Model name is required for custom endpoints. Please enter a model name.'
                    });
                    return;
                }
            }

            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'info',
                text: `Testing connection to ${config.provider.name}...`
            });

            // Test with a simple message
            const testMessage = [{
                role: 'user' as const,
                content: 'Please respond with just "OK" to confirm this API connection is working.'
            }];

            const result = await AIProviderManager.makeRequest(testMessage, 10);
            const content = result.choices?.[0]?.message?.content || '';
            
            if (content.toLowerCase().includes('ok') || content.toLowerCase().includes('working')) {
                this._view?.webview.postMessage({
                    command: 'showMessage',
                    type: 'success',
                    text: `\u2705 Connection successful! ${config.provider.name} (${config.model}) is working correctly.`
                });
            } else {
                this._view?.webview.postMessage({
                    command: 'showMessage',
                    type: 'warning',
                    text: `\u26a0\ufe0f Connection established but response was unexpected: "${content}". This may still work for analysis.`
                });
            }

        } catch (error) {
            console.error('Connection test failed:', error);
            
            let errorMessage = error instanceof Error ? error.message : String(error);
            
            // Provide specific guidance based on error type
            if (errorMessage.includes('HTML instead of JSON')) {
                errorMessage += '\n\n🔧 This usually means the endpoint URL is incorrect.';
            } else if (errorMessage.includes('401')) {
                errorMessage += '\n\n🔑 Please check your API key is correct and valid.';
            } else if (errorMessage.includes('404')) {
                errorMessage += '\n\n🌐 Please verify the endpoint URL is correct.';
            } else if (errorMessage.includes('429')) {
                errorMessage += '\n\n⏱\ufe0f Rate limit exceeded. Wait a moment and try again.';
            }
            
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `\u274c Connection test failed: ${errorMessage}`
            });
        }
    }

    private async handleClearCache(): Promise<void> {
        try {
            const { SmartAIAnalyzer } = await import('../analyzers/SmartAIAnalyzer.js');
            SmartAIAnalyzer.clearCache();
            
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'success',
                text: 'Analysis cache cleared'
            });
        } catch (error) {
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `Failed to clear cache: ${error}`
            });
        }
    }

    private async handleUpdateSetting(settingKey: string, value: any): Promise<void> {
        try {
            const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
            await config.update(settingKey, value, vscode.ConfigurationTarget.Global);
            
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'success',
                text: 'Settings updated'
            });
        } catch (error) {
            this._view?.webview.postMessage({
                command: 'showMessage',
                type: 'error',
                text: `Failed to update setting: ${error}`
            });
        }
    }

    private async sendCurrentSettings(): Promise<void> {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        const providers = AIProviderManager.getProviders();
        const currentConfig = AIProviderManager.getCurrentConfig();
        
        const settings = {
            providers,
            currentProvider: currentConfig?.provider.id || 'openrouter',
            currentModel: currentConfig?.model || 'openai/gpt-4o-mini',
            hasApiKey: !!currentConfig?.apiKey,
            customEndpoint: config.get<string>('customEndpoint', ''),
            customModel: config.get<string>('customModel', ''),
            temperature: config.get<number>('temperature', 0.1),
            maxTokens: config.get<number>('maxTokens', 1500),
            requestTimeout: config.get<number>('requestTimeout', 30000),
            enableAIAnalysis: config.get<boolean>('enableAIAnalysis', true),
            enableOfflineAnalysis: config.get<boolean>('enableOfflineAnalysis', true),
            hybridMode: config.get<boolean>('hybridMode', true),
            maxFileSize: config.get<number>('maxFileSize', 10000),
            chunkSize: config.get<number>('chunkSize', 3000),
            analysisDelay: config.get<number>('analysisDelay', 2000),
            enableBestPractices: config.get<boolean>('enableBestPractices', true),
            enableComplexityAnalysis: config.get<boolean>('enableComplexityAnalysis', true),
            showProviderInSuggestions: config.get<boolean>('showProviderInSuggestions', true),
            debugMode: config.get<boolean>('debugMode', false)
        };

        this._view?.webview.postMessage({
            command: 'updateSettings',
            settings
        });
    }

    public refresh(): void {
        this.sendCurrentSettings();
    }

    private _getHtmlForWebview(_webview: vscode.Webview): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Security Analyzer Settings</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            background-color: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            padding: 16px;
            margin: 0;
        }

        .section {
            background-color: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 16px;
        }

        .section h3 {
            margin: 0 0 12px 0;
            color: var(--vscode-foreground);
            font-size: 16px;
            font-weight: 600;
        }

        .form-group {
            margin-bottom: 12px;
        }

        .form-group label {
            display: block;
            margin-bottom: 4px;
            font-weight: 500;
        }

        .form-group select,
        .form-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid var(--vscode-input-border);
            background-color: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
            border-radius: 4px;
            font-family: inherit;
            font-size: inherit;
            box-sizing: border-box;
        }

        .form-group input[type="password"] {
            font-family: monospace;
        }

        .form-group input[type="checkbox"] {
            width: auto;
            margin-right: 8px;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            margin-bottom: 8px;
        }

        .btn {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: inherit;
            margin-right: 8px;
            margin-bottom: 8px;
        }

        .btn:hover {
            background-color: var(--vscode-button-hoverBackground);
        }

        .btn.secondary {
            background-color: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }

        .btn.secondary:hover {
            background-color: var(--vscode-button-secondaryHoverBackground);
        }

        .message {
            padding: 8px 12px;
            border-radius: 4px;
            margin-bottom: 12px;
            display: none;
        }

        .message.success {
            background-color: rgba(40, 167, 69, 0.1);
            border: 1px solid rgba(40, 167, 69, 0.3);
            color: #28a745;
        }

        .message.error {
            background-color: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.3);
            color: #dc3545;
        }

        .message.info {
            background-color: rgba(23, 162, 184, 0.1);
            border: 1px solid rgba(23, 162, 184, 0.3);
            color: #17a2b8;
        }

        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .status-indicator.connected {
            background-color: #28a745;
        }

        .status-indicator.disconnected {
            background-color: #dc3545;
        }

        .status-indicator.unknown {
            background-color: #ffc107;
        }

        .provider-info {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            margin-top: 4px;
            line-height: 1.4;
        }

        .slider {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .slider input[type="range"] {
            flex: 1;
        }

        .slider-value {
            min-width: 40px;
            text-align: right;
            font-weight: 500;
        }

        .model-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 8px;
            margin-top: 8px;
        }

        .model-option {
            padding: 6px 10px;
            border: 1px solid var(--vscode-input-border);
            border-radius: 4px;
            text-align: center;
            cursor: pointer;
            font-size: 12px;
            background-color: var(--vscode-input-background);
        }

        .model-option.selected {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border-color: var(--vscode-button-background);
        }

        .model-option:hover {
            background-color: var(--vscode-list-hoverBackground);
        }

        .advanced-section {
            border-top: 1px solid var(--vscode-panel-border);
            margin-top: 16px;
            padding-top: 16px;
        }

        .description {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            margin-top: 4px;
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="message" id="message"></div>

    <div class="section">
        <h3>🤖 AI Provider Configuration</h3>
        
        <div class="form-group">
            <label for="provider">AI Provider</label>
            <select id="provider" onchange="onProviderChange()">
                <option value="openai">OpenAI (Official API)</option>
                <option value="anthropic">Anthropic Claude (Official API)</option>
                <option value="openrouter">OpenRouter (Multi-Model Proxy)</option>
                <option value="ollama">Ollama (Local Models)</option>
                <option value="custom">Custom Endpoint</option>
            </select>
            <div class="provider-info" id="providerInfo"></div>
        </div>

        <div class="form-group" id="customEndpointGroup" style="display: none;">
            <label for="customEndpoint">Custom Endpoint URL</label>
            <input type="text" id="customEndpoint" placeholder="https://your-api-endpoint.com/v1/chat/completions" onchange="onCustomEndpointChange()">
            <div class="description">Enter your custom OpenAI-compatible API endpoint</div>
        </div>

        <div class="form-group" id="customModelGroup" style="display: none;">
            <label for="customModel">Model Name</label>
            <input type="text" id="customModel" placeholder="e.g., gpt-4, claude-3-sonnet, llama-3.1-70b" onchange="onCustomModelChange()">
            <div class="description">Enter the exact model name supported by your endpoint</div>
            <div class="model-examples" style="margin-top: 8px; font-size: 12px; color: var(--vscode-descriptionForeground);">
                <strong>Examples:</strong><br>
                • OpenAI: <code>gpt-4o-mini</code>, <code>gpt-4</code><br>
                • Anthropic: <code>claude-3-5-sonnet-20241022</code><br>
                • OpenRouter: <code>openai/gpt-4o-mini</code>, <code>anthropic/claude-3-haiku</code><br>
                • Local: <code>llama3.1</code>, <code>mistral</code>
            </div>
        </div>

        <div class="form-group" id="apiKeyGroup">
            <label for="apiKey">API Key</label>
            <input type="password" id="apiKey" placeholder="Enter your API key" onchange="onApiKeyChange()">
            <div class="description" id="apiKeyDescription">Your API key is stored securely in VS Code settings</div>
            <div class="api-key-help" id="apiKeyHelp" style="display: none;">
                <small>
                    <strong>How to get your API key:</strong><br>
                    <span id="keyInstructions"></span>
                </small>
            </div>
        </div>

        <div class="form-group">
            <label>Model Selection</label>
            <div class="model-grid" id="modelGrid"></div>
        </div>

        <div style="margin-top: 16px;">
            <button class="btn" onclick="testConnection()">🔗 Test Connection</button>
            <button class="btn secondary" onclick="clearCache()">🗑️ Clear Cache</button>
        </div>

        <div style="margin-top: 12px;">
            <span class="status-indicator unknown" id="connectionStatus"></span>
            <span id="connectionText">Connection status unknown</span>
        </div>
    </div>

    <div class="section">
        <h3>⚙️ Analysis Settings</h3>
        
        <div class="checkbox-group">
            <input type="checkbox" id="enableAI" onchange="onSettingChange('enableAIAnalysis', this.checked)">
            <label for="enableAI">Enable AI-powered analysis</label>
        </div>
        
        <div class="checkbox-group">
            <input type="checkbox" id="enableOffline" onchange="onSettingChange('enableOfflineAnalysis', this.checked)">
            <label for="enableOffline">Enable offline pattern analysis</label>
        </div>
        
        <div class="checkbox-group">
            <input type="checkbox" id="hybridMode" onchange="onSettingChange('hybridMode', this.checked)">
            <label for="hybridMode">Use hybrid mode (combine offline + AI)</label>
        </div>
        
        <div class="checkbox-group">
            <input type="checkbox" id="enableBestPractices" onchange="onSettingChange('enableBestPractices', this.checked)">
            <label for="enableBestPractices">Enable best practice checks</label>
        </div>
        
        <div class="checkbox-group">
            <input type="checkbox" id="enableComplexity" onchange="onSettingChange('enableComplexityAnalysis', this.checked)">
            <label for="enableComplexity">Enable complexity analysis</label>
        </div>

        <div class="checkbox-group">
            <input type="checkbox" id="showProvider" onchange="onSettingChange('showProviderInSuggestions', this.checked)">
            <label for="showProvider">Show provider name in suggestions</label>
        </div>
        
        <div class="checkbox-group">
            <input type="checkbox" id="debugMode" onchange="onSettingChange('debugMode', this.checked)">
            <label for="debugMode">Enable debug mode (detailed error logging)</label>
        </div>
    </div>

    <div class="section">
        <h3>🤖 AI Model Settings</h3>
        
        <div class="form-group">
            <label for="temperature">Temperature (Creativity)</label>
            <div class="slider">
                <input type="range" id="temperature" min="0" max="2" step="0.1" onchange="onSliderChange('temperature', this.value)">
                <span class="slider-value" id="temperatureValue">0.1</span>
            </div>
            <div class="description">Lower = more deterministic, Higher = more creative (0-2)</div>
        </div>
        
        <div class="form-group">
            <label for="maxTokens">Maximum Response Tokens</label>
            <div class="slider">
                <input type="range" id="maxTokens" min="100" max="4000" step="100" onchange="onSliderChange('maxTokens', this.value)">
                <span class="slider-value" id="maxTokensValue">1500</span>
            </div>
            <div class="description">Maximum length of AI responses (affects cost)</div>
        </div>
        
        <div class="form-group">
            <label for="requestTimeout">Request Timeout</label>
            <div class="slider">
                <input type="range" id="requestTimeout" min="5000" max="120000" step="5000" onchange="onSliderChange('requestTimeout', this.value)">
                <span class="slider-value" id="requestTimeoutValue">30000</span>
                <span>ms</span>
            </div>
            <div class="description">How long to wait for AI responses</div>
        </div>
    </div>

    <div class="section">
        <h3>🔧 Performance Tuning</h3>
        
        <div class="form-group">
            <label for="maxFileSize">Maximum file size for AI analysis</label>
            <div class="slider">
                <input type="range" id="maxFileSize" min="1000" max="50000" step="1000" onchange="onSliderChange('maxFileSize', this.value)">
                <span class="slider-value" id="maxFileSizeValue">10000</span>
                <span>chars</span>
            </div>
            <div class="description">Files larger than this will be chunked or skipped for AI analysis</div>
        </div>
        
        <div class="form-group">
            <label for="chunkSize">Chunk size for large files</label>
            <div class="slider">
                <input type="range" id="chunkSize" min="1000" max="10000" step="500" onchange="onSliderChange('chunkSize', this.value)">
                <span class="slider-value" id="chunkSizeValue">3000</span>
                <span>chars</span>
            </div>
            <div class="description">Size of chunks when processing large files</div>
        </div>
        
        <div class="form-group">
            <label for="analysisDelay">Analysis delay after changes</label>
            <div class="slider">
                <input type="range" id="analysisDelay" min="500" max="10000" step="500" onchange="onSliderChange('analysisDelay', this.value)">
                <span class="slider-value" id="analysisDelayValue">2000</span>
                <span>ms</span>
            </div>
            <div class="description">Delay before running analysis after code changes</div>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        let currentSettings = {};

        // Load settings on startup
        window.addEventListener('load', () => {
            vscode.postMessage({ command: 'loadSettings' });
        });

        // Listen for messages from extension
        window.addEventListener('message', event => {
            const message = event.data;
            
            switch (message.command) {
                case 'updateSettings':
                    updateUI(message.settings);
                    break;
                case 'showMessage':
                    showMessage(message.type, message.text);
                    break;
            }
        });

        function updateUI(settings) {
            currentSettings = settings;
            
            // Update provider selection
            document.getElementById('provider').value = settings.currentProvider;
            updateProviderInfo();
            
            // Update model grid
            updateModelGrid();
            
            // Update custom endpoint and model
            document.getElementById('customEndpoint').value = settings.customEndpoint;
            document.getElementById('customModel').value = settings.customModel || '';
            toggleCustomEndpoint();
            
            // Update API key info
            updateApiKeyInfo();
            
            // Update checkboxes
            document.getElementById('enableAI').checked = settings.enableAIAnalysis;
            document.getElementById('enableOffline').checked = settings.enableOfflineAnalysis;
            document.getElementById('hybridMode').checked = settings.hybridMode;
            document.getElementById('enableBestPractices').checked = settings.enableBestPractices;
            document.getElementById('enableComplexity').checked = settings.enableComplexityAnalysis;
            document.getElementById('showProvider').checked = settings.showProviderInSuggestions;
            document.getElementById('debugMode').checked = settings.debugMode;
            
            // Update AI model sliders
            updateSlider('temperature', settings.temperature);
            updateSlider('maxTokens', settings.maxTokens);
            updateSlider('requestTimeout', settings.requestTimeout / 1000); // Convert to seconds for display
            
            // Update performance sliders
            updateSlider('maxFileSize', settings.maxFileSize);
            updateSlider('chunkSize', settings.chunkSize);
            updateSlider('analysisDelay', settings.analysisDelay);
            
            // Update connection status
            updateConnectionStatus(settings.hasApiKey);
        }

        function updateSlider(id, value) {
            const slider = document.getElementById(id);
            const valueSpan = document.getElementById(id + 'Value');
            slider.value = value;
            valueSpan.textContent = value;
        }

        function updateProviderInfo() {
            const providerId = document.getElementById('provider').value;
            const provider = currentSettings.providers?.find(p => p.id === providerId);
            const infoDiv = document.getElementById('providerInfo');
            
            if (provider) {
                infoDiv.textContent = provider.description || '';
            }
        }

        function updateModelGrid() {
            const providerId = document.getElementById('provider').value;
            const provider = currentSettings.providers?.find(p => p.id === providerId);
            const grid = document.getElementById('modelGrid');
            
            if (provider) {
                grid.innerHTML = '';
                provider.models.forEach(model => {
                    const option = document.createElement('div');
                    option.className = 'model-option';
                    option.textContent = model;
                    option.onclick = () => selectModel(model);
                    
                    if (model === currentSettings.currentModel) {
                        option.classList.add('selected');
                    }
                    
                    grid.appendChild(option);
                });
            }
        }

        function selectModel(model) {
            document.querySelectorAll('.model-option').forEach(opt => {
                opt.classList.remove('selected');
            });
            event.target.classList.add('selected');
            
            vscode.postMessage({
                command: 'setProvider',
                provider: document.getElementById('provider').value,
                model: model
            });
        }

        function toggleCustomEndpoint() {
            const provider = document.getElementById('provider').value;
            const endpointGroup = document.getElementById('customEndpointGroup');
            const modelGroup = document.getElementById('customModelGroup');
            const apiKeyGroup = document.getElementById('apiKeyGroup');
            
            endpointGroup.style.display = provider === 'custom' ? 'block' : 'none';
            modelGroup.style.display = provider === 'custom' ? 'block' : 'none';
            apiKeyGroup.style.display = provider === 'ollama' ? 'none' : 'block';
        }

        function updateApiKeyInfo() {
            const provider = document.getElementById('provider').value;
            const description = document.getElementById('apiKeyDescription');
            const help = document.getElementById('apiKeyHelp');
            const instructions = document.getElementById('keyInstructions');
            
            let helpText = '';
            let showHelp = false;
            
            switch (provider) {
                case 'openai':
                    helpText = '1. Go to <a href="https://platform.openai.com/api-keys" target="_blank">OpenAI API Keys</a><br>2. Create a new secret key<br>3. Copy and paste it here';
                    showHelp = true;
                    description.textContent = 'Get your OpenAI API key from platform.openai.com';
                    break;
                case 'anthropic':
                    helpText = '1. Go to <a href="https://console.anthropic.com/account/keys" target="_blank">Anthropic Console</a><br>2. Create a new API key<br>3. Copy and paste it here';
                    showHelp = true;
                    description.textContent = 'Get your Anthropic API key from console.anthropic.com';
                    break;
                case 'openrouter':
                    helpText = '1. Go to <a href="https://openrouter.ai/keys" target="_blank">OpenRouter Keys</a><br>2. Create a new API key<br>3. Copy and paste it here<br>4. Add credits to your account at <a href="https://openrouter.ai/credits" target="_blank">openrouter.ai/credits</a>';
                    showHelp = true;
                    description.textContent = 'Get your OpenRouter API key from openrouter.ai/keys';
                    break;
                case 'ollama':
                    description.textContent = 'No API key required for local Ollama models';
                    showHelp = false;
                    break;
                case 'custom':
                    helpText = '1. Enter your custom API endpoint URL above<br>2. Specify the exact model name<br>3. Enter the API key if required<br>4. Test the connection to verify';
                    description.textContent = 'Configure your custom OpenAI-compatible endpoint';
                    showHelp = true;
                    break;
            }
            
            if (showHelp) {
                instructions.innerHTML = helpText;
                help.style.display = 'block';
            } else {
                help.style.display = 'none';
            }
        }

        function onProviderChange() {
            const providerId = document.getElementById('provider').value;
            updateProviderInfo();
            updateModelGrid();
            toggleCustomEndpoint();
            updateApiKeyInfo();
            
            vscode.postMessage({
                command: 'setProvider',
                provider: providerId
            });
        }

        function onCustomModelChange() {
            const model = document.getElementById('customModel').value.trim();
            
            if (model) {
                vscode.postMessage({
                    command: 'setCustomModel',
                    model: model
                });
                
                // Also update the current model
                vscode.postMessage({
                    command: 'updateSetting',
                    setting: 'aiModel',
                    value: model
                });
            }
        }

        function onApiKeyChange() {
            const providerId = document.getElementById('provider').value;
            const apiKey = document.getElementById('apiKey').value;
            
            if (apiKey.trim()) {
                vscode.postMessage({
                    command: 'setApiKey',
                    provider: providerId,
                    apiKey: apiKey.trim()
                });
            }
        }

        function onCustomEndpointChange() {
            const endpoint = document.getElementById('customEndpoint').value;
            
            vscode.postMessage({
                command: 'setCustomEndpoint',
                endpoint: endpoint
            });
        }

        function onSettingChange(setting, value) {
            vscode.postMessage({
                command: 'updateSetting',
                setting: setting,
                value: value
            });
        }

        function onSliderChange(setting, value) {
            let displayValue = value;
            let actualValue = value;
            
            // Handle special formatting
            if (setting === 'temperature') {
                displayValue = parseFloat(value).toFixed(1);
                actualValue = parseFloat(value);
            } else if (setting === 'requestTimeout') {
                displayValue = value; // Show in seconds
                actualValue = parseInt(value) * 1000; // Store in milliseconds
            } else {
                actualValue = parseInt(value);
            }
            
            document.getElementById(setting + 'Value').textContent = displayValue;
            
            // For AI model settings, use specific handlers
            if (['temperature', 'maxTokens'].includes(setting)) {
                vscode.postMessage({
                    command: setting === 'temperature' ? 'setTemperature' : 'setMaxTokens',
                    [setting]: actualValue
                });
            } else {
                vscode.postMessage({
                    command: 'updateSetting',
                    setting: setting,
                    value: actualValue
                });
            }
        }

        function testConnection() {
            // Provide immediate feedback
            const statusIndicator = document.getElementById('connectionStatus');
            const statusText = document.getElementById('connectionText');
            
            statusIndicator.className = 'status-indicator unknown';
            statusText.textContent = 'Testing connection...';
            

            vscode.postMessage({ command: 'testConnection' });
        }

        function clearCache() {
            vscode.postMessage({ command: 'clearCache' });
        }

        function updateConnectionStatus(hasApiKey) {
            const indicator = document.getElementById('connectionStatus');
            const text = document.getElementById('connectionText');
            
            if (hasApiKey) {
                indicator.className = 'status-indicator connected';
                text.textContent = 'API key configured';
            } else {
                indicator.className = 'status-indicator disconnected';
                text.textContent = 'No API key';
            }
        }

        function showMessage(type, text) {
            const messageDiv = document.getElementById('message');
            messageDiv.className = 'message ' + type;
            messageDiv.textContent = text;
            messageDiv.style.display = 'block';
            
            setTimeout(() => {
                messageDiv.style.display = 'none';
            }, 5000);
        }
    </script>
</body>
</html>`;
    }
}