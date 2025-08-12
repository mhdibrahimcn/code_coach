import * as vscode from 'vscode';

export interface AIProvider {
    id: string;
    name: string;
    endpoint: string;
    models: string[];
    requiresApiKey: boolean;
    defaultModel: string;
    description?: string;
    authType?: 'bearer' | 'api-key' | 'custom';
    headers?: Record<string, string>;
    customModelSupport?: boolean;
}

export interface AIProviderConfig {
    provider: AIProvider;
    apiKey: string;
    model: string;
    customEndpoint?: string;
    customModel?: string;
    temperature?: number;
    maxTokens?: number;
    timeout?: number;
}

export class AIProviderManager {
    private static readonly PROVIDERS: AIProvider[] = [
        {
            id: 'openai',
            name: 'OpenAI',
            endpoint: 'https://api.openai.com/v1/chat/completions',
            models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo', 'gpt-3.5-turbo-16k'],
            requiresApiKey: true,
            defaultModel: 'gpt-4o-mini',
            description: 'Official OpenAI API with GPT models',
            authType: 'bearer'
        },
        {
            id: 'anthropic',
            name: 'Anthropic Claude',
            endpoint: 'https://api.anthropic.com/v1/messages',
            models: ['claude-3-5-sonnet-20241022', 'claude-3-haiku-20240307', 'claude-3-sonnet-20240229', 'claude-3-opus-20240229'],
            requiresApiKey: true,
            defaultModel: 'claude-3-5-sonnet-20241022',
            description: 'Anthropic Claude models via official API',
            authType: 'api-key',
            headers: {
                'anthropic-version': '2023-06-01'
            }
        },
        {
            id: 'openrouter',
            name: 'OpenRouter',
            endpoint: 'https://openrouter.ai/api/v1/chat/completions',
            models: [
                'openai/gpt-4o-mini',
                'openai/gpt-4o',
                'openai/gpt-4-turbo',
                'anthropic/claude-3.5-sonnet',
                'anthropic/claude-3-haiku',
                'meta-llama/llama-3.1-8b-instruct:free',
                'meta-llama/llama-3.1-70b-instruct',
                'google/gemini-pro-1.5',
                'mistralai/mistral-7b-instruct',
                'qwen/qwen-2.5-72b-instruct',
                'openai/gpt-3.5-turbo',
                'microsoft/wizardlm-2-8x22b',
                'nousresearch/hermes-3-llama-3.1-405b:free'
            ],
            requiresApiKey: true,
            defaultModel: 'openai/gpt-4o-mini',
            description: 'Access to multiple AI models through OpenRouter',
            authType: 'bearer',
            headers: {
                'HTTP-Referer': 'https://github.com/conceptmates/code-coach',
                'X-Title': 'Code Security Analyzer'
            }
        },
        {
            id: 'ollama',
            name: 'Ollama (Local)',
            endpoint: 'http://localhost:11434/api/chat',
            models: ['llama3.1', 'codellama', 'mistral', 'gemma', 'qwen2.5'],
            requiresApiKey: false,
            defaultModel: 'llama3.1',
            description: 'Local Ollama models (no API key required)',
            authType: 'custom'
        },
        {
            id: 'custom',
            name: 'Custom Endpoint',
            endpoint: '',
            models: [],
            requiresApiKey: true,
            defaultModel: '',
            description: 'Custom OpenAI-compatible API endpoint',
            authType: 'bearer',
            customModelSupport: true
        }
    ];

    public static getProviders(): AIProvider[] {
        return [...this.PROVIDERS];
    }

    public static getProvider(id: string): AIProvider | undefined {
        return this.PROVIDERS.find(p => p.id === id);
    }

    public static getCurrentConfig(): AIProviderConfig | null {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        const providerId = config.get<string>('aiProvider', 'openrouter');
        const model = config.get<string>('aiModel', 'openai/gpt-4o-mini');
        const apiKeys = config.get<Record<string, string>>('apiKeys', {});
        const customEndpoint = config.get<string>('customEndpoint', '');
        const customModel = config.get<string>('customModel', '');
        const temperature = config.get<number>('temperature', 0.1);
        const maxTokens = config.get<number>('maxTokens', 1500);
        const timeout = config.get<number>('requestTimeout', 30000);

        const provider = this.getProvider(providerId);
        if (!provider) {
            return null;
        }

        const apiKey = apiKeys[providerId] || '';
        
        let finalProvider = { ...provider };
        let finalModel = model;
        
        if (providerId === 'custom') {
            finalProvider.endpoint = customEndpoint;
            if (customModel) {
                finalProvider.models = [customModel];
                finalProvider.defaultModel = customModel;
                finalModel = customModel;
            }
        }

        return {
            provider: finalProvider,
            apiKey,
            model: finalModel,
            customEndpoint,
            customModel,
            temperature,
            maxTokens,
            timeout
        };
    }

    public static async setApiKey(providerId: string, apiKey: string): Promise<void> {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        const apiKeys = config.get<Record<string, string>>('apiKeys', {});
        
        apiKeys[providerId] = apiKey;
        
        await config.update('apiKeys', apiKeys, vscode.ConfigurationTarget.Global);
    }

    public static async setProvider(providerId: string, model?: string): Promise<void> {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        const provider = this.getProvider(providerId);
        
        if (!provider) {
            throw new Error(`Unknown provider: ${providerId}`);
        }

        await config.update('aiProvider', providerId, vscode.ConfigurationTarget.Global);
        
        if (model && provider.models.includes(model)) {
            await config.update('aiModel', model, vscode.ConfigurationTarget.Global);
        } else {
            await config.update('aiModel', provider.defaultModel, vscode.ConfigurationTarget.Global);
        }
    }

    public static async setCustomEndpoint(endpoint: string): Promise<void> {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        await config.update('customEndpoint', endpoint, vscode.ConfigurationTarget.Global);
    }

    public static async setCustomModel(model: string): Promise<void> {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        await config.update('customModel', model, vscode.ConfigurationTarget.Global);
    }

    public static async setTemperature(temperature: number): Promise<void> {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        await config.update('temperature', temperature, vscode.ConfigurationTarget.Global);
    }

    public static async setMaxTokens(maxTokens: number): Promise<void> {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        await config.update('maxTokens', maxTokens, vscode.ConfigurationTarget.Global);
    }

    public static hasValidConfig(): boolean {
        const config = this.getCurrentConfig();
        if (!config) {
            return false;
        }

        // Check if provider requires API key and we have one
        if (config.provider.requiresApiKey && !config.apiKey) {
            return false;
        }

        // Check if custom endpoint is provided when using custom provider
        if (config.provider.id === 'custom' && !config.customEndpoint) {
            return false;
        }

        return true;
    }

    public static getStatusText(): string {
        const config = this.getCurrentConfig();
        if (!config) {
            return '❌ No AI Provider';
        }

        const hasKey = config.apiKey ? '✅' : '❌';
        return `${hasKey} ${config.provider.name} (${config.model})`;
    }

    public static async makeRequest(messages: any[], maxTokens?: number): Promise<any> {
        const config = this.getCurrentConfig();
        if (!config) {
            throw new Error('No AI provider configured. Please configure an AI provider in settings.');
        }

        if (config.provider.requiresApiKey && !config.apiKey) {
            throw new Error(`No API key configured for ${config.provider.name}. Please add your API key in settings.`);
        }

        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'User-Agent': 'Code-Security-Analyzer/2.0'
        };

        // Add provider-specific headers
        if (config.provider.headers) {
            Object.assign(headers, config.provider.headers);
        }

        // Set authorization header based on auth type
        if (config.provider.requiresApiKey && config.apiKey) {
            if (config.provider.authType === 'bearer' || !config.provider.authType) {
                headers['Authorization'] = `Bearer ${config.apiKey}`;
            } else if (config.provider.authType === 'api-key') {
                headers['x-api-key'] = config.apiKey;
            }
        }
        
        // Validate endpoint for custom providers
        if (config.provider.id === 'custom') {
            if (!config.provider.endpoint) {
                throw new Error('Custom endpoint URL is required. Please configure the endpoint in settings.');
            }
            if (!config.provider.endpoint.startsWith('http')) {
                throw new Error('Custom endpoint must be a valid HTTP/HTTPS URL');
            }
            if (!config.model || config.model.trim() === '') {
                throw new Error('Model name is required for custom endpoints. Please specify a model in settings.');
            }
        }

        // Normalize endpoint: append /chat/completions if needed for OpenAI-compatible endpoints
        let endpoint = config.provider.endpoint;
        if (config.provider.id === 'custom') {
            const lower = endpoint.toLowerCase();
            const looksLikeOpenAICompatibleBase = /\/v1\/?$/.test(endpoint) && !/anthropic\.com/.test(lower);
            const isOpenRouter = lower.includes('openrouter.ai');
            const missingChat = !/\/chat\/completions/.test(lower) && !/\/messages/.test(lower);
            if ((looksLikeOpenAICompatibleBase || isOpenRouter) && missingChat) {
                endpoint = endpoint.replace(/\/+$/, '') + '/chat/completions';
            }

            // Add OpenRouter ranking headers if using OpenRouter via custom endpoint
            if (isOpenRouter) {
                headers['HTTP-Referer'] = headers['HTTP-Referer'] || 'https://github.com/conceptmates/code-coach';
                headers['X-Title'] = headers['X-Title'] || 'Code Security Analyzer';
            }
        }

        let requestBody: any;
        
        if (config.provider.id === 'anthropic') {
            // Anthropic uses a different message format
            requestBody = {
                model: config.model,
                max_tokens: maxTokens || config.maxTokens || 1500,
                temperature: config.temperature || 0.1,
                messages: messages.map(msg => ({
                    role: msg.role === 'system' ? 'user' : msg.role,
                    content: msg.role === 'system' ? `System: ${msg.content}` : msg.content
                }))
            };
        } else if (config.provider.id === 'ollama') {
            // Ollama uses a different format
            requestBody = {
                model: config.model,
                messages,
                stream: false,
                options: {
                    temperature: config.temperature || 0.1,
                    num_predict: maxTokens || config.maxTokens || 1500
                }
            };
        } else {
            // OpenAI-compatible format
            requestBody = {
                model: config.model,
                messages,
                max_tokens: maxTokens || config.maxTokens || 1500,
                temperature: config.temperature || 0.1,
                top_p: 0.9
            };
        }

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), config.timeout || 30000);
            
            console.log(`🚀 Making request to: ${endpoint}`);
            console.log(`📝 Request headers:`, headers);
            console.log(`📦 Request body:`, JSON.stringify(requestBody, null, 2));
            
            const response = await fetch(endpoint, {
                method: 'POST',
                headers,
                body: JSON.stringify(requestBody),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            console.log(`📡 Response status: ${response.status} ${response.statusText}`);
            console.log(`📡 Response headers:`, Object.fromEntries(response.headers.entries()));

            if (!response.ok) {
                const errorText = await response.text();
                console.error(`❌ Error response body:`, errorText);
                
                let errorMessage = `AI API Error (${response.status} ${response.statusText})`;
                
                // Check if response is HTML (common when endpoint is wrong)
                if (errorText.trim().startsWith('<!DOCTYPE') || errorText.trim().startsWith('<html')) {
                    errorMessage = `Invalid endpoint - received HTML instead of JSON. Check your endpoint URL: ${endpoint}`;
                    if (/openrouter\.ai/.test(endpoint)) {
                        errorMessage += `\n\nHint: For OpenRouter, use https://openrouter.ai/api/v1/chat/completions`; 
                    } else if (/api\.openai\.com/.test(endpoint)) {
                        errorMessage += `\n\nHint: For OpenAI, use https://api.openai.com/v1/chat/completions`;
                    }
                } else {
                    try {
                        const errorJson = JSON.parse(errorText);
                        if (errorJson.error?.message) {
                            errorMessage += `: ${errorJson.error.message}`;
                        } else if (errorJson.message) {
                            errorMessage += `: ${errorJson.message}`;
                        } else if (errorJson.detail) {
                            errorMessage += `: ${errorJson.detail}`;
                        }
                    } catch {
                        if (errorText.length < 200) {
                            errorMessage += `: ${errorText}`;
                        }
                    }
                }
                
                // Add specific error handling for common issues
                if (response.status === 401) {
                    errorMessage += '\n\n🔑 Solution: Check your API key is valid and has sufficient credits';
                } else if (response.status === 403) {
                    errorMessage += '\n\n🔑 Solution: Verify your API key has access to the requested model';
                } else if (response.status === 404) {
                    errorMessage += `\n\n🌐 Solution: Verify the endpoint URL is correct: ${endpoint}`;
                } else if (response.status === 422) {
                    errorMessage += `\n\n📝 Solution: Check if the model name is correct: ${config.model}`;
                } else if (response.status === 429) {
                    errorMessage += '\n\n⏱️ Solution: Wait 1-2 minutes and try again, or upgrade your API plan';
                } else if (response.status === 500) {
                    errorMessage += '\n\n🔧 Solution: The AI service is experiencing issues, try again later';
                } else if (response.status === 503) {
                    errorMessage += '\n\n⚠️ Solution: Service is temporarily unavailable, try again in a few minutes';
                }
                
                throw new Error(errorMessage);
            }

            const responseText = await response.text();
            console.log(`📥 Raw response:`, responseText.substring(0, 500) + (responseText.length > 500 ? '...' : ''));
            
            let result;
            try {
                result = JSON.parse(responseText);
            } catch (parseError) {
                console.error(`❌ JSON Parse Error:`, parseError);
                if (responseText.trim().startsWith('<!DOCTYPE') || responseText.trim().startsWith('<html')) {
                    throw new Error(`Received HTML instead of JSON from ${endpoint}. This usually means:\n\n` +
                        `🌐 The endpoint URL is incorrect\n` +
                        `🔑 Authentication headers are missing or wrong\n` +
                        `📝 The request format doesn't match what the server expects\n\n` +
                        `Please verify your endpoint URL and model configuration.`);
                }
                throw new Error(`Invalid JSON response from AI provider: ${parseError}`);
            }
            
            // Validate response format
            if (!result) {
                throw new Error('Empty response from AI provider');
            }
            
            // Handle different response formats
            if (config.provider.id === 'anthropic') {
                const anthropicResult = result as { content?: Array<{ text?: string }> };
                if (!anthropicResult.content || !Array.isArray(anthropicResult.content)) {
                    throw new Error('Invalid response format from Anthropic API');
                }
                // Convert to OpenAI-compatible format
                return {
                    choices: [{
                        message: {
                            content: anthropicResult.content[0]?.text || '',
                            role: 'assistant'
                        }
                    }]
                };
            } else if (config.provider.id === 'ollama') {
                const ollamaResult = result as { message?: { content?: string } };
                if (!ollamaResult.message) {
                    throw new Error('Invalid response format from Ollama API');
                }
                // Convert to OpenAI-compatible format
                return {
                    choices: [{
                        message: {
                            content: ollamaResult.message.content || '',
                            role: 'assistant'
                        }
                    }]
                };
            } else {
                // OpenAI-compatible format
                const openAIResult = result as { choices?: Array<any> };
                if (!openAIResult.choices || !Array.isArray(openAIResult.choices) || openAIResult.choices.length === 0) {
                    throw new Error('Invalid response format - no choices returned');
                }
            }
            
            return result;
            
        } catch (error) {
            if (error instanceof Error) {
                if (error.name === 'AbortError') {
                    throw new Error(`Request timeout after ${(config.timeout || 30000) / 1000} seconds`);
                }
                throw error;
            }
            throw new Error(`Unknown error occurred: ${String(error)}`);
        }
    }
}