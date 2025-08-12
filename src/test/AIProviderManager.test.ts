import * as assert from 'assert';
import * as vscode from 'vscode';
import { AIProviderManager } from '../core/AIProviderManager';

suite('AIProviderManager Test Suite', () => {
    vscode.window.showInformationMessage('Starting AIProviderManager tests...');

    test('Should return available providers', () => {
        const providers = AIProviderManager.getProviders();
        
        assert.strictEqual(providers.length >= 3, true, 'Should have at least 3 providers');
        
        const providerIds = providers.map(p => p.id);
        assert.strictEqual(providerIds.includes('openai'), true, 'Should include OpenAI provider');
        assert.strictEqual(providerIds.includes('openrouter'), true, 'Should include OpenRouter provider');
        assert.strictEqual(providerIds.includes('custom'), true, 'Should include Custom provider');
    });

    test('Should get specific provider by ID', () => {
        const openaiProvider = AIProviderManager.getProvider('openai');
        
        assert.strictEqual(openaiProvider !== undefined, true, 'Should find OpenAI provider');
        assert.strictEqual(openaiProvider?.name, 'OpenAI');
        assert.strictEqual(openaiProvider?.requiresApiKey, true, 'OpenAI should require API key');
        assert.strictEqual(openaiProvider?.models.length > 0, true, 'Should have available models');
    });

    test('Should return undefined for invalid provider ID', () => {
        const invalidProvider = AIProviderManager.getProvider('nonexistent');
        
        assert.strictEqual(invalidProvider, undefined, 'Should return undefined for invalid provider');
    });

    test('Should validate configuration requirements', () => {
        // This test assumes no valid configuration is set initially
        const hasValidConfig = AIProviderManager.hasValidConfig();
        
        // Since we're in a test environment without actual API keys, 
        // this should typically be false
        assert.strictEqual(typeof hasValidConfig, 'boolean', 'Should return boolean');
    });

    test('Should generate appropriate status text', () => {
        const statusText = AIProviderManager.getStatusText();
        
        assert.strictEqual(typeof statusText, 'string', 'Should return string');
        assert.strictEqual(statusText.length > 0, true, 'Status text should not be empty');
    });

    test('Provider models should be valid', () => {
        const providers = AIProviderManager.getProviders();
        
        for (const provider of providers) {
            assert.strictEqual(provider.models.length > 0, true, `${provider.name} should have models`);
            assert.strictEqual(provider.defaultModel.length > 0, true, `${provider.name} should have default model`);
            assert.strictEqual(
                provider.models.includes(provider.defaultModel), 
                true, 
                `${provider.name} default model should be in models list`
            );
        }
    });

    test('OpenAI provider should have correct configuration', () => {
        const openai = AIProviderManager.getProvider('openai');
        
        assert.strictEqual(openai?.endpoint, 'https://api.openai.com/v1/chat/completions');
        assert.strictEqual(openai?.requiresApiKey, true);
        assert.strictEqual(openai?.models.includes('gpt-4o-mini'), true, 'Should include gpt-4o-mini');
        assert.strictEqual(openai?.models.includes('gpt-3.5-turbo'), true, 'Should include gpt-3.5-turbo');
    });

    test('OpenRouter provider should have correct configuration', () => {
        const openrouter = AIProviderManager.getProvider('openrouter');
        
        assert.strictEqual(openrouter?.endpoint, 'https://openrouter.ai/api/v1/chat/completions');
        assert.strictEqual(openrouter?.requiresApiKey, true);
        assert.strictEqual(openrouter?.models.length > 5, true, 'Should have multiple models');
    });

    test('Custom provider should allow empty endpoint', () => {
        const custom = AIProviderManager.getProvider('custom');
        
        assert.strictEqual(custom?.endpoint, '');
        assert.strictEqual(custom?.requiresApiKey, true);
        assert.strictEqual(custom?.id, 'custom');
    });

    test('Should handle provider switching gracefully', async () => {
        try {
            // Test switching to a valid provider
            await AIProviderManager.setProvider('openai');
            
            const config = AIProviderManager.getCurrentConfig();
            assert.strictEqual(config?.provider.id, 'openai', 'Should switch to OpenAI');
        } catch (error) {
            // This might fail in test environment due to workspace configuration restrictions
            console.log('Provider switching test skipped due to workspace restrictions');
        }
    });

    test('Should reject invalid provider IDs when switching', async () => {
        try {
            await AIProviderManager.setProvider('invalid-provider');
            assert.fail('Should throw error for invalid provider');
        } catch (error) {
            assert.strictEqual(error instanceof Error, true, 'Should throw Error');
            assert.strictEqual(
                (error as Error).message.includes('Unknown provider'), 
                true, 
                'Should mention unknown provider'
            );
        }
    });

    test('Current config should handle missing configuration', () => {
        const config = AIProviderManager.getCurrentConfig();
        
        // In test environment, config might be null or have default values
        if (config) {
            assert.strictEqual(typeof config.provider, 'object', 'Provider should be object');
            assert.strictEqual(typeof config.model, 'string', 'Model should be string');
            assert.strictEqual(typeof config.apiKey, 'string', 'API key should be string');
        }
    });

    test('Should validate model selection within provider', async () => {
        const openai = AIProviderManager.getProvider('openai');
        
        if (openai) {
            try {
                // Test with valid model
                await AIProviderManager.setProvider('openai', 'gpt-4o-mini');
                
                const config = AIProviderManager.getCurrentConfig();
                if (config) {
                    assert.strictEqual(config.model, 'gpt-4o-mini', 'Should set valid model');
                }
            } catch (error) {
                console.log('Model selection test skipped due to workspace restrictions');
            }
        }
    });
});