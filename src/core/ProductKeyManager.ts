import * as vscode from 'vscode';
import * as crypto from 'crypto';

export class ProductKeyManager {
    private static readonly HARDCODED_PRODUCT_KEY = 'CSA-2025-PROD-KEY-9B8F-E71C-A3D2-4F89';
    private static readonly STORAGE_KEY = 'codeSecurityAnalyzer.productKey';
    private static readonly ACTIVATION_TIMESTAMP_KEY = 'codeSecurityAnalyzer.activationTimestamp';
    
    constructor(private context: vscode.ExtensionContext) {}

    /**
     * Validates the provided product key against the hardcoded key
     */
    public validateProductKey(key: string): boolean {
        if (!key || typeof key !== 'string') {
            return false;
        }
        
        const normalizedKey = this.normalizeProductKey(key);
        const expectedKey = this.normalizeProductKey(ProductKeyManager.HARDCODED_PRODUCT_KEY);
        
        // Primary validation - exact match with hardcoded key
        return normalizedKey === expectedKey;
    }

    /**
     * Checks if the extension is currently activated with a valid product key
     */
    public async isActivated(): Promise<boolean> {
        const storedKey = await this.getStoredProductKey();
        if (!storedKey) {
            return false;
        }
        
        return this.validateProductKey(storedKey);
    }

    /**
     * Activates the extension with the provided product key
     */
    public async activateWithKey(key: string): Promise<boolean> {
        const trimmedKey = key.trim();
        
        if (!this.validateProductKey(trimmedKey)) {
            console.log('Product key validation failed for key:', this.maskProductKey(trimmedKey));
            return false;
        }

        try {
            // Store the product key
            await this.context.globalState.update(ProductKeyManager.STORAGE_KEY, trimmedKey);
            await this.context.globalState.update(ProductKeyManager.ACTIVATION_TIMESTAMP_KEY, Date.now());
            
            console.log('Product key activated successfully');
            return true;
        } catch (error) {
            console.error('Failed to store product key:', error);
            vscode.window.showErrorMessage('Failed to activate extension. Please try again.');
            return false;
        }
    }

    /**
     * Deactivates the extension by removing the stored product key
     */
    public async deactivate(): Promise<void> {
        await this.context.globalState.update(ProductKeyManager.STORAGE_KEY, undefined);
        await this.context.globalState.update(ProductKeyManager.ACTIVATION_TIMESTAMP_KEY, undefined);
        
        vscode.window.showInformationMessage('Code Security Analyzer has been deactivated.');
    }

    /**
     * Shows the product key activation dialog
     */
    public async showActivationDialog(): Promise<boolean> {
        const key = await vscode.window.showInputBox({
            prompt: 'Enter your Code Security Analyzer product key',
            password: false,
            placeHolder: 'CSA-2025-PROD-KEY-9B8F-E71C-A3D2-4F89',
            ignoreFocusOut: true,
            title: 'Product Key Activation',
            validateInput: (value: string) => {
                if (!value || value.trim().length === 0) {
                    return 'Product key cannot be empty';
                }
                const trimmedValue = value.trim();
                if (trimmedValue.length < 10) {
                    return 'Product key is too short';
                }
                if (!this.isValidKeyFormat(trimmedValue)) {
                    return 'Invalid product key format. Expected format: CSA-2025-PROD-KEY-9B8F-E71C-A3D2-4F89';
                }
                return undefined;
            }
        });

        if (!key || key.trim().length === 0) {
            return false;
        }

        return await this.activateWithKey(key.trim());
    }

    /**
     * Gets the stored product key from global state
     */
    private async getStoredProductKey(): Promise<string | undefined> {
        return this.context.globalState.get(ProductKeyManager.STORAGE_KEY);
    }

    /**
     * Normalizes the product key by removing spaces and converting to uppercase
     */
    private normalizeProductKey(key: string): string {
        return key.replace(/\s/g, '').toUpperCase();
    }

    /**
     * Checks if the key follows the expected format
     */
    private isValidKeyFormat(key: string): boolean {
        const normalizedKey = this.normalizeProductKey(key);
        // Expected format: CSA-2025-PROD-KEY-9B8F-E71C-A3D2-4F89 (flexible segment lengths)
        const keyPattern = /^CSA-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+$/;
        return keyPattern.test(normalizedKey);
    }


    /**
     * Returns activation information
     */
    public async getActivationInfo(): Promise<{
        isActivated: boolean;
        activationTimestamp?: number;
        productKey?: string;
    }> {
        const isActivated = await this.isActivated();
        const activationTimestamp = this.context.globalState.get<number>(ProductKeyManager.ACTIVATION_TIMESTAMP_KEY);
        const productKey = isActivated ? await this.getStoredProductKey() : undefined;
        
        return {
            isActivated,
            activationTimestamp,
            productKey: productKey ? this.maskProductKey(productKey) : undefined
        };
    }

    /**
     * Masks the product key for display purposes
     */
    private maskProductKey(key: string): string {
        const normalizedKey = this.normalizeProductKey(key);
        if (normalizedKey.length < 8) {
            return '*'.repeat(normalizedKey.length);
        }
        
        const firstPart = normalizedKey.substring(0, 4);
        const lastPart = normalizedKey.substring(normalizedKey.length - 4);
        const middlePart = '*'.repeat(normalizedKey.length - 8);
        
        return `${firstPart}${middlePart}${lastPart}`;
    }

    /**
     * Generates a trial period check (could be extended for trial functionality)
     */
    public async isTrialPeriodActive(): Promise<boolean> {
        // For now, return false as we're using product key authentication
        // This could be extended to support trial periods
        return false;
    }

    /**
     * Quick authentication check - throws error if not authenticated
     */
    public async requireAuthentication(): Promise<void> {
        const isActivated = await this.isActivated();
        if (!isActivated) {
            throw new Error('Extension not authenticated. Product key required.');
        }
    }

    /**
     * Silent authentication check - returns boolean without throwing
     */
    public async isAuthenticated(): Promise<boolean> {
        try {
            await this.requireAuthentication();
            return true;
        } catch {
            return false;
        }
    }
}