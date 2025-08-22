import * as vscode from 'vscode';

export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3
}

export class DebugLogger {
    private static instance: DebugLogger;
    private outputChannel: vscode.LogOutputChannel;
    private enabled: boolean = false;
    private logLevel: LogLevel = LogLevel.INFO;

    private constructor() {
        this.outputChannel = vscode.window.createOutputChannel('Code Security Analyzer', { log: true });
        this.updateSettings();
    }

    public static getInstance(): DebugLogger {
        if (!DebugLogger.instance) {
            DebugLogger.instance = new DebugLogger();
        }
        return DebugLogger.instance;
    }

    public updateSettings(): void {
        const config = vscode.workspace.getConfiguration('codeSecurityAnalyzer');
        this.enabled = config.get<boolean>('debugMode', false);
        const level = config.get<string>('logLevel', 'info');
        
        switch (level.toLowerCase()) {
            case 'debug': this.logLevel = LogLevel.DEBUG; break;
            case 'info': this.logLevel = LogLevel.INFO; break;
            case 'warn': this.logLevel = LogLevel.WARN; break;
            case 'error': this.logLevel = LogLevel.ERROR; break;
            default: this.logLevel = LogLevel.INFO;
        }
    }

    public debug(message: string, data?: any): void {
        if (this.shouldLog(LogLevel.DEBUG)) {
            this.outputChannel.debug(this.formatMessage(message, data));
        }
    }

    public info(message: string, data?: any): void {
        if (this.shouldLog(LogLevel.INFO)) {
            this.outputChannel.info(this.formatMessage(message, data));
        }
    }

    public warn(message: string, data?: any): void {
        if (this.shouldLog(LogLevel.WARN)) {
            this.outputChannel.warn(this.formatMessage(message, data));
        }
    }

    public error(message: string, error?: any): void {
        if (this.shouldLog(LogLevel.ERROR)) {
            const errorMsg = error instanceof Error ? error.stack || error.message : JSON.stringify(error);
            this.outputChannel.error(this.formatMessage(message, errorMsg));
        }
    }

    public logAnalysisStart(document: vscode.TextDocument, analysisType: string): void {
        this.info(`🚀 Starting ${analysisType} analysis`, {
            file: document.fileName,
            language: document.languageId,
            size: document.getText().length,
            lines: document.lineCount
        });
    }

    public logAnalysisEnd(document: vscode.TextDocument, analysisType: string, duration: number, issuesFound: number): void {
        this.info(`✅ Completed ${analysisType} analysis`, {
            file: document.fileName,
            duration: `${duration}ms`,
            issuesFound,
            performance: duration < 5000 ? 'Fast' : duration < 15000 ? 'Normal' : 'Slow'
        });
    }

    public logFunctionAnalysis(functionName: string, startLine: number, endLine: number, vulnerabilities: number): void {
        this.debug(`🔍 Function analysis: ${functionName}`, {
            lines: `${startLine}-${endLine}`,
            vulnerabilities,
            linesOfCode: endLine - startLine + 1
        });
    }

    public logAIRequest(provider: string, model: string, promptLength: number): void {
        this.debug(`🤖 AI Request`, {
            provider,
            model,
            promptLength,
            timestamp: new Date().toISOString()
        });
    }

    public logAIResponse(provider: string, responseLength: number, tokensUsed?: number): void {
        this.debug(`📤 AI Response`, {
            provider,
            responseLength,
            tokensUsed: tokensUsed || 'unknown',
            timestamp: new Date().toISOString()
        });
    }

    public logError(operation: string, error: any, context?: any): void {
        this.error(`❌ Error in ${operation}`, {
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
            context
        });
    }

    public logPerformanceMetric(operation: string, duration: number, metadata?: any): void {
        this.debug(`⏱️ Performance: ${operation}`, {
            duration: `${duration}ms`,
            ...metadata
        });
    }

    public show(): void {
        this.outputChannel.show();
    }

    public dispose(): void {
        this.outputChannel.dispose();
    }

    private shouldLog(level: LogLevel): boolean {
        return this.enabled && level >= this.logLevel;
    }

    private formatMessage(message: string, data?: any): string {
        if (!data) {
            return message;
        }
        
        if (typeof data === 'string') {
            return `${message} - ${data}`;
        }
        
        try {
            return `${message} - ${JSON.stringify(data, null, 2)}`;
        } catch (error) {
            return `${message} - [Unserializable data]`;
        }
    }
}

// Convenience functions for global use
export const logger = DebugLogger.getInstance();
export const debug = (message: string, data?: any) => logger.debug(message, data);
export const info = (message: string, data?: any) => logger.info(message, data);
export const warn = (message: string, data?: any) => logger.warn(message, data);
export const error = (message: string, error?: any) => logger.error(message, error);