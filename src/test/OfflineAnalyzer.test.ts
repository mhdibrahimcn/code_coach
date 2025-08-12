import * as assert from 'assert';
import * as vscode from 'vscode';
import { OfflineAnalyzer } from '../analyzers/OfflineAnalyzer';

suite('OfflineAnalyzer Test Suite', () => {
    vscode.window.showInformationMessage('Starting OfflineAnalyzer tests...');

    test('Should detect SQL injection vulnerabilities', async () => {
        const vulnerableCode = `
function getUser(userId) {
    const query = \`SELECT * FROM users WHERE id = \${userId}\`;
    return database.execute(query);
}`;

        const document = await vscode.workspace.openTextDocument({
            content: vulnerableCode,
            language: 'javascript'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, false);
        const sqlInjectionIssues = issues.filter(issue => 
            issue.message.toLowerCase().includes('sql') || 
            issue.description.toLowerCase().includes('injection')
        );

        assert.strictEqual(sqlInjectionIssues.length > 0, true, 'Should detect SQL injection vulnerability');
        assert.strictEqual(sqlInjectionIssues[0].type, 'vulnerability');
        assert.strictEqual(sqlInjectionIssues[0].severity, vscode.DiagnosticSeverity.Error);
    });

    test('Should detect XSS vulnerabilities', async () => {
        const vulnerableCode = `
function updateDisplay(userInput) {
    document.getElementById('content').innerHTML = userInput;
}`;

        const document = await vscode.workspace.openTextDocument({
            content: vulnerableCode,
            language: 'javascript'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, false);
        const xssIssues = issues.filter(issue => 
            issue.message.toLowerCase().includes('xss') ||
            issue.message.toLowerCase().includes('dom')
        );

        assert.strictEqual(xssIssues.length > 0, true, 'Should detect XSS vulnerability');
        assert.strictEqual(xssIssues[0].confidence >= 80, true, 'Should have high confidence');
    });

    test('Should detect weak cryptography', async () => {
        const vulnerableCode = `
const crypto = require('crypto');
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}`;

        const document = await vscode.workspace.openTextDocument({
            content: vulnerableCode,
            language: 'javascript'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, false);
        const cryptoIssues = issues.filter(issue => 
            issue.message.toLowerCase().includes('md5') ||
            issue.message.toLowerCase().includes('weak')
        );

        assert.strictEqual(cryptoIssues.length > 0, true, 'Should detect weak cryptography');
        assert.strictEqual(cryptoIssues[0].cveReference?.includes('CWE-327'), true, 'Should reference CWE-327');
    });

    test('Should detect command injection', async () => {
        const vulnerableCode = `
const { exec } = require('child_process');
function processFile(filename) {
    exec(\`cat \${filename}\`, callback);
}`;

        const document = await vscode.workspace.openTextDocument({
            content: vulnerableCode,
            language: 'javascript'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, false);
        const commandInjectionIssues = issues.filter(issue => 
            issue.message.toLowerCase().includes('command') ||
            issue.message.toLowerCase().includes('injection')
        );

        assert.strictEqual(commandInjectionIssues.length > 0, true, 'Should detect command injection');
    });

    test('Should detect best practice violations', async () => {
        const codeWithIssues = `
function authenticate(username, password) {
    console.log('Authenticating user:', username, password);
    debugger;
    try {
        // auth logic
    } catch (e) {
        // empty catch block
    }
}`;

        const document = await vscode.workspace.openTextDocument({
            content: codeWithIssues,
            language: 'javascript'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, true);
        const bestPracticeIssues = issues.filter(issue => issue.type === 'best-practice');

        assert.strictEqual(bestPracticeIssues.length >= 2, true, 'Should detect multiple best practice issues');
        
        const hasConsoleLog = bestPracticeIssues.some(issue => 
            issue.message.toLowerCase().includes('console.log'));
        const hasDebugger = bestPracticeIssues.some(issue => 
            issue.message.toLowerCase().includes('debugger'));

        assert.strictEqual(hasConsoleLog, true, 'Should detect console.log');
        assert.strictEqual(hasDebugger, true, 'Should detect debugger statement');
    });

    test('Should handle Python-specific patterns', async () => {
        const pythonCode = `
import subprocess
import os

def process_user_input(user_input):
    # Command injection vulnerability
    os.system(f"echo {user_input}")
    
    # SQL injection vulnerability  
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    
    # Debug print
    print("Processing:", user_input)
`;

        const document = await vscode.workspace.openTextDocument({
            content: pythonCode,
            language: 'python'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, true);
        
        const commandInjection = issues.filter(issue => 
            issue.message.toLowerCase().includes('command'));
        const sqlInjection = issues.filter(issue => 
            issue.message.toLowerCase().includes('sql'));
        const printStatement = issues.filter(issue => 
            issue.message.toLowerCase().includes('print'));

        assert.strictEqual(commandInjection.length > 0, true, 'Should detect Python command injection');
        assert.strictEqual(sqlInjection.length > 0, true, 'Should detect Python SQL injection');
        assert.strictEqual(printStatement.length > 0, true, 'Should detect Python print statement');
    });

    test('Should not flag secure code', async () => {
        const secureCode = `
// Secure parameterized query
function getUser(userId) {
    const query = 'SELECT * FROM users WHERE id = ?';
    return database.execute(query, [userId]);
}

// Secure DOM manipulation
function updateDisplay(userInput) {
    const element = document.getElementById('content');
    element.textContent = userInput; // Using textContent instead of innerHTML
}

// Strong cryptography
const crypto = require('crypto');
function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha256').toString('hex');
}`;

        const document = await vscode.workspace.openTextDocument({
            content: secureCode,
            language: 'javascript'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, false);
        const vulnerabilities = issues.filter(issue => issue.type === 'vulnerability');

        assert.strictEqual(vulnerabilities.length, 0, 'Should not flag secure code as vulnerable');
    });

    test('Should calculate appropriate confidence scores', async () => {
        const vulnerableCode = `
function processUserData(userInput) {
    // High confidence - clear SQL injection
    const query = \`SELECT * FROM users WHERE name = '\${userInput}'\`;
    
    // Medium confidence - potential XSS
    document.getElementById('output').innerHTML = someProcessedData;
}`;

        const document = await vscode.workspace.openTextDocument({
            content: vulnerableCode,
            language: 'javascript'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, false);
        
        // Check that confidence scores are reasonable
        for (const issue of issues) {
            assert.strictEqual(issue.confidence >= 10, true, 'Confidence should be at least 10');
            assert.strictEqual(issue.confidence <= 100, true, 'Confidence should not exceed 100');
        }

        // SQL injection should have high confidence
        const sqlIssue = issues.find(issue => issue.message.toLowerCase().includes('sql'));
        if (sqlIssue) {
            assert.strictEqual(sqlIssue.confidence >= 80, true, 'SQL injection should have high confidence');
        }
    });

    test('Should provide appropriate suggestions', async () => {
        const vulnerableCode = `
function unsafeFunction(userInput) {
    eval(userInput);
}`;

        const document = await vscode.workspace.openTextDocument({
            content: vulnerableCode,
            language: 'javascript'
        });

        const issues = await OfflineAnalyzer.analyzeDocument(document, false);
        const evalIssue = issues.find(issue => issue.message.toLowerCase().includes('eval'));

        assert.strictEqual(evalIssue !== undefined, true, 'Should detect eval usage');
        assert.strictEqual(evalIssue?.suggestion && evalIssue.suggestion.length > 10, true, 'Should provide meaningful suggestion');
        assert.strictEqual(evalIssue?.suggestion && evalIssue.suggestion.toLowerCase().includes('avoid'), true, 'Should suggest avoiding eval');
    });
});