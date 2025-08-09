// Test file for debugging the security analyzer extension
// This file contains intentional security vulnerabilities for testing

// SQL Injection vulnerability
function getUser(userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return database.execute(query);
}

// XSS vulnerability
function displayMessage(userInput) {
    document.getElementById('message').innerHTML = userInput;
}

// Hardcoded API key
const API_KEY = "sk-1234567890abcdef";

// Insecure random generation
function generateToken() {
    return Math.random().toString(36);
}

// Weak cryptography
const crypto = require('crypto');
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// HTTP instead of HTTPS
const apiUrl = "http://api.example.com/data";

// Use of eval()
function processData(code) {
    return eval(code);
}
