// Test file to demonstrate AI analysis with basic fallback
// This file contains intentional security vulnerabilities for testing

// SQL Injection vulnerabilities - should be caught by basic analysis
function getUserData(userId) {
    // This will be caught by basic pattern analysis if AI fails
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return database.execute(query);
}

function searchUsers(searchTerm) {
    // String concatenation SQL injection
    const sql = "SELECT * FROM users WHERE name = '" + searchTerm + "'";
    return db.query(sql);
}

// XSS vulnerabilities - should be caught by basic analysis
function displayUserMessage(userInput) {
    // XSS through innerHTML
    document.getElementById('message').innerHTML = userInput;
    
    // Another XSS pattern
    document.write("Hello " + userInput);
}

// Hardcoded credentials - should be caught by basic analysis
const DATABASE_PASSWORD = "mysecretpassword123";
const API_KEY = "sk-1234567890abcdef";
const secret_token = "very_secret_token_here";

// Dangerous functions - should be caught by basic analysis
function executeCode(userCode) {
    // Dangerous eval usage
    return eval(userCode);
}

// Insecure network - should be caught by basic analysis
const apiEndpoint = "http://api.example.com/data";
fetch("http://insecure-api.com/endpoint");

// Weak cryptography - should be caught by basic analysis
const crypto = require('crypto');
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

function generateRandomId() {
    // Insecure random generation
    return Math.random().toString(36);
}

// Command injection - should be caught by basic analysis
function runCommand(userInput) {
    const { exec } = require('child_process');
    exec(`ls ${userInput}`, (error, stdout) => {
        console.log(stdout);
    });
}

// Path traversal - should be caught by basic analysis
function readUserFile(filename) {
    const fs = require('fs');
    return fs.readFile(filename, 'utf8');
}

// This should test both AI and fallback scenarios
console.log("Security test file ready for analysis");
