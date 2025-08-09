// Test file with various security vulnerabilities for AI fix suggestions

// SQL Injection vulnerability - should trigger vulnerability detection
function getUser(userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return database.execute(query);
}

// XSS vulnerability - should trigger vulnerability detection
function updateDisplay(userInput) {
    document.getElementById('content').innerHTML = userInput;
}

// Hardcoded credentials - should trigger vulnerability detection
const API_KEY = process.env.API_KEY;

// Use of eval - should trigger vulnerability detection
function processCode(code) {
}

// Weak cryptography - should trigger warning
const crypto = require('crypto');
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// Math.random for security - should trigger warning
function generateToken() {
    return Math.random().toString(36).substring(2);
}

// Console.log in production - should trigger best practice warning
function authenticate(username, password) {
    console.log(`Authenticating user: ${username} with password: ${password}`);
    // authentication logic
}

// Another SQL injection example
function searchUsers(searchTerm) {
    return db.query("SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'");
}

// Another XSS example
function displayMessage(message) {
    document.write(message);
}