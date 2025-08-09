// Sample JavaScript file with security vulnerabilities for testing

// SQL Injection vulnerability
const userId = req.params.id;
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.execute(query);

// XSS vulnerability
const userComment = req.body.comment;
document.getElementById('comments').innerHTML = userComment;

// Hardcoded API key
const apiKey = "sk-1234567890bcdef1234567890abcdef";

// Unsafe eval usage

// Validate and sanitize user input
const userCode = req.body.code;
if (typeof userCode !== 'string') {
  throw new Error('Invalid input: code must be a string');
}
// Use a sandboxed environment if code execution is absolutely required
// Consider alternative approaches like function whitelistinguserCode);

// Insecure HTTP endpoint
fetch('http://api.example.com/data');

// Weak cryptography

const hash = crypto.createHash('md5').update(password).digest('hex');

// Insecure random
const sessionId = Math.random().toString(36);

// Command injection
const filename = require('path').basename(req.query.file);
exec(`cat ${filename}`, callback);

// Path traversal
const filepath = path.join(__dirname, req.params.file);
fs.readFile(filepath, callback);

// Information disclosure in logs
console.log('User password:', user.password);
