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
const userCode = req.body.code;
eval(userCode);

// Insecure HTTP endpoint
fetch('http://api.example.com/data');

// Weak cryptography

const hash = crypto.createHash('md5').update(password).digest('hex');

// Insecure random
const sessionId = Math.random().toString(36);

// Command injection
const filename = req.query.file;
exec(`cat ${filename}`, callback);

// Path traversal
const filepath = path.join(__dirname, req.params.file);
fs.readFile(filepath, callback);

// Information disclosure in logs
console.log('User password:', user.password);
