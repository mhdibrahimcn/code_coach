// This file is designed to test the AI analysis error handling
// It contains code that might trigger AI analysis but with potential API issues

function vulnerableFunction() {
    // SQL injection vulnerability
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    database.execute(query);
    
    // XSS vulnerability  
    element.innerHTML = userInput;
    
    // Hardcoded credentials
    const apiKey = "sk-test-1234567890abcdef";
    
    // Use of eval
    eval(userCode);
    
    // Weak crypto
    const hash = crypto.createHash('md5').update(data).digest('hex');
    
    return "Test data";
}

// This should trigger analysis and potentially show errors in HTML format
console.log("Testing AI analysis error handling...");