# 🔧 OpenRouter Integration Fix Guide

## 🚨 **Error**: "Unexpected token '<', "<!DOCTYPE "... is not valid JSON"

This error indicates that OpenRouter is returning HTML instead of JSON, which happens when the request is malformed or authentication is incorrect.

---

## ✅ **Solution: Proper OpenRouter Configuration**

### **Step 1: Use OpenRouter Provider (Not Custom)**

**❌ Wrong Configuration:**
```json
{
  "aiProvider": "custom",
  "customEndpoint": "https://openrouter.ai/api/v1/chat/completions",
  "customModel": "openai/gpt-oss-20b:free"
}
```

**✅ Correct Configuration:**
```json
{
  "aiProvider": "openrouter", 
  "aiModel": "openai/gpt-4o-mini"
}
```

### **Step 2: Model Format for OpenRouter**

OpenRouter requires the **full model path** format:

**✅ Correct Model Names:**
- `openai/gpt-4o-mini` (recommended - fast & cheap)
- `openai/gpt-4o` 
- `anthropic/claude-3-haiku`
- `meta-llama/llama-3.1-8b-instruct:free` (free tier)

**❌ Wrong Format:**
- `gpt-4o-mini` (missing provider prefix)
- `claude-3-haiku` (missing provider prefix)

### **Step 3: Required Headers**

OpenRouter needs specific headers that our extension now handles automatically:

```javascript
{
  "Authorization": "Bearer your-openrouter-api-key",
  "HTTP-Referer": "https://github.com/conceptmates/code-coach",
  "X-Title": "Code Security Analyzer",
  "Content-Type": "application/json"
}
```

---

## 🎯 **How to Configure in the Extension**

### **Method 1: Settings Panel (Recommended)**

1. **Open Settings**: Click the shield icon in status bar
2. **Select Provider**: Choose "OpenRouter (Multi-Model Proxy)" 
3. **Enter API Key**: Get from [openrouter.ai/keys](https://openrouter.ai/keys)
4. **Choose Model**: Select from the model grid (e.g., `openai/gpt-4o-mini`)
5. **Test Connection**: Click "Test Connection" to verify

### **Method 2: VS Code Settings**

```json
{
  "codeSecurityAnalyzer.aiProvider": "openrouter",
  "codeSecurityAnalyzer.aiModel": "openai/gpt-4o-mini",
  "codeSecurityAnalyzer.apiKeys": {
    "openrouter": "your-api-key-here"
  }
}
```

### **Method 3: Command Palette**

1. `Ctrl+Shift+P` → "Code Security Analyzer: Configure API Key"
2. Select "OpenRouter"
3. Enter your API key

---

## 🆓 **Free Models on OpenRouter**

If you want to use free models:

```json
{
  "aiProvider": "openrouter",
  "aiModel": "meta-llama/llama-3.1-8b-instruct:free"
}
```

**Available Free Models:**
- `meta-llama/llama-3.1-8b-instruct:free`
- `nousresearch/hermes-3-llama-3.1-405b:free`
- `microsoft/phi-3-mini-128k-instruct:free`

---

## 🔍 **Debugging Steps**

### **1. Enable Debug Mode**
```json
{
  "codeSecurityAnalyzer.debugMode": true
}
```

### **2. Check Console Output**
- Open VS Code Developer Console: `Help` → `Toggle Developer Tools`
- Look for detailed request/response logs

### **3. Test with cURL**
```bash
curl -X POST "https://openrouter.ai/api/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "HTTP-Referer: https://github.com/conceptmates/code-coach" \
  -H "X-Title: Code Security Analyzer" \
  -d '{
    "model": "openai/gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

### **4. Validate Your API Key**
- Go to [openrouter.ai/activity](https://openrouter.ai/activity)
- Check if your key is valid and has credits
- Verify key permissions

---

## 🚨 **Common Issues & Solutions**

### **Issue 1: "HTML instead of JSON"**
**Cause**: Wrong endpoint or missing authentication
**Solution**: Use OpenRouter provider, not custom endpoint

### **Issue 2: "Model not found" (404)**
**Cause**: Incorrect model name format
**Solution**: Use full model path like `openai/gpt-4o-mini`

### **Issue 3: "Unauthorized" (401)**
**Cause**: Invalid or missing API key
**Solution**: Check API key from [openrouter.ai/keys](https://openrouter.ai/keys)

### **Issue 4: "Insufficient credits" (402)**
**Cause**: No credits in OpenRouter account
**Solution**: Add credits at [openrouter.ai/credits](https://openrouter.ai/credits)

### **Issue 5: "Rate limit exceeded" (429)**
**Cause**: Too many requests
**Solution**: Wait 1-2 minutes, or upgrade plan

---

## 🎯 **Recommended Configuration**

For **best performance and cost**:

```json
{
  "codeSecurityAnalyzer.aiProvider": "openrouter",
  "codeSecurityAnalyzer.aiModel": "openai/gpt-4o-mini",
  "codeSecurityAnalyzer.temperature": 0.1,
  "codeSecurityAnalyzer.maxTokens": 1500,
  "codeSecurityAnalyzer.hybridMode": true
}
```

This gives you:
- ✅ High accuracy for security analysis
- ✅ Low cost (~$0.15 per 1M tokens)
- ✅ Fast response times
- ✅ Reliable uptime

---

## 🧪 **Test Your Configuration**

1. **Open any JavaScript file** with the test vulnerabilities
2. **Look for analysis results** in CodeLens above functions
3. **Check status bar** for provider confirmation
4. **Try "Get AI Fix"** on any detected issue

If you see results, your OpenRouter integration is working perfectly! 🎉

---

## 📞 **Still Having Issues?**

1. **Enable debug mode** and check console logs
2. **Test connection** in settings panel
3. **Try a different model** (e.g., `anthropic/claude-3-haiku`)
4. **Verify OpenRouter account status** at [openrouter.ai](https://openrouter.ai)

The extension now provides detailed error messages and guidance for every failure scenario!