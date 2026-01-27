# Cross-Site Request Forgery (CSRF)

> Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request.

## Summary

* [How CSRF Works](#how-csrf-works)
* [CSRF Attack Examples](#csrf-attack-examples)
* [CSRF Prevention Methods](#csrf-prevention-methods)
* [CSRF Tokens](#csrf-tokens)
* [SameSite Cookies](#samesite-cookies)
* [Double Submit Cookies](#double-submit-cookies)
* [CSRF in Modern Frameworks](#csrf-in-modern-frameworks)
* [Testing for CSRF](#testing-for-csrf)
* [CSRF vs CORS](#csrf-vs-cors)
* [References](#references)

## How CSRF Works

### Attack Flow
1. User logs into `bank.com` and receives authentication cookie
2. User visits malicious site `evil.com`
3. `evil.com` contains auto-submitting form targeting `bank.com`
4. Browser automatically includes cookies for `bank.com`
5. `bank.com` processes request as legitimate user action

### Key Characteristics
- **Trust Exploitation**: Exploits the trust a site has in the user's browser
- **State-Changing**: Targets actions that change server state (POST, PUT, DELETE)
- **Invisible**: User typically unaware the attack occurred
- **Cross-Site**: Originates from a different site/domain

## CSRF Attack Examples

### Basic Form Attack
```html
<!-- Malicious site (evil.com) -->
<form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

### Image Tag Attack
```html
<!-- GET request attack -->
<img src="https://bank.com/transfer?to=attacker&amount=1000" width="0" height="0">
```

### AJAX Attack
```javascript
// Modern CSRF attack using fetch
fetch('https://bank.com/api/transfer', {
    method: 'POST',
    credentials: 'include',  // Include cookies
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        to: 'attacker',
        amount: 1000
    })
});
```

### JSON CSRF Attack
```html
<!-- Exploiting JSON endpoints -->
<form action="https://api.example.com/user/update" method="POST" enctype="text/plain">
    <input name='{"email":"attacker@evil.com","ignore":"' value='test"}' type='hidden'>
</form>
```

## CSRF Prevention Methods

### 1. CSRF Tokens (Synchronizer Token Pattern)
```python
# Django example
from django.middleware.csrf import get_token

def my_view(request):
    csrf_token = get_token(request)
    return render(request, 'template.html', {'csrf_token': csrf_token})

# In template
<form method="post">
    {% csrf_token %}
    <!-- form fields -->
</form>
```

### 2. SameSite Cookies
```python
# Flask example
from flask import Flask, make_response

app = Flask(__name__)

@app.route('/login')
def login():
    resp = make_response('Logged in')
    resp.set_cookie('session', 'abc123', samesite='Strict')
    return resp
```

### 3. Double Submit Cookies
```javascript
// Client-side implementation
function generateCSRFToken() {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Set cookie and form field
const token = generateCSRFToken();
document.cookie = `csrf_token=${token}; path=/`;
document.querySelector('input[name="csrf_token"]').value = token;
```

### 4. Custom Headers
```javascript
// JavaScript (requires preflight for CORS)
fetch('/api/data', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': 'random-token',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
});
```

## CSRF Tokens

### Token Generation
```python
import secrets
import hashlib

def generate_csrf_token():
    """Generate cryptographically secure CSRF token"""
    return secrets.token_urlsafe(32)

def generate_signed_token(user_id):
    """Generate signed token tied to user session"""
    token = secrets.token_urlsafe(32)
    signature = hashlib.sha256(f"{user_id}:{token}:secret".encode()).hexdigest()
    return f"{token}:{signature}"
```

### Token Validation
```python
def validate_csrf_token(token, user_id):
    """Validate CSRF token signature"""
    try:
        token_part, signature = token.split(':')
        expected = hashlib.sha256(f"{user_id}:{token_part}:secret".encode()).hexdigest()
        return signature == expected
    except ValueError:
        return False
```

### Token Storage
```python
# Server-side storage (Redis example)
import redis
import json

r = redis.Redis()

def store_csrf_token(user_id, token):
    """Store CSRF token with expiration"""
    key = f"csrf:{user_id}"
    r.setex(key, 3600, json.dumps({
        'token': token,
        'timestamp': time.time()
    }))

def get_csrf_token(user_id):
    """Retrieve CSRF token"""
    key = f"csrf:{user_id}"
    data = r.get(key)
    return json.loads(data) if data else None
```

## SameSite Cookies

### Cookie Attributes
```python
# Flask example with all attributes
response.set_cookie(
    'session',
    'abc123',
    samesite='Lax',  # or 'Strict' or 'None'
    secure=True,
    httponly=True,
    max_age=3600
)
```

### SameSite Values
- **Strict**: Cookie never sent with cross-site requests
- **Lax**: Cookie sent with safe cross-site requests (GET)
- **None**: Cookie sent with all cross-site requests (requires Secure)

### Browser Compatibility
```javascript
// Check SameSite support
function checkSameSiteSupport() {
    try {
        document.cookie = 'test=samesite; SameSite=Lax';
        return document.cookie.includes('test=samesite');
    } catch (e) {
        return false;
    }
}
```

## Double Submit Cookies

### Implementation
```python
# Server-side validation
def validate_double_submit_cookie(request):
    """Validate double submit cookie pattern"""
    cookie_token = request.cookies.get('csrf_token')
    form_token = request.form.get('csrf_token')
    
    if not cookie_token or not form_token:
        return False
    
    return cookie_token == form_token

# Client-side implementation
function setupDoubleSubmit() {
    const token = generateCSRFToken();
    document.cookie = `csrf_token=${token}; path=/; Secure; SameSite=Lax`;
    
    // Add to all forms
    document.querySelectorAll('form').forEach(form => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = token;
        form.appendChild(input);
    });
}
```

## CSRF in Modern Frameworks

### Django
```python
# settings.py
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_USE_SESSIONS = True

# Views
from django.views.decorators.csrf import csrf_exempt, csrf_protect

@csrf_protect
def my_view(request):
    # CSRF protected
    pass

@csrf_exempt
def api_view(request):
    # CSRF exempt (use with caution)
    pass
```

### Flask
```python
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

# Exempt specific routes
@csrf.exempt
@app.route('/api/webhook')
def webhook():
    return 'OK'

# Custom validation
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('_csrf_token', None)
        if not token or token != request.headers.get('X-CSRF-Token'):
            abort(403)
```

### Express.js
```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);

app.get('/form', (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/process', (req, res) => {
    // CSRF token automatically validated
    res.send('OK');
});
```

### Spring Boot
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringAntMatchers("/api/webhook");
        return http.build();
    }
}
```

## Testing for CSRF

### Manual Testing
```html
<!-- Test form -->
<form action="https://target.com/api/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="submit" value="Submit">
</form>

<!-- Image tag test -->
<img src="https://target.com/api/delete-account" width="0" height="0">
```

### Automated Testing
```python
# Python test script
import requests

def test_csrf_vulnerability(url, session_cookie):
    """Test for CSRF vulnerability"""
    cookies = {'session': session_cookie}
    
    # Test without CSRF token
    response = requests.post(url, data={'action': 'delete'}, cookies=cookies)
    
    # Test with invalid CSRF token
    response = requests.post(url, data={
        'action': 'delete',
        'csrf_token': 'invalid_token'
    }, cookies=cookies)
    
    return response.status_code == 200

# Burp Suite extension
# Use CSRF Scanner extension for automated testing
```

### Test Cases
```python
# Test scenarios
test_cases = [
    {
        'name': 'Missing CSRF token',
        'data': {'action': 'update'},
        'expected': 403
    },
    {
        'name': 'Invalid CSRF token',
        'data': {'action': 'update', 'csrf_token': 'invalid'},
        'expected': 403
    },
    {
        'name': 'Valid CSRF token',
        'data': {'action': 'update', 'csrf_token': 'valid_token'},
        'expected': 200
    }
]
```

## CSRF vs CORS

### Key Differences
| Aspect | CSRF | CORS |
|--------|------|------|
| **Purpose** | Prevent unwanted actions | Allow controlled cross-origin access |
| **Mechanism** | Token validation | Preflight requests + headers |
| **Scope** | State-changing requests | Read access to resources |
| **Browser Role** | Enforce same-origin policy | Enforce CORS headers |

### CORS Configuration for CSRF Protection
```python
# Flask CORS with CSRF
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
CORS(app, origins=['https://trusted-site.com'], supports_credentials=True)
csrf = CSRFProtect(app)

# Only allow specific origins
app.config['CORS_ORIGINS'] = ['https://trusted-site.com']
```

## References

* [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
* [SameSite Cookie Attribute](https://web.dev/samesite-cookies-explained/)
* [CSRF Testing Guide](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
* [Modern CSRF Protection](https://scotthelme.co.uk/csrf-is-dead/)
