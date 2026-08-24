"""
Authentication Module — GovLLM-Sentinel
=======================================

JWT-based authentication for API endpoints.

VULN-B002 fix: Implement authentication for all sensitive endpoints.

Usage:
    from auth import verify_token, create_token, get_current_user
    
    @app.get("/protected")
    async def protected_endpoint(user: dict = Depends(verify_token)):
        return {"message": f"Hello {user['username']}"}

Environment Variables:
    JWT_SECRET: Secret key for JWT signing (required in production)
    JWT_ALGORITHM: Algorithm for JWT (default: HS256)
    JWT_EXPIRY_MINUTES: Token expiry time (default: 60)
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import os
import hashlib
import secrets


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

ENV = os.getenv("ENV", "development")

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

# Generate secret for development if not provided
if not JWT_SECRET and ENV == "development":
    JWT_SECRET = secrets.token_hex(32)
    print(f"⚠️  Generated development JWT secret: {JWT_SECRET[:8]}...")
elif not JWT_SECRET and ENV == "production":
    raise ValueError("JWT_SECRET environment variable is required in production")


# ═══════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════

class TokenRequest(BaseModel):
    """Request for token generation."""
    username: str
    password: str

class TokenResponse(BaseModel):
    """Response with JWT token."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]

class User(BaseModel):
    """User model."""
    username: str
    role: str = "viewer"
    permissions: list = []


# ═══════════════════════════════════════════════════════════════════
# SIMULATED USER DATABASE (Replace with real DB in production)
# ═══════════════════════════════════════════════════════════════════

# Default users (passwords are hashed)
USERS_DB = {
    "admin": {
        "username": "admin",
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "admin",
        "permissions": ["read", "write", "redteam", "admin"]
    },
    "analyst": {
        "username": "analyst",
        "password_hash": hashlib.sha256("analyst123".encode()).hexdigest(),
        "role": "analyst",
        "permissions": ["read", "write"]
    },
    "viewer": {
        "username": "viewer",
        "password_hash": hashlib.sha256("viewer123".encode()).hexdigest(),
        "role": "viewer",
        "permissions": ["read"]
    }
}


# ═══════════════════════════════════════════════════════════════════
# JWT FUNCTIONS (Simple implementation without python-jose)
# ═══════════════════════════════════════════════════════════════════

def create_token(user: Dict[str, Any], expires_minutes: int = None) -> str:
    """Create a JWT token.
    
    Args:
        user: User data to encode in token
        expires_minutes: Token expiry time
        
    Returns:
        JWT token string
    """
    if expires_minutes is None:
        expires_minutes = JWT_EXPIRY_MINUTES
    
    # Create payload
    payload = {
        "sub": user["username"],
        "role": user.get("role", "viewer"),
        "permissions": user.get("permissions", []),
        "iat": datetime.utcnow().timestamp(),
        "exp": (datetime.utcnow() + timedelta(minutes=expires_minutes)).timestamp(),
        "iss": "govllm-sentinel"
    }
    
    # Simple JWT encoding (base64 + signature)
    import json
    import base64
    
    def base64url_encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    
    # Header
    header = {"alg": "HS256", "typ": "JWT"}
    header_encoded = base64url_encode(json.dumps(header).encode())
    
    # Payload
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    
    # Signature
    message = f"{header_encoded}.{payload_encoded}"
    signature = hashlib.sha256(
        (message + JWT_SECRET).encode()
    ).digest()
    signature_encoded = base64url_encode(signature)
    
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and verify a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded payload
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    import json
    import base64
    
    def base64url_decode(data):
        # Add padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)
    
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )
        
        header_encoded, payload_encoded, signature_encoded = parts
        
        # Verify signature
        message = f"{header_encoded}.{payload_encoded}"
        expected_signature = hashlib.sha256(
            (message + JWT_SECRET).encode()
        ).digest()
        
        actual_signature = base64url_decode(signature_encoded)
        
        if expected_signature != actual_signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature"
            )
        
        # Decode payload
        payload = json.loads(base64url_decode(payload_encoded))
        
        # Check expiration
        if datetime.utcnow().timestamp() > payload.get("exp", 0):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired"
            )
        
        return payload
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


# ═══════════════════════════════════════════════════════════════════
# AUTHENTICATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate user with username and password.
    
    Args:
        username: Username
        password: Plain text password
        
    Returns:
        User dict if authenticated, None otherwise
    """
    user = USERS_DB.get(username)
    if not user:
        return None
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user["password_hash"] != password_hash:
        return None
    
    return {
        "username": user["username"],
        "role": user["role"],
        "permissions": user["permissions"]
    }


# Security scheme
security = HTTPBearer()


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token from Authorization header.
    
    VULN-B002 fix: Protect endpoints with authentication.
    
    Usage:
        @app.get("/protected")
        async def protected(user: dict = Depends(verify_token)):
            return {"user": user}
    """
    token = credentials.credentials
    payload = decode_token(token)
    
    return {
        "username": payload.get("sub"),
        "role": payload.get("role", "viewer"),
        "permissions": payload.get("permissions", [])
    }


def require_permission(permission: str):
    """Dependency factory for permission checking.
    
    Usage:
        @app.get("/redteam")
        async def redteam(user = Depends(require_permission("redteam"))):
            ...
    """
    async def check_permission(user: dict = Depends(verify_token)):
        if permission not in user.get("permissions", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        return user
    return check_permission


# ═══════════════════════════════════════════════════════════════════
# PUBLIC USER FUNCTIONS (for testing/development)
# ═══════════════════════════════════════════════════════════════════

def get_public_users():
    """Get list of available users (for testing only)."""
    return [
        {"username": u["username"], "role": u["role"]}
        for u in USERS_DB.values()
    ]
