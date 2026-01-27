"""
Authentication service
"""
import logging
from typing import Optional
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user
from core.models import User, db

logger = logging.getLogger(__name__)

class AuthService:
    """Authentication service"""
    
    def create_user(self, username: str, email: str, password: str) -> Optional[User]:
        """Create a new user"""
        try:
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                logger.warning(f"Username already exists: {username}")
                return None
            
            if User.query.filter_by(email=email).first():
                logger.warning(f"Email already exists: {email}")
                return None
            
            # Create new user
            user = User()
            user.username = username
            user.email = email
            user.password_hash = generate_password_hash(password)
            
            db.session.add(user)
            db.session.commit()
            
            logger.info(f"User created successfully: {username}")
            return user
            
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            db.session.rollback()
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        try:
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                logger.info(f"User authenticated successfully: {username}")
                return user
            
            logger.warning(f"Authentication failed for user: {username}")
            return None
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
    
    def login(self, user: User) -> bool:
        """Login user"""
        try:
            login_user(user)
            logger.info(f"User logged in: {user.username}")
            return True
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def logout(self) -> bool:
        """Logout current user"""
        try:
            logout_user()
            logger.info("User logged out")
            return True
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        try:
            return User.query.get(user_id)
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
            return None

# Global instance
_auth_service = None

def get_auth_service() -> AuthService:
    """Get global auth service instance"""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
