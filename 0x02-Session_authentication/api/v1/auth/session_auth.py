#!/usr/bin/env python3
""" Module of Basic Authentication
"""
from api.v1.auth.auth import Auth
import base64

from typing import TypeVar
from models.user import User
import uuid

class SessionAuth(Auth):
    """
    session
    """
    user_id_by_session_id = {}
    
    def create_session(self, user_id: str = None) -> str:
        """
        session id
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id
    
    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        return user id
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        user_id = self.user_id_by_session_id.get(session_id)
        return user_id