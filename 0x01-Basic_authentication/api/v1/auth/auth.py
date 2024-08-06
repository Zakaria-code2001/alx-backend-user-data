#!/usr/bin/env python3
"""
Class to manage
the API authentication
"""
from flask import request
from typing import List, TypeVar


class Auth():
    """
    Authorization Class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        eturns False - path
        """
        return False

    def authorization_header(self, request=None) -> str:
        """
        returns None - request
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        returns None - request
        """
        return None
