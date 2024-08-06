#!/usr/bin/env python3
"""
Class to manage
the API authentication
"""
from flask import request
from typing import List, TypeVar
import os
import fnmatch


class Auth():
    """
    Authorization Class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        eturns False - path
        """
        if path is None:
            return True

        if excluded_paths is None or not excluded_paths:
            return True

        normalized_path = path if path.endswith('/') else path + '/'

        for excluded_path in excluded_paths:
            if normalized_path.startswith(excluded_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        returns None - request
        """
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None

        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        returns None - request
        """
        return None
