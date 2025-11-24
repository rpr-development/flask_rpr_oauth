#!/usr/bin/env python
"""
Quick test script voor flask-rpr-oauth package
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask_rpr_oauth import (
    RPRAuth,
    OAuthUser,
    current_user,
    login_required,
    permission_required,
    any_permission_required,
    group_required,
    any_group_required,
    OAuthError,
    TokenExpiredError,
    PermissionDeniedError,
)


def test_imports():
    """Test dat alle imports werken."""
    print("✓ Alle imports succesvol")


def test_user_model():
    """Test OAuthUser model."""
    user = OAuthUser(
        oauth_id="test-123",
        email="test@example.com",
        voornaam="Test",
        achternaam="User",
        permissions=["read", "write"],
        groups=["users"],
    )

    assert user.oauth_id == "test-123"
    assert user.email == "test@example.com"
    assert user.has_permission("read")
    assert user.in_group("users")
    assert not user.has_permission("admin")
    assert not user.in_group("admins")

    print("✓ OAuthUser model werkt correct")


def test_permissions():
    """Test permission checks."""
    user = OAuthUser(
        oauth_id="test-123", email="test@example.com", permissions=["read", "write", "delete"]
    )

    assert user.has_permission("read")
    assert user.has_any_permission("read", "admin")
    assert not user.has_any_permission("admin", "create")

    print("✓ Permission checks werken correct")


def test_groups():
    """Test group checks."""
    user = OAuthUser(oauth_id="test-123", email="test@example.com", groups=["users", "moderators"])

    assert user.in_group("users")
    assert user.in_any_group("users", "admins")
    assert not user.in_any_group("admins", "staff")

    print("✓ Group checks werken correct")


def test_exceptions():
    """Test custom exceptions."""
    try:
        raise OAuthError("Test error")
    except OAuthError as e:
        assert e.status_code == 401

    try:
        raise TokenExpiredError()
    except TokenExpiredError as e:
        assert e.status_code == 401

    try:
        raise PermissionDeniedError(permission="test.admin")
    except PermissionDeniedError as e:
        assert e.status_code == 403
        assert e.permission == "test.admin"

    print("✓ Custom exceptions werken correct")


def main():
    """Run alle tests."""
    print("=" * 50)
    print("Flask RPR OAuth - Package Tests")
    print("=" * 50)
    print()

    try:
        test_imports()
        test_user_model()
        test_permissions()
        test_groups()
        test_exceptions()

        print()
        print("=" * 50)
        print("✓ Alle tests geslaagd!")
        print("=" * 50)
        return 0

    except AssertionError as e:
        print()
        print("=" * 50)
        print(f"✗ Test failed: {e}")
        print("=" * 50)
        return 1

    except Exception as e:
        print()
        print("=" * 50)
        print(f"✗ Error: {e}")
        print("=" * 50)
        return 1


if __name__ == "__main__":
    sys.exit(main())
