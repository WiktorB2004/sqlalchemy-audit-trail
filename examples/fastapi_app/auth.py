"""Deliberately fake authentication. Do not copy it.

Users and their plain-text passwords live in a dict, and tokens in another
dict in memory, lost on restart. Use a real identity provider. What is worth
copying is what happens once the user is known: `set_actor` records who
is calling, and the tenant becomes the scope of the request's entries.
"""

from __future__ import annotations

import secrets
from typing import Annotated, NamedTuple

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from audit_trail import Actor
from audit_trail.integrations.fastapi import set_actor


class User(NamedTuple):
    id: str  # opaque: actor_id is never scrubbed, so no e-mail here
    email: str
    password: str
    tenant_id: str
    is_admin: bool = False


USERS = {
    "ada": User("u1", "ada@acme.test", "ada-pass", "acme", is_admin=True),
    "bob": User("u2", "bob@acme.test", "bob-pass", "acme"),
    "eve": User("u3", "eve@globex.test", "eve-pass", "globex"),
}
TOKENS: dict[str, User] = {}

bearer = HTTPBearer()


def check_password(login: str, password: str) -> User | None:
    user = USERS.get(login)
    if user is None or not secrets.compare_digest(user.password, password):
        return None
    return user


def issue_token(user: User) -> str:
    token = secrets.token_urlsafe(24)
    TOKENS[token] = user
    return token


def record_user(user: User, auth_method: str) -> None:
    """Make `user` the actor, and their tenant the scope, of this request."""
    context = set_actor(
        Actor(type="user", id=user.id, label=user.email), auth_method=auth_method
    )
    # AuditContext is mutable on purpose: entries without a model scope
    # (auth.login) get the tenant from here.
    context.scope_id = user.tenant_id


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
) -> User:
    user = TOKENS.get(credentials.credentials)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown token")
    record_user(user, "bearer")
    return user


def require_admin(user: Annotated[User, Depends(current_user)]) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admins only")
    return user
