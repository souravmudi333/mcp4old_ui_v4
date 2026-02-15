# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/routers/tokens.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

JWT Token Catalog API endpoints.
Provides comprehensive API token management with scoping, revocation, and analytics.
"""

# Standard
from typing import Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import (
    TokenCreateRequest,
    TokenCreateResponse,
    TokenListResponse,
    TokenResponse,
    TokenRevokeRequest,
    TokenUsageStatsResponse,
)
from mcpgateway.services.token_catalog_service import TokenCatalogService, TokenScope

router = APIRouter(prefix="/tokens", tags=["tokens"])


def _none_if_blank(value: Optional[str]) -> Optional[str]:
    """Convert empty/whitespace strings to None (prevents FK violations)."""
    if value is None:
        return None
    value = str(value).strip()
    return value if value else None


def _clean_list(values: Optional[list]) -> list:
    """Remove empty strings from list inputs coming from UI/schema defaults."""
    if not values:
        return []
    cleaned = []
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            cleaned.append(s)
    return cleaned


def _to_scope(request_scope) -> Optional[TokenScope]:
    """Convert request.scope to TokenScope safely (sanitize UI defaults)."""
    if not request_scope:
        return None
    return TokenScope(
        server_id=_none_if_blank(request_scope.server_id),
        permissions=_clean_list(request_scope.permissions),
        ip_restrictions=_clean_list(request_scope.ip_restrictions),
        time_restrictions=request_scope.time_restrictions or {},
        usage_limits=request_scope.usage_limits or {},
    )


# ============================================================
# Personal Tokens (User)
# ============================================================

@router.post("", response_model=TokenCreateResponse, status_code=status.HTTP_201_CREATED)
@require_permission("tokens.create")
async def create_token(
    request: TokenCreateRequest,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenCreateResponse:
    """Create a new API token for the current user.

    NOTE:
        This route creates PERSONAL tokens only.
        team_id from payload (if any) is ignored to avoid accidental team-scoped inserts.
    """
    service = TokenCatalogService(db)
    scope = _to_scope(request.scope)

    try:
        # IMPORTANT: Personal token route => always team_id=None
        token_record, raw_token = await service.create_token(
            user_email=current_user["email"],
            name=request.name,
            description=request.description,
            scope=scope,
            expires_in_days=request.expires_in_days,
            tags=request.tags,
            team_id=None,
        )

        token_response = TokenResponse(
            id=token_record.id,
            name=token_record.name,
            description=token_record.description,
            user_email=token_record.user_email,
            team_id=token_record.team_id,
            server_id=token_record.server_id,
            resource_scopes=token_record.resource_scopes or [],
            ip_restrictions=token_record.ip_restrictions or [],
            time_restrictions=token_record.time_restrictions or {},
            usage_limits=token_record.usage_limits or {},
            created_at=token_record.created_at,
            expires_at=token_record.expires_at,
            last_used=token_record.last_used,
            is_active=token_record.is_active,
            tags=token_record.tags or [],
        )

        return TokenCreateResponse(token=token_response, access_token=raw_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("", response_model=TokenListResponse)
@require_permission("tokens.read")
async def list_tokens(
    include_inactive: bool = False,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user_with_permissions),
) -> TokenListResponse:
    """List PERSONAL API tokens for the current user."""
    service = TokenCatalogService(db)
    tokens = await service.list_user_tokens(
        user_email=current_user["email"],
        include_inactive=include_inactive,
        limit=limit,
        offset=offset,
    )

    token_responses = []
    for token in tokens:
        revocation_info = await service.get_token_revocation(token.jti)

        token_responses.append(
            TokenResponse(
                id=token.id,
                name=token.name,
                description=token.description,
                user_email=token.user_email,
                team_id=token.team_id,
                created_at=token.created_at,
                expires_at=token.expires_at,
                last_used=token.last_used,
                is_active=token.is_active,
                is_revoked=revocation_info is not None,
                revoked_at=revocation_info.revoked_at if revocation_info else None,
                revoked_by=revocation_info.revoked_by if revocation_info else None,
                revocation_reason=revocation_info.reason if revocation_info else None,
                tags=token.tags,
                server_id=token.server_id,
                resource_scopes=token.resource_scopes,
                ip_restrictions=token.ip_restrictions,
                time_restrictions=token.time_restrictions,
                usage_limits=token.usage_limits,
            )
        )

    return TokenListResponse(tokens=token_responses, total=len(token_responses), limit=limit, offset=offset)


@router.get("/{token_id}", response_model=TokenResponse)
@require_permission("tokens.read")
async def get_token(
    token_id: str,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Get details of a specific PERSONAL token (owner only)."""
    service = TokenCatalogService(db)
    token = await service.get_token(token_id, current_user["email"])

    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    return TokenResponse(
        id=token.id,
        name=token.name,
        description=token.description,
        user_email=token.user_email,
        team_id=token.team_id,
        created_at=token.created_at,
        expires_at=token.expires_at,
        last_used=token.last_used,
        is_active=token.is_active,
        tags=token.tags,
        server_id=token.server_id,
        resource_scopes=token.resource_scopes,
        ip_restrictions=token.ip_restrictions,
        time_restrictions=token.time_restrictions,
        usage_limits=token.usage_limits,
    )


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permission("tokens.revoke")
async def revoke_token(
    token_id: str,
    request: Optional[TokenRevokeRequest] = None,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> None:
    """Revoke (delete) a PERSONAL token (owner only)."""
    service = TokenCatalogService(db)

    # Enforce ownership by lookup first (prevents deleting other user's token_id)
    token = await service.get_token(token_id, current_user["email"])
    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    reason = request.reason if request else "Revoked by user"
    success = await service.revoke_token(token_id=token_id, revoked_by=current_user["email"], reason=reason)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")


@router.get("/{token_id}/usage", response_model=TokenUsageStatsResponse)
@require_permission("tokens.usage")
async def get_token_usage_stats(
    token_id: str,
    days: int = 30,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenUsageStatsResponse:
    """Get usage statistics for a specific PERSONAL token (owner only)."""
    service = TokenCatalogService(db)

    token = await service.get_token(token_id, current_user["email"])
    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    stats = await service.get_token_usage_stats(user_email=current_user["email"], token_id=token_id, days=days)
    return TokenUsageStatsResponse(**stats)


# ============================================================
# Team Tokens (User / Owner-only, enforced by service)
# ============================================================

@router.post("/teams/{team_id}", response_model=TokenCreateResponse, status_code=status.HTTP_201_CREATED)
@require_permission("tokens.team.create")
async def create_team_token(
    team_id: str,
    request: TokenCreateRequest,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenCreateResponse:
    """Create a new API token for a team (only team owners can do this)."""
    service = TokenCatalogService(db)
    scope = _to_scope(request.scope)

    try:
        token_record, raw_token = await service.create_token(
            user_email=current_user["email"],
            name=request.name,
            description=request.description,
            scope=scope,
            expires_in_days=request.expires_in_days,
            tags=request.tags,
            team_id=team_id,
        )

        token_response = TokenResponse(
            id=token_record.id,
            name=token_record.name,
            description=token_record.description,
            user_email=token_record.user_email,
            team_id=token_record.team_id,
            server_id=token_record.server_id,
            resource_scopes=token_record.resource_scopes or [],
            ip_restrictions=token_record.ip_restrictions or [],
            time_restrictions=token_record.time_restrictions or {},
            usage_limits=token_record.usage_limits or {},
            created_at=token_record.created_at,
            expires_at=token_record.expires_at,
            last_used=token_record.last_used,
            is_active=token_record.is_active,
            tags=token_record.tags or [],
        )

        return TokenCreateResponse(token=token_response, access_token=raw_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/teams/{team_id}", response_model=TokenListResponse)
@require_permission("tokens.team.read")
async def list_team_tokens(
    team_id: str,
    include_inactive: bool = False,
    limit: int = 50,
    offset: int = 0,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenListResponse:
    """List API tokens for a team (only team owners can do this)."""
    service = TokenCatalogService(db)

    try:
        tokens = await service.list_team_tokens(
            team_id=team_id,
            user_email=current_user["email"],
            include_inactive=include_inactive,
            limit=limit,
            offset=offset,
        )
    except ValueError as e:
        # Service returns "Only team owners..." -> keep behavior stable
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    token_responses = []
    for token in tokens:
        revocation_info = await service.get_token_revocation(token.jti)
        token_responses.append(
            TokenResponse(
                id=token.id,
                name=token.name,
                description=token.description,
                user_email=token.user_email,
                team_id=token.team_id,
                created_at=token.created_at,
                expires_at=token.expires_at,
                last_used=token.last_used,
                is_active=token.is_active,
                is_revoked=revocation_info is not None,
                revoked_at=revocation_info.revoked_at if revocation_info else None,
                revoked_by=revocation_info.revoked_by if revocation_info else None,
                revocation_reason=revocation_info.reason if revocation_info else None,
                tags=token.tags,
                server_id=token.server_id,
                resource_scopes=token.resource_scopes,
                ip_restrictions=token.ip_restrictions,
                time_restrictions=token.time_restrictions,
                usage_limits=token.usage_limits,
            )
        )

    return TokenListResponse(tokens=token_responses, total=len(token_responses), limit=limit, offset=offset)


# ============================================================
# Admin Personal Tokens (see/manage everyone’s personal tokens)
# ============================================================

@router.get("/admin/personal", response_model=TokenListResponse, tags=["admin"])
@require_permission("tokens.admin.read")
async def admin_list_personal_tokens(
    user_email: Optional[str] = None,
    include_inactive: bool = False,
    limit: int = 100,
    offset: int = 0,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenListResponse:
    """Admin: list personal tokens (team_id is NULL) for all users, optionally filter by user_email."""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    service = TokenCatalogService(db)

    tokens = await service.list_all_tokens(
        include_inactive=include_inactive,
        limit=limit,
        offset=offset,
        user_email=user_email,
        team_id=None,  # personal only
    )

    token_responses = []
    for token in tokens:
        revocation_info = await service.get_token_revocation(token.jti)
        token_responses.append(
            TokenResponse(
                id=token.id,
                name=token.name,
                description=token.description,
                user_email=token.user_email,
                team_id=token.team_id,
                created_at=token.created_at,
                expires_at=token.expires_at,
                last_used=token.last_used,
                is_active=token.is_active,
                is_revoked=revocation_info is not None,
                revoked_at=revocation_info.revoked_at if revocation_info else None,
                revoked_by=revocation_info.revoked_by if revocation_info else None,
                revocation_reason=revocation_info.reason if revocation_info else None,
                tags=token.tags,
                server_id=token.server_id,
                resource_scopes=token.resource_scopes,
                ip_restrictions=token.ip_restrictions,
                time_restrictions=token.time_restrictions,
                usage_limits=token.usage_limits,
            )
        )

    return TokenListResponse(tokens=token_responses, total=len(token_responses), limit=limit, offset=offset)


@router.get("/admin/{token_id}", response_model=TokenResponse, tags=["admin"])
@require_permission("tokens.admin.read")
async def admin_get_token(
    token_id: str,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Admin: get details of ANY token (personal or team)."""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    service = TokenCatalogService(db)
    token = await service.get_token(token_id)  # no user filter

    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    return TokenResponse(
        id=token.id,
        name=token.name,
        description=token.description,
        user_email=token.user_email,
        team_id=token.team_id,
        created_at=token.created_at,
        expires_at=token.expires_at,
        last_used=token.last_used,
        is_active=token.is_active,
        tags=token.tags,
        server_id=token.server_id,
        resource_scopes=token.resource_scopes,
        ip_restrictions=token.ip_restrictions,
        time_restrictions=token.time_restrictions,
        usage_limits=token.usage_limits,
    )


@router.get("/admin/{token_id}/usage", response_model=TokenUsageStatsResponse, tags=["admin"])
@require_permission("tokens.admin.usage")
async def admin_get_token_usage_stats(
    token_id: str,
    days: int = 30,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenUsageStatsResponse:
    """Admin: usage stats for ANY token."""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    service = TokenCatalogService(db)

    token = await service.get_token(token_id)  # no user filter
    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    stats = await service.get_token_usage_stats(user_email=token.user_email, token_id=token_id, days=days)
    return TokenUsageStatsResponse(**stats)


@router.delete("/admin/{token_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["admin"])
@require_permission("tokens.admin.revoke")
async def admin_revoke_token(
    token_id: str,
    request: Optional[TokenRevokeRequest] = None,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> None:
    """Admin endpoint to revoke any token."""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    service = TokenCatalogService(db)
    admin_email = current_user["email"]
    reason = request.reason if request else f"Revoked by admin {admin_email}"

    success = await service.revoke_token(token_id=token_id, revoked_by=admin_email, reason=reason)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")


# ============================================================
# Admin Team Tokens (manage tokens for ANY team)
# ============================================================

@router.get("/admin/teams/{team_id}", response_model=TokenListResponse, tags=["admin"])
@require_permission("tokens.admin.team.read")
async def admin_list_team_tokens(
    team_id: str,
    include_inactive: bool = False,
    limit: int = 100,
    offset: int = 0,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenListResponse:
    """Admin: list tokens for ANY team (no membership/owner requirement)."""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    service = TokenCatalogService(db)

    tokens = await service.list_all_tokens(
        include_inactive=include_inactive,
        limit=limit,
        offset=offset,
        team_id=team_id,
    )

    token_responses = []
    for token in tokens:
        revocation_info = await service.get_token_revocation(token.jti)
        token_responses.append(
            TokenResponse(
                id=token.id,
                name=token.name,
                description=token.description,
                user_email=token.user_email,
                team_id=token.team_id,
                created_at=token.created_at,
                expires_at=token.expires_at,
                last_used=token.last_used,
                is_active=token.is_active,
                is_revoked=revocation_info is not None,
                revoked_at=revocation_info.revoked_at if revocation_info else None,
                revoked_by=revocation_info.revoked_by if revocation_info else None,
                revocation_reason=revocation_info.reason if revocation_info else None,
                tags=token.tags,
                server_id=token.server_id,
                resource_scopes=token.resource_scopes,
                ip_restrictions=token.ip_restrictions,
                time_restrictions=token.time_restrictions,
                usage_limits=token.usage_limits,
            )
        )

    return TokenListResponse(tokens=token_responses, total=len(token_responses), limit=limit, offset=offset)


@router.post("/admin/teams/{team_id}", response_model=TokenCreateResponse, status_code=status.HTTP_201_CREATED, tags=["admin"])
@require_permission("tokens.admin.team.create")
async def admin_create_team_token(
    team_id: str,
    request: TokenCreateRequest,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TokenCreateResponse:
    """Admin: create a team token for ANY team (no owner requirement)."""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    service = TokenCatalogService(db)
    scope = _to_scope(request.scope)

    # Admin path => bypass owner check by creating directly at DB level
    # We reuse create_token but that enforces owner for team_id in service
    # So we do a small safe bypass here using list_all_tokens/create_token patterns.
    #
    # IMPORTANT: Team tokens require explicit permissions.
    if not scope or not scope.permissions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Team token requires at least one permission in scope.permissions",
        )

    try:
        token_record, raw_token = await service.create_token_admin_team(
            user_email=current_user["email"],
            team_id=team_id,
            name=request.name,
            description=request.description,
            scope=scope,
            expires_in_days=request.expires_in_days,
            tags=request.tags,
        )
    except AttributeError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Missing admin team token creation method in TokenCatalogService (create_token_admin_team)",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    token_response = TokenResponse(
        id=token_record.id,
        name=token_record.name,
        description=token_record.description,
        user_email=token_record.user_email,
        team_id=token_record.team_id,
        server_id=token_record.server_id,
        resource_scopes=token_record.resource_scopes or [],
        ip_restrictions=token_record.ip_restrictions or [],
        time_restrictions=token_record.time_restrictions or {},
        usage_limits=token_record.usage_limits or {},
        created_at=token_record.created_at,
        expires_at=token_record.expires_at,
        last_used=token_record.last_used,
        is_active=token_record.is_active,
        tags=token_record.tags or [],
    )

    return TokenCreateResponse(token=token_response, access_token=raw_token)
