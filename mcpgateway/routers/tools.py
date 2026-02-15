# -*- coding: utf-8 -*-
"""
Tools Router (RBAC-protected).

Centralized Tools API routes under /api/tools (non-breaking).
This does NOT change or replace existing main.py/admin.py routes.
It provides a centralized "root" while preserving legacy endpoints.

Mount in main.py (non-breaking):
    from mcpgateway.routers.tools import tool_router as centralized_tools_router
    app.include_router(centralized_tools_router)
"""

# -------------------------
# Standard
# -------------------------
from typing import Any, Dict, List, Optional, Union

# -------------------------
# Third-Party
# -------------------------
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# -------------------------
# First-Party
# -------------------------
from mcpgateway.db import Tool as DbTool
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import require_permission, get_current_user_with_permissions
from mcpgateway.schemas import ToolCreate, ToolRead, ToolUpdate
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.services.tool_service import (
    ToolError,
    ToolNameConflictError,
    ToolNotFoundError,
    ToolPermissionError,
    ToolService,
)
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.metadata_capture import MetadataCapture

# -------------------------
# Router + Service
# -------------------------
tool_router = APIRouter(prefix="/tools", tags=["tools"])
tool_service = ToolService()


# -------------------------
# Helpers (local, safe)
# -------------------------
def get_user_email(user: Any) -> str:
    """
    Extract an email-like identity from the RBAC user object.

    We keep this local to avoid coupling to legacy imports.
    Matches existing behavior patterns: dict user with "email".
    """
    if isinstance(user, dict):
        email = (user.get("email") or user.get("user") or user.get("sub") or "").strip()
        return email
    # fallback to attribute access
    for attr in ("email", "user", "sub"):
        val = getattr(user, attr, None)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def is_platform_admin(user: Any) -> bool:
    """
    Platform admin detection.

    We keep this conservative and compatible:
    - if user dict has is_admin True -> admin
    - else false
    """
    if isinstance(user, dict):
        return bool(user.get("is_admin", False))
    return bool(getattr(user, "is_admin", False))


# ============================================================
# Centralized Tools API (User-scoped)
# ============================================================

@tool_router.get("", response_model=List[ToolRead])
@tool_router.get("/", response_model=List[ToolRead])
@require_permission("tools.read")
async def list_tools(
    include_inactive: bool = False,
    team_id: Optional[str] = Query(None),
    visibility: Optional[str] = Query(None, description="private | team | public"),
    tags: Optional[str] = Query(None, description="Comma-separated tags filter (client-side filter)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[ToolRead]:
    """
    List tools the current user has access to (RBAC protected).

    Notes:
    - Uses ToolService.list_tools_for_user() which supports team_id + visibility + include_inactive + pagination.
    - Tag filtering is applied in-router (safe) because list_tools_for_user does not accept tags.
    """
    user_email = get_user_email(user)
    tools = await tool_service.list_tools_for_user(
        db=db,
        user_email=user_email,
        team_id=team_id,
        visibility=visibility,
        include_inactive=include_inactive,
        skip=skip,
        limit=limit,
    )

    # Optional tags filter (safe local filter)
    if tags:
        wanted = {t.strip().lower() for t in tags.split(",") if t.strip()}
        if wanted:
            filtered: List[ToolRead] = []
            for tool in tools:
                tool_tags = {(x or "").strip().lower() for x in (tool.tags or [])}
                if tool_tags.intersection(wanted):
                    filtered.append(tool)
            tools = filtered

    return tools


@tool_router.get("/{tool_id}", response_model=ToolRead)
@require_permission("tools.read")
async def get_tool(
    tool_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ToolRead:
    """
    Get tool by ID (RBAC protected).

    NOTE:
    - This mirrors existing behavior from your main.py tool route.
    - Visibility enforcement is assumed to be handled via RBAC + service rules.
    """
    try:
        return await tool_service.get_tool(db, tool_id)
    except ToolNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e


@tool_router.post("", response_model=ToolRead)
@tool_router.post("/", response_model=ToolRead)
@require_permission("tools.create")
async def create_tool(
    tool: ToolCreate,
    request: Request,
    team_id: Optional[str] = Body(None, description="Team ID to assign tool to"),
    visibility: str = Body("private", description="Tool visibility: private, team, public"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ToolRead:
    """
    Create a tool (RBAC protected), preserving existing create semantics from main.py.

    - Captures metadata via MetadataCapture
    - If team_id not provided, defaults to personal team (include_personal=True)
    - Passes team_id, owner_email, visibility into ToolService.register_tool
    """
    try:
        metadata = MetadataCapture.extract_creation_metadata(request, user)
        user_email = get_user_email(user)

        # Default team_id -> user's personal team
        if not team_id:
            team_service = TeamManagementService(db)
            user_teams = await team_service.get_user_teams(user_email, include_personal=True)
            personal_team = next((t for t in user_teams if getattr(t, "is_personal", False)), None)
            team_id = getattr(personal_team, "id", None) if personal_team else None

        return await tool_service.register_tool(
            db=db,
            tool=tool,
            created_by=metadata.get("created_by"),
            created_from_ip=metadata.get("created_from_ip"),
            created_via=metadata.get("created_via"),
            created_user_agent=metadata.get("created_user_agent"),
            import_batch_id=metadata.get("import_batch_id"),
            federation_source=metadata.get("federation_source"),
            team_id=team_id,
            owner_email=user_email,
            visibility=visibility,
        )

    except ToolNameConflictError as ex:
        # mirror existing behavior from main.py
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ex)) from ex
    except (ValidationError, ValueError) as ex:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorFormatter.format_validation_error(ex),
        ) from ex
    except IntegrityError as ex:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorFormatter.format_database_error(ex),
        ) from ex
    except ToolError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex)) from ex
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while creating the tool",
        ) from ex


@tool_router.put("/{tool_id}", response_model=ToolRead)
@require_permission("tools.update")
async def update_tool(
    tool_id: str,
    tool: ToolUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ToolRead:
    """
    Update tool (RBAC protected), preserving existing update semantics:
    - Captures modification metadata (including current version)
    - Passes actor_is_admin into service so its authorization gate stays consistent
    """
    try:
        current_tool = db.get(DbTool, tool_id)
        current_version = getattr(current_tool, "version", 0) if current_tool else 0
        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, current_version)

        return await tool_service.update_tool(
            db=db,
            tool_id=tool_id,
            tool_update=tool,
            modified_by=mod_metadata.get("modified_by"),
            modified_from_ip=mod_metadata.get("modified_from_ip"),
            modified_via=mod_metadata.get("modified_via"),
            modified_user_agent=mod_metadata.get("modified_user_agent"),
            actor_is_admin=is_platform_admin(user),
        )

    except ToolNotFoundError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex)) from ex
    except ToolPermissionError as ex:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(ex)) from ex
    except ToolNameConflictError as ex:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ex)) from ex
    except ValidationError as ex:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorFormatter.format_validation_error(ex),
        ) from ex
    except IntegrityError as ex:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorFormatter.format_database_error(ex),
        ) from ex
    except ToolError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex)) from ex
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while updating the tool",
        ) from ex


@tool_router.delete("/{tool_id}", response_model=Dict[str, str])
@require_permission("tools.delete")
async def delete_tool(
    tool_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, str]:
    """
    Delete tool (RBAC protected).

    IMPORTANT:
    - Uses ToolService.delete_tool guardrails (owner/team-admin/admin rules).
    - Keeps responses simple for API clients.
    """
    try:
        await tool_service.delete_tool(
            db=db,
            tool_id=tool_id,
            actor_email=get_user_email(user),
            actor_is_admin=is_platform_admin(user),
        )
        return {"status": "success", "message": f"Tool {tool_id} permanently deleted"}

    except ToolNotFoundError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex)) from ex
    except ToolPermissionError as ex:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(ex)) from ex
    except ToolError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex)) from ex
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while deleting the tool",
        ) from ex


@tool_router.post("/{tool_id}/toggle", response_model=Dict[str, Any])
@require_permission("tools.update")
async def toggle_tool_status(
    tool_id: str,
    activate: bool = True,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    Toggle tool enabled/reachable state (RBAC protected).
    Mirrors existing /tools/{id}/toggle behavior in main.py.
    """
    try:
        tool = await tool_service.toggle_tool_status(db, tool_id, activate, reachable=activate)
        return {
            "status": "success",
            "message": f"Tool {tool_id} {'activated' if activate else 'deactivated'}",
            "tool": tool.model_dump(),
        }
    except ToolNotFoundError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex)) from ex
    except ToolError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex)) from ex
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while toggling tool status",
        ) from ex


# ============================================================
# Centralized Tools API (Admin list-all)
# ============================================================

@tool_router.get("/admin/tools", response_model=List[ToolRead])
@require_permission("admin.read")
async def admin_list_all_tools(
    include_inactive: bool = False,
    tags: Optional[str] = Query(None, description="Comma-separated tags (e.g., 'api,data')"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[ToolRead]:
    """
    ADMIN-ONLY: List ALL tools (bypasses per-user visibility rules).
    Mirrors your main.py admin list-all behavior but under /api/tools/admin/tools.
    """
    tags_list: Optional[List[str]] = None
    if tags:
        tags_list = [t.strip() for t in tags.split(",") if t.strip()]

    return await tool_service.list_tools(
        db=db,
        include_inactive=include_inactive,
        cursor=None,
        tags=tags_list,
    )
