# -*- coding: utf-8 -*-
"""
Gateway Router (RBAC-protected).

This file replaces admin.py gateway CRUD routes.
It preserves ALL existing behavior and inputs.
"""

# -------------------------
# Standard
# -------------------------
import json
from typing import Any, Dict, List, Optional, Union

# -------------------------
# Third-Party
# -------------------------
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from pydantic import ValidationError

# -------------------------
# First-Party
# -------------------------
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import (
    require_permission,
    get_current_user_with_permissions,
)
from mcpgateway.schemas import (
    GatewayCreate,
    GatewayRead,
    GatewayUpdate,
)
from mcpgateway.services.gateway_service import (
    GatewayService,
    GatewayConnectionError,
    GatewayNameConflictError,
    GatewayNotFoundError,
    GatewayPermissionError,
    GatewayUrlConflictError,
)
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.config import settings
from mcpgateway.utils.oauth_encryption import get_oauth_encryption  # ← same path admin.py used

# -------------------------
# Router
# -------------------------
gateway_router = APIRouter(prefix="/gateways", tags=["Gateways"])

# -------------------------
# Service (single instance)
# -------------------------
gateway_service: GatewayService = GatewayService()


# =====================================================================
# LOCAL helper — intentionally NOT shared
# =====================================================================
def get_user_email(user) -> str:
    """
    Extract user email from RBAC/JWT payload.

    Priority:
    1) dict["sub"]
    2) dict["email"]
    3) user.email
    4) str(user)
    """
    if isinstance(user, dict):
        return user.get("sub") or user.get("email") or "unknown"
    if hasattr(user, "email"):
        return str(getattr(user, "email") or "unknown")
    return str(user) if user else "unknown"


def _is_admin(user) -> bool:
    return bool(
        getattr(user, "is_admin", False)
        or (isinstance(user, dict) and user.get("is_admin"))
    )


# =====================================================================
# LIST
# =====================================================================
@gateway_router.get("", response_model=List[GatewayRead])
@gateway_router.get("/", response_model=List[GatewayRead])
@require_permission("gateways.read")
async def list_gateways(
    include_inactive: bool = False,
    team_id: Optional[str] = Query(None),
    visibility: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    user_email = get_user_email(user)

    return await gateway_service.list_gateways_for_user(
        db=db,
        user_email=user_email,
        team_id=team_id,
        visibility=visibility,
        include_inactive=include_inactive,
    )


# =====================================================================
# GET BY ID
# =====================================================================
@gateway_router.get("/{gateway_id}", response_model=GatewayRead)
@require_permission("gateways.read")
async def get_gateway(
    gateway_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    return await gateway_service.get_gateway(db, gateway_id)


# =====================================================================
# CREATE (JSON API – unchanged)
# =====================================================================
@gateway_router.post("", response_model=GatewayRead)
@gateway_router.post("/", response_model=GatewayRead)
@require_permission("gateways.create")
async def register_gateway(
    gateway: GatewayCreate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    try:
        metadata = MetadataCapture.extract_creation_metadata(request, user)

        user_email = get_user_email(user)
        visibility = gateway.visibility or "private"
        team_id = gateway.team_id

        if not team_id:
            team_service = TeamManagementService(db)
            teams = await team_service.get_user_teams(user_email, include_personal=True)
            personal = next((t for t in teams if t.is_personal), None)
            team_id = personal.id if personal else None

        return await gateway_service.register_gateway(
            db=db,
            gateway=gateway,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            team_id=team_id,
            owner_email=user_email,
            visibility=visibility,
        )

    except GatewayConnectionError:
        return JSONResponse({"message": "Unable to connect to gateway"}, 503)
    except GatewayNameConflictError as e:
        return JSONResponse({"message": str(e)}, 409)
    except GatewayUrlConflictError as e:
        return JSONResponse({"message": str(e)}, 409)
    except ValidationError as e:
        return JSONResponse(ErrorFormatter.format_validation_error(e), 422)
    except IntegrityError as e:
        return JSONResponse(ErrorFormatter.format_database_error(e), 409)
    except Exception as e:
        return JSONResponse({"message": str(e)}, 500)


# =====================================================================
# UPDATE
# =====================================================================
@gateway_router.put("/{gateway_id}", response_model=GatewayRead)
@require_permission("gateways.update")
async def update_gateway(
    gateway_id: str,
    gateway: GatewayUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    try:
        metadata = MetadataCapture.extract_modification_metadata(request, user, 0)

        return await gateway_service.update_gateway(
            db=db,
            gateway_id=gateway_id,
            gateway_update=gateway,
            modified_by=metadata["modified_by"],
            modified_from_ip=metadata["modified_from_ip"],
            modified_via=metadata["modified_via"],
            modified_user_agent=metadata["modified_user_agent"],
            actor_email=get_user_email(user),
            actor_is_admin=_is_admin(user),
        )

    except GatewayPermissionError as e:
        return JSONResponse({"message": str(e)}, 403)
    except GatewayNotFoundError:
        return JSONResponse({"message": "Gateway not found"}, 404)
    except ValidationError as e:
        return JSONResponse(ErrorFormatter.format_validation_error(e), 422)
    except IntegrityError as e:
        return JSONResponse(ErrorFormatter.format_database_error(e), 409)
    except Exception as e:
        return JSONResponse({"message": str(e)}, 500)


# =====================================================================
# TOGGLE
# =====================================================================
@gateway_router.post("/{gateway_id}/toggle")
@require_permission("gateways.update")
async def toggle_gateway(
    gateway_id: str,
    activate: bool = True,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    try:
        gw = await gateway_service.toggle_gateway_status(db, gateway_id, activate)
        return {
            "success": True,
            "message": f"Gateway {'activated' if activate else 'deactivated'}",
            "gateway": gw.model_dump(),
        }
    except Exception as e:
        raise HTTPException(400, str(e))


# =====================================================================
# DELETE
# =====================================================================
@gateway_router.delete("/{gateway_id}")
@require_permission("gateways.delete")
async def delete_gateway(
    gateway_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    try:
        await gateway_service.delete_gateway(
            db=db,
            gateway_id=gateway_id,
            actor_email=get_user_email(user),
            actor_is_admin=_is_admin(user),
        )
        return {"success": True, "message": "Gateway deleted successfully"}

    except GatewayPermissionError as e:
        return JSONResponse({"message": str(e)}, 403)
    except GatewayNotFoundError:
        return JSONResponse({"message": "Gateway not found"}, 404)
    except Exception as e:
        return JSONResponse({"message": str(e)}, 500)
