# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/routers/servers.py

Servers Router (REST JSON).
Routes + params preserved to match the existing main.py behavior.
"""

# Standard
import asyncio
from typing import Any, Dict, List, Optional

# Third-Party
from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.db import SessionLocal
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import (
    PromptRead,
    ResourceRead,
    ServerCreate,
    ServerRead,
    ServerUpdate,
    ToolRead,
)
from mcpgateway.services.server_service import (
    ServerError,
    ServerNameConflictError,
    ServerNotFoundError,
    ServerService,
)
from mcpgateway.cache.session_registry_singleton import session_registry
from mcpgateway.services.tool_service import ToolService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.transports.sse_transport import SSETransport
from mcpgateway.utils.error_formatter import ErrorFormatter
from urllib.parse import urlparse, urlunparse
from mcpgateway.utils.metadata_capture import MetadataCapture

server_router = APIRouter(prefix="/servers", tags=["servers"])

server_service = ServerService()
tool_service = ToolService()
resource_service = ResourceService()
prompt_service = PromptService()


# If you have a shared logger pattern, plug it in here.
# Keeping minimal: use print/debug logs or import your logging_service like main.py does.
import logging
logger = logging.getLogger("mcpgateway")


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

def get_db() -> Session:
    """Dependency for DB session (consistent with SessionLocal usage in your codebase)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def update_url_protocol(request: Request) -> str:
    """
    Update the base URL protocol based on the request's scheme or forwarded headers.

    Args:
        request (Request): The FastAPI request object.

    Returns:
        str: The base URL with the correct protocol.

    Examples:
        Test URL protocol update with HTTPS proxy:
        >>> from mcpgateway import main
        >>> from fastapi import Request
        >>>
        >>> # Mock request with HTTPS forwarded proto
        >>> scope_https = {
        ...     'type': 'http',
        ...     'scheme': 'http',
        ...     'server': ('example.com', 80),
        ...     'path': '/',
        ...     'headers': [(b'x-forwarded-proto', b'https')],
        ... }
        >>> req_https = Request(scope_https)
        >>> url = main.update_url_protocol(req_https)
        >>> url.startswith('https://example.com')
        True

        Test URL protocol update with HTTP direct:
        >>> scope_http = {
        ...     'type': 'http',
        ...     'scheme': 'http',
        ...     'server': ('localhost', 8000),
        ...     'path': '/',
        ...     'headers': [],
        ... }
        >>> req_http = Request(scope_http)
        >>> url = main.update_url_protocol(req_http)
        >>> url.startswith('http://localhost:8000')
        True

        Test URL protocol update preserves host and port:
        >>> scope_port = {
        ...     'type': 'http',
        ...     'scheme': 'https',
        ...     'server': ('api.test.com', 443),
        ...     'path': '/',
        ...     'headers': [],
        ... }
        >>> req_port = Request(scope_port)
        >>> url = main.update_url_protocol(req_port)
        >>> 'api.test.com' in url and url.startswith('https://')
        True

        Test trailing slash removal:
        >>> # URL should not end with trailing slash
        >>> url = main.update_url_protocol(req_http)
        >>> url.endswith('/')
        False
    """
    parsed = urlparse(str(request.base_url))
    proto = get_protocol_from_request(request)
    new_parsed = parsed._replace(scheme=proto)
    # urlunparse keeps netloc and path intact
    return str(urlunparse(new_parsed)).rstrip("/")

def get_protocol_from_request(request: Request) -> str:
    """
    Return "https" or "http" based on:
     1) X-Forwarded-Proto (if set by a proxy)
     2) request.url.scheme  (e.g. when Gunicorn/Uvicorn is terminating TLS)

    Args:
        request (Request): The FastAPI request object.

    Returns:
        str: The protocol used for the request, either "http" or "https".

    Examples:
        Test with X-Forwarded-Proto header (proxy scenario):
        >>> from mcpgateway import main
        >>> from fastapi import Request
        >>> from urllib.parse import urlparse
        >>>
        >>> # Mock request with X-Forwarded-Proto
        >>> scope = {
        ...     'type': 'http',
        ...     'scheme': 'http',
        ...     'headers': [(b'x-forwarded-proto', b'https')],
        ...     'server': ('testserver', 80),
        ...     'path': '/',
        ... }
        >>> req = Request(scope)
        >>> main.get_protocol_from_request(req)
        'https'

        Test with comma-separated X-Forwarded-Proto:
        >>> scope_multi = {
        ...     'type': 'http',
        ...     'scheme': 'http',
        ...     'headers': [(b'x-forwarded-proto', b'https,http')],
        ...     'server': ('testserver', 80),
        ...     'path': '/',
        ... }
        >>> req_multi = Request(scope_multi)
        >>> main.get_protocol_from_request(req_multi)
        'https'

        Test without X-Forwarded-Proto (direct connection):
        >>> scope_direct = {
        ...     'type': 'http',
        ...     'scheme': 'https',
        ...     'headers': [],
        ...     'server': ('testserver', 443),
        ...     'path': '/',
        ... }
        >>> req_direct = Request(scope_direct)
        >>> main.get_protocol_from_request(req_direct)
        'https'

        Test with HTTP direct connection:
        >>> scope_http = {
        ...     'type': 'http',
        ...     'scheme': 'http',
        ...     'headers': [],
        ...     'server': ('testserver', 80),
        ...     'path': '/',
        ... }
        >>> req_http = Request(scope_http)
        >>> main.get_protocol_from_request(req_http)
        'http'
    """
    forwarded = request.headers.get("x-forwarded-proto")
    if forwarded:
        # may be a comma-separated list; take the first
        return forwarded.split(",")[0].strip()
    return request.url.scheme



###############
# Server APIs #
###############

@server_router.get("", response_model=List[ServerRead])
@server_router.get("/", response_model=List[ServerRead])
@require_permission("servers.read")
async def list_servers(
    include_inactive: bool = False,
    tags: Optional[str] = None,
    team_id: Optional[str] = Query(None, description="Filter by team ID"),
    visibility: Optional[str] = Query(None, description="Filter by visibility: private, team, public"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[ServerRead]:
    """
    Lists servers accessible to the current user, enforcing visibility rules.
    Signature preserved.
    """
    tags_list: Optional[List[str]] = None
    if tags:
        tags_list = [tag.strip() for tag in tags.split(",") if tag.strip()]

    user_email = get_user_email(user)

    data = await server_service.list_servers_for_user(
        db=db,
        user_email=user_email,
        team_id=team_id,
        visibility=visibility,
        include_inactive=include_inactive,
    )

    if tags_list:
        filtered: List[ServerRead] = []
        for server in data:
            server_tags = getattr(server, "tags", None)
            if server_tags and any(tag in server_tags for tag in tags_list):
                filtered.append(server)
        data = filtered

    return data


@server_router.get("/admin/servers", response_model=List[ServerRead])
@require_permission("admin.read")
async def admin_list_all_servers(
    include_inactive: bool = False,
    tags: Optional[str] = Query(None, description="Comma-separated tags (e.g., 'nlp,data,ocr')"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[ServerRead]:
    """
    ADMIN-ONLY: List ALL servers (public + private + team).
    Route preserved.
    """
    tags_list: Optional[List[str]] = None
    if tags:
        tags_list = [t.strip() for t in tags.split(",") if t.strip()]

    servers = await server_service.list_servers(
        db=db,
        include_inactive=include_inactive,
        tags=tags_list,
    )
    return servers


@server_router.get("/{server_id}", response_model=ServerRead)
@require_permission("servers.read")
async def get_server(
    server_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ServerRead:
    """Retrieve a server by ID. Route preserved."""
    try:
        logger.debug("User %s requested server with ID %s", user, server_id)
        return await server_service.get_server(db, server_id)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@server_router.post("", response_model=ServerRead, status_code=201)
@server_router.post("/", response_model=ServerRead, status_code=201)
@require_permission("servers.create")
async def create_server(
    server: ServerCreate,
    request: Request,
    team_id: Optional[str] = Body(None, description="Team ID to assign server to"),
    visibility: str = Body("private", description="Server visibility: private, team, public"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ServerRead:
    """
    Create server. Route + params preserved.
    """
    try:
        metadata = MetadataCapture.extract_creation_metadata(request, user)
        user_email = get_user_email(user)

        # Keep your behavior: if team_id omitted, attempt to use personal team.
        if not team_id:
            from mcpgateway.services.team_management_service import TeamManagementService  # pylint: disable=import-outside-toplevel

            team_service = TeamManagementService(db)
            user_teams = await team_service.get_user_teams(user_email, include_personal=True)
            personal_team = next((team for team in user_teams if team.is_personal), None)
            team_id = personal_team.id if personal_team else None

        logger.debug("User %s creating server for team %s", user_email, team_id)

        return await server_service.register_server(
            db,
            server,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            team_id=team_id,
            owner_email=user_email,
            visibility=visibility,
        )

    except ServerNameConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ServerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValidationError as e:
        logger.error("Validation error while creating server: %s", e)
        raise HTTPException(status_code=422, detail=ErrorFormatter.format_validation_error(e))
    except IntegrityError as e:
        logger.error("Integrity error while creating server: %s", e)
        raise HTTPException(status_code=409, detail=ErrorFormatter.format_database_error(e))


@server_router.put("/{server_id}", response_model=ServerRead)
@require_permission("servers.update")
async def update_server(
    server_id: str,
    server: ServerUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ServerRead:
    """
    Update server. Route + params preserved.
    """
    try:
        logger.debug("User %s updating server with ID %s", user, server_id)

        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        user_email: str = get_user_email(user)

        return await server_service.update_server(
            db,
            server_id,
            server,
            user_email,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
        )

    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ServerNameConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ServerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValidationError as e:
        logger.error("Validation error while updating server %s: %s", server_id, e)
        raise HTTPException(status_code=422, detail=ErrorFormatter.format_validation_error(e))
    except IntegrityError as e:
        logger.error("Integrity error while updating server %s: %s", server_id, e)
        raise HTTPException(status_code=409, detail=ErrorFormatter.format_database_error(e))


@server_router.post("/{server_id}/toggle", response_model=ServerRead)
@require_permission("servers.update")
async def toggle_server_status(
    server_id: str,
    activate: bool = True,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ServerRead:
    """Toggle active status. Route + param preserved."""
    try:
        logger.debug("User %s toggling server %s activate=%s", user, server_id, activate)
        return await server_service.toggle_server_status(db, server_id, activate)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ServerError as e:
        raise HTTPException(status_code=400, detail=str(e))


@server_router.delete("/{server_id}", response_model=Dict[str, str])
@require_permission("servers.delete")
async def delete_server(
    server_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, str]:
    """
    Deletes a server by its ID.
    """
    try:
        actor_email = get_user_email(user)
        actor_is_admin = bool(
            getattr(user, "is_admin", False)
            or (isinstance(user, dict) and user.get("is_admin"))
        )

        logger.debug(f"User {actor_email} is deleting server with ID {server_id}")
        await server_service.delete_server(
            db,
            server_id,
            actor_email=actor_email,
            actor_is_admin=actor_is_admin,
        )
        return {
            "status": "success",
            "message": f"Server {server_id} deleted successfully",
        }
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ServerError as e:
        raise HTTPException(status_code=400, detail=str(e))


##########################
# Server SSE Endpoints   #
##########################

@server_router.get("/{server_id}/sse")
@require_permission("servers.manage")
async def sse_endpoint(
    request: Request,
    server_id: str,
    user=Depends(get_current_user_with_permissions),
):
    """
    SSE connection for server.
    Preserved flow from your main.py snippet.
    """
    try:
        logger.debug("User %s establishing SSE connection for server %s", user, server_id)

        base_url = update_url_protocol(request)
        server_sse_url = f"{base_url}/servers/{server_id}"

        transport = SSETransport(base_url=server_sse_url)
        await transport.connect()

        await session_registry.add_session(transport.session_id, transport)
        response = await transport.create_sse_response(request)

        asyncio.create_task(
            session_registry.respond(
                server_id,
                user,
                session_id=transport.session_id,
                base_url=base_url,
            )
        )

        tasks = BackgroundTasks()
        tasks.add_task(session_registry.remove_session, transport.session_id)
        response.background = tasks

        logger.info("SSE connection established: %s", transport.session_id)
        return response

    except Exception as e:
        logger.error("SSE connection error: %s", e)
        raise HTTPException(status_code=500, detail="SSE connection failed")


@server_router.post("/{server_id}/message")
@require_permission("servers.manage")
async def message_endpoint(
    request: Request,
    server_id: str,
    user=Depends(get_current_user_with_permissions),
):
    """Handle incoming messages. Preserved from your main.py snippet."""
    try:
        logger.debug("User %s sent a message to server %s", user, server_id)

        session_id = request.query_params.get("session_id")
        if not session_id:
            raise HTTPException(status_code=400, detail="Missing session_id")

        message = await request.json()

        await session_registry.broadcast(session_id=session_id, message=message)
        return JSONResponse(content={"status": "success"}, status_code=202)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Message handling error: %s", e)
        raise HTTPException(status_code=500, detail="Failed to process message")


############################
# Server-associated Catalog #
############################

@server_router.get("/{server_id}/tools", response_model=List[ToolRead])
@require_permission("servers.read")
async def server_get_tools(
    server_id: str,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[Dict[str, Any]]:
    logger.debug("User %s listed tools for server_id=%s", user, server_id)
    tools = await tool_service.list_server_tools(db, server_id=server_id, include_inactive=include_inactive)
    return [tool.model_dump(by_alias=True) for tool in tools]


@server_router.get("/{server_id}/resources", response_model=List[ResourceRead])
@require_permission("servers.read")
async def server_get_resources(
    server_id: str,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[Dict[str, Any]]:
    logger.debug("User %s listed resources for server_id=%s", user, server_id)
    resources = await resource_service.list_server_resources(db, server_id=server_id, include_inactive=include_inactive)
    return [resource.model_dump(by_alias=True) for resource in resources]


@server_router.get("/{server_id}/prompts", response_model=List[PromptRead])
@require_permission("servers.read")
async def server_get_prompts(
    server_id: str,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[Dict[str, Any]]:
    logger.debug("User %s listed prompts for server_id=%s", user, server_id)
    prompts = await prompt_service.list_server_prompts(db, server_id=server_id, include_inactive=include_inactive)
    return [prompt.model_dump(by_alias=True) for prompt in prompts]
