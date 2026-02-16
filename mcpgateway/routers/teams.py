# -*- coding: utf-8 -*-
# import sys,os
# print("STARTUP: teams.py loaded from:", __file__, "pid=", os.getpid(), file=sys.stderr, flush=True)
"""Location: ./mcpgateway/routers/teams.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Team Management Router.
This module provides FastAPI routes for team management including
team creation, member management, and invitation handling.

Examples:
    >>> from fastapi import FastAPI
    >>> from mcpgateway.routers.teams import teams_router
    >>> app = FastAPI()
    >>> app.include_router(teams_router, prefix="/teams", tags=["Teams"])
    >>> isinstance(teams_router, APIRouter)
    True
    >>> len(teams_router.routes) > 10  # Multiple team management endpoints
    True
"""

# Standard
from typing import Any, cast, List, Optional
from fastapi.responses import JSONResponse
# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.auth import get_current_user
from mcpgateway.db import get_db, EmailTeamMember, EmailTeam, EmailTeamJoinRequest
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import (
    EmailUserResponse,
    SuccessResponse,
    TeamCreateRequest,
    TeamDiscoveryResponse,
    TeamInvitationResponse,
    TeamInviteRequest,
    TeamJoinRequest,
    TeamJoinRequestResponse,
    TeamListResponse,
    TeamMemberResponse,
    TeamMemberUpdateRequest,
    TeamResponse,
    TeamUpdateRequest,
)
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.team_invitation_service import TeamInvitationService
from mcpgateway.services.team_management_service import TeamManagementService

# Initialize logging
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

# Create router
teams_router = APIRouter()


# ---------------------------------------------------------------------------
# Team CRUD Operations
# ---------------------------------------------------------------------------


@teams_router.post("/", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
@require_permission("teams.create")
async def create_team(request: TeamCreateRequest, current_user_ctx: dict = Depends(get_current_user_with_permissions)) -> TeamResponse:
    """Create a new team.

    Args:
        request: Team creation request data
        current_user_ctx: Currently authenticated user context

    Returns:
        TeamResponse: Created team data

    Raises:
        HTTPException: If team creation fails

    Examples:
        >>> import asyncio
        >>> asyncio.iscoroutinefunction(create_team)
        True
    """
    try:
        db = current_user_ctx["db"]
        service = TeamManagementService(db)
        team = await service.create_team(name=request.name, description=request.description, created_by=current_user_ctx["email"], visibility=request.visibility, max_members=request.max_members)

        return TeamResponse(
            id=team.id,
            name=team.name,
            slug=team.slug,
            description=team.description,
            created_by=team.created_by,
            is_personal=team.is_personal,
            visibility=team.visibility,
            max_members=team.max_members,
            member_count=team.get_member_count(),
            created_at=team.created_at,
            updated_at=team.updated_at,
            is_active=team.is_active,
        )
    except ValueError as e:
        logger.error(f"Team creation failed: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error creating team: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create team")


@teams_router.get("/", response_model=TeamListResponse)
@require_permission("teams.list")
async def list_teams(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user_ctx: dict = Depends(get_current_user_with_permissions),
) -> TeamListResponse:
    try:
        db = current_user_ctx["db"]
        user_email = current_user_ctx["email"]
        is_admin = current_user_ctx.get("is_admin", False)

        service = TeamManagementService(db)

        # ----------------------------
        # Load teams
        # ----------------------------
        if is_admin:
            teams, total = await service.list_teams(limit=limit, offset=skip)

            # Keep admin behavior (all teams) but also include admin's personal team
            # so UI reflects personal-team naming consistently.
            admin_user_teams = await service.get_user_teams(
                user_email,
                include_personal=True,
            )
            admin_personal_team = next(
                (t for t in admin_user_teams if getattr(t, "is_personal", False)),
                None,
            )
            if skip == 0 and admin_personal_team is not None and all(t.id != admin_personal_team.id for t in teams):
                teams = [admin_personal_team] + list(teams)
                total += 1
        else:
            teams = await service.get_user_teams(
                user_email,
                include_personal=True,
            )
            total = len(teams)
            teams = teams[skip : skip + limit]

        team_responses: list[TeamResponse] = []

        # ----------------------------
        # Build response PER TEAM
        # ----------------------------
        for team in teams:
            members = await service.get_team_members(team.id)
            member_emails = set(members)  # ✅ FIXED AS REQUESTED

            is_owner = team.created_by == user_email
            is_member = is_owner or user_email in member_emails
            can_join = (
                team.visibility == "public"
                and not is_owner
                and not is_member
            )

            team_responses.append(
                TeamResponse(
                    id=team.id,
                    name=team.name,
                    slug=team.slug,
                    description=team.description,
                    created_by=team.created_by,
                    is_personal=team.is_personal,
                    visibility=team.visibility,
                    max_members=team.max_members,
                    member_count=len(member_emails),
                    created_at=team.created_at,
                    updated_at=team.updated_at,
                    is_active=team.is_active,

                    # 🔥 FLAGS USED BY FRONTEND BUTTONS
                    is_owner=is_owner,
                    is_member=is_member,
                    can_join=can_join,
                    is_admin=is_admin
                )
            )

        return TeamListResponse(
            teams=team_responses,
            total=total,
        )

    except Exception as e:
        logger.error(f"Error listing teams: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list teams",
        )

#------------------------
# Discover Public Teams
#------------------------

@teams_router.get("/discover", response_model=List[TeamDiscoveryResponse])
@require_permission("teams.discover")
async def discover_public_teams(
    skip: int = Query(0, ge=0, description="Number of teams to skip"),
    limit: int = Query(50, ge=1, le=100, description="Number of teams to return"),
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
) -> List[TeamDiscoveryResponse]:
    """Discover public teams that can be joined.

    Returns public teams that are discoverable to all authenticated users.
    Only shows teams where the current user is not already a member.

    Args:
        skip: Number of teams to skip for pagination
        limit: Maximum number of teams to return
        current_user_ctx: Current user context with permissions and database session

    Returns:
        List[TeamDiscoveryResponse]: List of discoverable public teams

    Raises:
        HTTPException: If there's an error discovering teams
    """
    try:
        db: Session = current_user_ctx["db"]
        team_service = TeamManagementService(db)

        # Get public teams where user is not already a member
        public_teams = await team_service.discover_public_teams(current_user_ctx["email"], skip=skip, limit=limit)

        if public_teams is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No Public teams found")
        else:
            team_ids = [team.id for team in public_teams if getattr(team, "id", None)]
            pending_requested_ids = set()
            if team_ids:
                pending_rows = (
                    db.query(EmailTeamJoinRequest.team_id)
                    .filter(
                        EmailTeamJoinRequest.user_email == current_user_ctx["email"],
                        EmailTeamJoinRequest.status == "pending",
                        EmailTeamJoinRequest.team_id.in_(team_ids),
                    )
                    .all()
                )
                pending_requested_ids = {row[0] for row in pending_rows if row and row[0]}

            discovery_responses = []
            for team in public_teams:
                discovery_responses.append(
                    TeamDiscoveryResponse(
                        id=team.id,
                        name=team.name,
                        description=team.description,
                        member_count=team.get_member_count(),
                        created_at=team.created_at,
                        is_joinable=True,  # All returned teams are joinable
                        requested=team.id in pending_requested_ids,
                    )
                )

            return discovery_responses
    except Exception as e:
        logger.error(f"Error discovering public teams: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to discover teams")


@teams_router.get("/invitations", response_model=List[TeamInvitationResponse])
@require_permission("teams.invite")
async def get_my_invitations(
    current_user_ctx: dict = Depends(get_current_user_with_permissions),
) -> List[TeamInvitationResponse]:
    """
    Get all active invitations for the currently authenticated user.
    """

    try:
        db: Session = current_user_ctx["db"]
        user_email: str = current_user_ctx["email"]

        invitation_service = TeamInvitationService(db)
        team_service = TeamManagementService(db)

        invitations = await invitation_service.get_user_invitations(user_email)

        invitation_responses = []
        for invitation in invitations:
            team = await team_service.get_team_by_id(invitation.team_id)
            team_name = team.name if team else "Unknown Team"
            invitation_responses.append(
                TeamInvitationResponse(
                    id=invitation.id,
                    team_id=invitation.team_id,
                    team_name=team_name,
                    email=invitation.email,
                    role=invitation.role,
                    invited_by=invitation.invited_by,
                    invited_at=invitation.invited_at,
                    expires_at=invitation.expires_at,
                    token=invitation.token,
                    is_active=invitation.is_active,
                    is_expired=invitation.is_expired()
                )
            )

        return invitation_responses
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching invitations for user {current_user_ctx['email']}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve invitations"
        )


@teams_router.get("/{team_id}", response_model=TeamResponse)
@require_permission("teams.read")
async def get_team(
    team_id: str,
    current_user_ctx: dict = Depends(get_current_user_with_permissions),
) -> TeamResponse:
    """
    Get a specific team by ID.
    """
    try:
        db: Session = current_user_ctx["db"]
        service = TeamManagementService(db)
        team = await service.get_team_by_id(team_id)
        if team is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team Not Found")

        return TeamResponse(
            id=team.id,
            name=team.name,
            slug=team.slug,
            description=team.description,
            created_by=team.created_by,
            is_personal=team.is_personal,
            visibility=team.visibility,
            max_members=team.max_members,
            member_count=team.get_member_count(),
            created_at=team.created_at,
            updated_at=team.updated_at,
            is_active=team.is_active,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Error getting team %s", team_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get team")

#-------------------
# Team Update
#-------------------

@teams_router.put("/{team_id}", response_model=TeamResponse)
@require_permission("teams.update")
async def update_team(
    team_id: str,
    request: TeamUpdateRequest,
    current_user_ctx: dict = Depends(get_current_user_with_permissions),
) -> TeamResponse:
    try:
        db: Session = current_user_ctx["db"]
        service = TeamManagementService(db)

        # 🔥 Call service layer
        success = await service.update_team(
            team_id=team_id,
            name=request.name,
            description=request.description,
            visibility=request.visibility,
            max_members=request.max_members,
            updated_by=current_user_ctx["email"],
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to update team"
            )

        # 🔥 Fetch updated team after update
        team = await service.get_team_by_id(team_id)

        if team is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found after update"
            )

        return TeamResponse(
            id=team.id,
            name=team.name,
            slug=team.slug,
            description=team.description,
            created_by=team.created_by,
            is_personal=team.is_personal,
            visibility=team.visibility,
            max_members=team.max_members,
            member_count=team.get_member_count(),
            created_at=team.created_at,
            updated_at=team.updated_at,
            is_active=team.is_active,
        )

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error updating team {team_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update team"
        )

#-------------------
# Team Delete
#-------------------

@teams_router.delete("/{team_id}", response_model=SuccessResponse)
@require_permission("teams.delete")
async def delete_team(
    team_id: str, 
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
    ) -> TeamResponse:
    """Delete a team.

    Args:
        team_id: Team UUID
        current_user: Currently authenticated user
        db: Database session

    Returns:
        SuccessResponse: Success confirmation

    Raises:
        HTTPException: If team not found, access denied, or deletion fails
    """
    try:
        db: Session = current_user_ctx["db"]
        service = TeamManagementService(db)
        team = await service.get_team_by_id(team_id)
        if team is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )
        success = await service.delete_team(team_id, current_user_ctx["email"])
        if not success:
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Team Deletion Unsuccessful.")
        else:
            return SuccessResponse(message="Team deleted successfully")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete team")


# ---------------------------------------------------------------------------
# Team Member Management
# ---------------------------------------------------------------------------
#-------------------
# View team Members
#-------------------

@teams_router.get("/{team_id}/members", response_model=List[TeamMemberResponse])
@require_permission("teams.read")
async def list_team_members(
    team_id: str, 
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
    ) -> List[TeamMemberResponse]:
    """List team members.

    Args:
        team_id: Team UUID
        current_user: Currently authenticated user
        db: Database session

    Returns:
        List[TeamMemberResponse]: List of team members

    Raises:
        HTTPException: If team not found or access denied
    """
    try:
        db: Session = current_user_ctx["db"]
        service = TeamManagementService(db)
        team = await service.get_team_by_id(team_id)
        if team is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )
        # Check if user is team owner
        members = await service.get_team_members(team_id)
        if not members:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No members Found")

        member_responses = []
        for user, member in members:
            member_responses.append(TeamMemberResponse(
                id=member.id, 
                team_id=member.team_id, 
                user_email=member.user_email, 
                role=member.role, 
                joined_at=member.joined_at, 
                invited_by=member.invited_by, 
                is_active=member.is_active))
            logger.debug(f"members data added to member responses for {team_id}")
        return member_responses
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing team members for team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list team members")

#-------------------
# Update Team Member
#-------------------

@teams_router.put("/{team_id}/members/{user_email}", response_model=TeamMemberResponse)
@require_permission("teams.manage_members")
async def update_team_member(
    team_id: str, 
    user_email: str, 
    request: TeamMemberUpdateRequest, 
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
) -> TeamMemberResponse:
    """Update a team member's role.

    Args:
        team_id: Team UUID
        user_email: Email of the member to update
        request: Member update request data
        current_user: Currently authenticated user
        db: Database session

    Returns:
        TeamMemberResponse: Updated member data

    Raises:
        HTTPException: If member not found, access denied, or update fails
    """
    try:
        db: Session = current_user_ctx["db"]
        service = TeamManagementService(db)
        team = await service.get_team_by_id(team_id)
        if team is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )
        role = await service.get_user_role_in_team(current_user_ctx["email"], team_id)
        if user_email == current_user_ctx and role == "owner":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Self Demotion Restricted.")
        member = await service.update_member_role(team_id, user_email, request.role)
        if not member:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team member not found")
        
        return TeamMemberResponse(id=member.id, team_id=member.team_id, user_email=member.user_email, role=member.role, joined_at=member.joined_at, invited_by=member.invited_by, is_active=member.is_active)
    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Member update failed: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating team member {user_email} in team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update team member")

#-------------------
# Delete Team Member
#-------------------

@teams_router.delete("/{team_id}/members/{user_email}", response_model=SuccessResponse)
@require_permission("teams.manage_members")
async def remove_team_member(
    team_id: str, 
    user_email: str, 
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
    ) -> SuccessResponse:
    """Remove a team member.

    Args:
        team_id: Team UUID
        user_email: Email of the member to remove
        current_user: Currently authenticated user
        db: Database session

    Returns:
        SuccessResponse: Success confirmation

    Raises:
        HTTPException: If member not found, access denied, or removal fails
    """
    try:
        db: Session = current_user_ctx["db"]
        service = TeamManagementService(db)

        # Users can remove themselves, or owners can remove others
        role = await service.get_user_role_in_team(user_email, team_id)
        if role == "owner":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner Deletion not allowed")
        elif role == None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team member not found")
        
        success = await service.remove_member_from_team(team_id, user_email)
        if success:
            return SuccessResponse(message="Team member removed successfully")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Member Deletion Unsuccessful")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing team member {user_email} from team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to remove team member")


# ---------------------------------------------------------------------------
# Team Invitations
# ---------------------------------------------------------------------------
#------------------------
# Invite Member to a Team
#------------------------

@teams_router.post("/{team_id}/invitations", response_model=TeamInvitationResponse, status_code=status.HTTP_201_CREATED)
@require_permission("teams.manage_members")
async def invite_team_member(
    team_id: str, 
    request: TeamInviteRequest, 
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
    ) -> TeamInvitationResponse:
    """Invite a user to join a team.

    Args:
        team_id: Team UUID
        request: Invitation request data
        current_user: Currently authenticated user
        db: Database session

    Returns:
        TeamInvitationResponse: Created invitation data

    Raises:
        HTTPException: If team not found, access denied, or invitation fails
    """
    try:
        db: Session = current_user_ctx["db"]
        team_service = TeamManagementService(db)
        invitation_service = TeamInvitationService(db)

        invitation = await invitation_service.create_invitation(team_id=team_id, email=str(request.email), role=request.role, invited_by=current_user_ctx["email"])

        if not invitation:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create invitation")

        # Get team name for response
        team = await team_service.get_team_by_id(team_id)
        team_name = team.name if team else "Unknown Team"

        return TeamInvitationResponse(
            id=invitation.id,
            team_id=invitation.team_id,
            team_name=team_name,
            email=invitation.email,
            role=invitation.role,
            invited_by=invitation.invited_by,
            invited_at=invitation.invited_at,
            expires_at=invitation.expires_at,
            token=invitation.token,
            is_active=invitation.is_active,
            is_expired=invitation.is_expired(),
        )
    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Team invitation failed: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating team invitation for team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create invitation")

#-----------------------------
# Get list of team invitations
#----------------------------

@teams_router.get("/{team_id}/invitations", response_model=List[TeamInvitationResponse])
@require_permission("teams.read")
async def list_team_invitations(
    team_id: str, 
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
    ) -> List[TeamInvitationResponse]:
    """List team invitations.

    Args:
        team_id: Team UUID
        current_user: Currently authenticated user
        db: Database session

    Returns:
        List[TeamInvitationResponse]: List of team invitations

    Raises:
        HTTPException: If team not found or access denied
    """
    try:
        db: Session = current_user_ctx["db"]
        team_service = TeamManagementService(db)
        invitation_service = TeamInvitationService(db)

        invitations = await invitation_service.get_team_invitations(team_id)
        if invitations is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No invitations Found")

        # Get team name for responses
        team = await team_service.get_team_by_id(team_id)
        team_name = team.name if team else "Unknown Team"

        invitation_responses = []
        for invitation in invitations:
            invitation_responses.append(
                TeamInvitationResponse(
                    id=invitation.id,
                    team_id=invitation.team_id,
                    team_name=team_name,
                    email=invitation.email,
                    role=invitation.role,
                    invited_by=invitation.invited_by,
                    invited_at=invitation.invited_at,
                    expires_at=invitation.expires_at,
                    token=invitation.token,
                    is_active=invitation.is_active,
                    is_expired=invitation.is_expired(),
                )
            )

        return invitation_responses
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing team invitations for team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list invitations")

#------------------------
# Accept team invitation testing
#------------------------

@teams_router.post("/invitations/{token}/accept", response_model=TeamMemberResponse)
@require_permission("teams.accept")
async def accept_team_invitation(
    token: str,
    user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> TeamMemberResponse:
    """Accept a team invitation.

    Args:
        token: Invitation token
        user: Current authenticated user (dict from get_current_user_with_permissions)
        db: Database session

    Returns:
        TeamMemberResponse: New team member data

    Raises:
        HTTPException: If invitation not found, expired, or acceptance fails
    """
    try:
        invitation_service = TeamInvitationService(db)

        # user is the dict context, use user["email"]
        member = await invitation_service.accept_invitation(token, user["email"])

        if not member:
            # Service returned None – treat as invalid/expired
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired invitation",
            )
        
        return TeamMemberResponse(
            id=member.id,
            team_id=member.team_id,
            user_email=member.user_email,
            role=member.role,
            joined_at=member.joined_at,
            invited_by=member.invited_by,
            is_active=member.is_active,
        )

    except ValueError as e:
        # Validation / business logic errors → 400
        logger.error(f"Invitation acceptance failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error accepting invitation {token}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to accept invitation",
        )

#------------------------
#Reject team invitation
#------------------------
@teams_router.delete("/invitations/{token}/reject", response_model=SuccessResponse)
@require_permission("teams.invite")
async def reject_team_invitation(
    token: str,
    current_user_ctx: dict = Depends(get_current_user_with_permissions),
) -> SuccessResponse:
    """
    Reject (decline) a team invitation sent to the current user.

    Args:
        token: Invitation token
        current_user_ctx: Authenticated user context

    Returns:
        SuccessResponse: Confirmation of rejection

    Raises:
        HTTPException: If invitation not found or rejection fails
    """
    try:
        db: Session = current_user_ctx["db"]
        user_email: str = current_user_ctx["email"]

        invitation_service = TeamInvitationService(db)

        success = await invitation_service.decline_invitation(
            token=token,
            declining_user_email=user_email
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to reject invitation"
            )

        return SuccessResponse(
            message="Team invitation rejected successfully"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting invitation with token {token}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reject invitation"
        )

#------------------------
# Revoke team invitation
#------------------------
@teams_router.delete("/{team_id}/invitations/{invitation_id}", response_model=SuccessResponse)
@require_permission("teams.manage_members")
async def cancel_team_invitation(
    team_id:str,
    invitation_id: str, 
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
    ) -> SuccessResponse:
    """Cancel a team invitation.

    Args:
        invitation_id: Invitation UUID
        current_user: Currently authenticated user
        db: Database session

    Returns:
        SuccessResponse: Success confirmation

    Raises:
        HTTPException: If invitation not found, access denied, or cancellation fails
    """
    try:
        db: Session = current_user_ctx["db"]
        team_service = TeamManagementService(db)
        invitation_service = TeamInvitationService(db)

        is_admin = current_user_ctx.get("is_admin", False)

        # Get invitation to check team permissions
        # First-Party
        from mcpgateway.db import EmailTeamInvitation
        role = await team_service.get_user_role_in_team(current_user_ctx["email"], team_id)
        invitation = db.query(EmailTeamInvitation).filter(EmailTeamInvitation.id == invitation_id).first()
        if not invitation:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found")

        if invitation.team_id != team_id:
            raise HTTPException(status_code=400, detail="Invitation does not belong to the specified team")

        if is_admin or role == "owner":
            success = await invitation_service.revoke_invitation(invitation_id, current_user_ctx["email"], is_admin=is_admin)

        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found")

        return SuccessResponse(message="Team invitation cancelled successfully")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling invitation {invitation_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to cancel invitation")

#-------------------------
# Request to join a  team 
#-------------------------

@teams_router.post("/{team_id}/join", response_model=TeamJoinRequestResponse)
@require_permission("teams.join")
async def request_to_join_team(
    team_id: str,
    join_request: TeamJoinRequest,
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
) -> TeamJoinRequestResponse:
    """Request to join a public team.

    Allows users to request membership in public teams. The request will be
    pending until approved by a team owner.

    Args:
        team_id: ID of the team to join
        join_request: Join request details including optional message
        current_user: Currently authenticated user
        db: Database session

    Returns:
        TeamJoinRequestResponse: Created join request details

    Raises:
        HTTPException: If team not found, not public, user already member, or request fails
    """
    try:
        db: Session = current_user_ctx["db"]
        team_service = TeamManagementService(db)

        # Validate team exists and is public
        team = await team_service.get_team_by_id(team_id)
        join_req = await team_service.create_join_request(team_id=team_id, user_email=current_user_ctx["email"], message=join_request.message)

        return TeamJoinRequestResponse(
            id=join_req.id,
            team_id=join_req.team_id,
            team_name=team.name,
            user_email=join_req.user_email,
            message=join_req.message,
            status=join_req.status,
            requested_at=join_req.requested_at,
            expires_at=join_req.expires_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating join request for team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create join request")


@teams_router.delete("/{team_id}/leave", response_model=SuccessResponse)
async def leave_team(
    team_id: str,
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
) -> SuccessResponse:
    """Leave a team.

    Allows users to remove themselves from a team. Cannot leave personal teams
    or if they are the last owner of a team.

    Args:
        team_id: ID of the team to leave
        current_user: Currently authenticated user
        db: Database session

    Returns:
        SuccessResponse: Confirmation of leaving the team

    Raises:
        HTTPException: If team not found, user not member, cannot leave personal team, or last owner
    """
    try:
        db: Session = current_user_ctx["db"]
        team_service = TeamManagementService(db)

        # Validate team exists
        team = await team_service.get_team_by_id(team_id)
        user_role = await team_service.get_user_role_in_team(current_user_ctx["email"], team_id)
        if team is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
        elif team.is_personal:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot leave personal team")
        elif not user_role:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is not a member of this team")

        # Remove user from team
        success = await team_service.remove_member_from_team(team_id, current_user_ctx["email"], removed_by=current_user_ctx["email"])
        if not success:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot leave team - you may be the last owner")

        return SuccessResponse(message="Successfully left the team")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error leaving team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to leave team")


@teams_router.get("/{team_id}/join-requests", response_model=List[TeamJoinRequestResponse])
@require_permission("teams.manage_members")
async def list_team_join_requests(
    team_id: str,
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
) -> List[TeamJoinRequestResponse]:
    """List pending join requests for a team.

    Only team owners can view join requests for their teams.

    Args:
        team_id: ID of the team
        current_user: Currently authenticated user
        db: Database session

    Returns:
        List[TeamJoinRequestResponse]: List of pending join requests

    Raises:
        HTTPException: If team not found or user not authorized
    """
    try:
        db: Session = current_user_ctx["db"]
        team_service = TeamManagementService(db)

        # Validate team exists and user is owner
        team = await team_service.get_team_by_id(team_id)
        if team is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
        join_requests = await team_service.list_join_requests(team_id)

        if join_requests is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No team join requests found")

        return [
            TeamJoinRequestResponse(
                id=req.id,
                team_id=req.team_id,
                team_name=team.name,
                user_email=req.user_email,
                message=req.message,
                status=req.status,
                requested_at=req.requested_at,
                expires_at=req.expires_at,
            )
            for req in join_requests
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing join requests for team {team_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list join requests")

@teams_router.post("/{team_id}/join-requests/{request_id}/approve", response_model=TeamMemberResponse)
@require_permission("teams.manage_members")
async def approve_join_request(
    team_id: str,
    request_id: str,
    user=Depends(get_current_user_with_permissions),
) -> TeamMemberResponse:
    """Approve a team join request.

    Only team owners can approve join requests for their teams.
    """
    try:
        db: Session = user["db"]
        current_email: str = user["email"]

        team_service = TeamManagementService(db)

        # Validate team exists and user is owner
        team = await team_service.get_team_by_id(team_id)
        if team is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found",
            )

        # Approve join request
        member = await team_service.approve_join_request(
            request_id,
            approved_by=current_email,
        )
        if not member:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Approving Join Request Failed",
            )

        return TeamMemberResponse(
            id=member.id,
            team_id=member.team_id,
            user_email=member.user_email,
            role=member.role,
            joined_at=member.joined_at,
            invited_by=member.invited_by,
            is_active=member.is_active,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving join request {request_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve join request",
        )

@teams_router.delete("/{team_id}/join-requests/{request_id}", response_model=SuccessResponse)
@require_permission("teams.manage_members")
async def reject_join_request(
    team_id: str,
    request_id: str,
    current_user_ctx: dict = Depends(get_current_user_with_permissions)
) -> SuccessResponse:
    """Reject a team join request.

    Only team owners can reject join requests for their teams.

    Args:
        team_id: ID of the team
        request_id: ID of the join request
        current_user: Currently authenticated user
        db: Database session

    Returns:
        SuccessResponse: Confirmation of rejection

    Raises:
        HTTPException: If request not found or user not authorized
    """
    try:
        db: Session = current_user_ctx["db"]
        team_service = TeamManagementService(db)

        # Validate team exists and user is owner
        team = await team_service.get_team_by_id(team_id)
        if team is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
        success = await team_service.reject_join_request(request_id, rejected_by=current_user_ctx["email"])

        # Reject join request
        if not success:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Rejection of Join Request Failed")

        return SuccessResponse(message="Join request rejected successfully")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting join request {request_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to reject join request")
