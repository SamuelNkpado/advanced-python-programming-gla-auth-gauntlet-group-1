# ─────────────────────────────────────────────────────────────────────────────
# api/views.py — Authentication Gauntlet Lab
#
# Wrap-Up Comparison Table (Reporter fills this in at the end of the lab):
#
# +-------------------+------------+-----------+-------------------+----------+
# | Method            | Stateful?  | DB Lookup?| Credentials sent  | Safe on  |
# |                   |            |           | every request?    | HTTP?    |
# +-------------------+------------+-----------+-------------------+----------+
# | Basic Auth        |  No        |    Yes    |          Yes      |     No   |
# | Session Auth      |            |           |                   |          |
# | Opaque Token Auth |            |           |                   |          |
# | JWT               |            |           |                   |          |
# +-------------------+------------+-----------+-------------------+----------+
#
# ─────────────────────────────────────────────────────────────────────────────

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
    TokenAuthentication,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Basic Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def basic_auth_view(request):
    # ── Driver Task ───────────────────────────────────────────────────────────
    # TODO: Extract the raw Authorization header from request.META and print
    #       it to the terminal with a descriptive label.
    #       Then return: Response({"message": "Check your terminal!"})
    #
    # Hint: the header key in request.META is 'HTTP_AUTHORIZATION'.
    # ─────────────────────────────────────────────────────────────────────────

    # Reporter — Phase 1 challenge answers:
    
    # Q1 answer (header format for admin:admin123):
    #   Basic YWRtaW46YWRtaW4xMjM= — decodes to "admin:admin123" (username:password, colon-separated).
    # Q2 answer (what happens without credentials):
    #   401 Unauthorized. Body: {"detail": "Authentication credentials were not provided."}
    #   DRF rejects the request before the view even runs — no "Incoming Header" line is printed,
    #   confirming BasicAuthentication fails upstream of the view logic.

    auth_header = request.META.get("HTTP_AUTHORIZATION")
    print(f"Incoming Header: {auth_header}")
    return Response({"message": "Check your terminal!"})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Session Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
def session_auth_view(request):
    # Reporter — Phase 2 challenge answers:
    # Q1 answer (effect of deleting the session cookie):
    # Synthesis answer (how session fixation works):

    return Response({"message": "Session authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Token Authentication (Opaque)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def token_auth_view(request):
    # Reporter — Phase 3 challenge answers:
    # Q1 answer (status code when token is tampered):
    # Q2 answer (algorithm used to hash admin's password in the DB):
    # Synthesis answer (how to revoke a token):

    return Response({"message": "Token authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — JSON Web Tokens (JWT)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def jwt_protected_view(request):
    # Reporter — Phase 4 challenge answers:
    # Q1 answer (fields found in the decoded payload):
    # Q2 answer (what happens when the signature is tampered):
    # Synthesis answer (JWT revocation challenge and workaround):

    return Response({"message": "JWT authenticated.", "user": request.user.username})
