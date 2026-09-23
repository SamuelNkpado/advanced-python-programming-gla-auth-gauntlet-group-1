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
# | Session Auth      |  Yes       |    Yes    |  No (cookie only) |     No   |
# | Opaque Token Auth |  No        |    Yes    |  No (token only)  |     No   |
# | JWT               |  No        |    No     |          Yes      |     No   |
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
    #   After deleting the `sessionid` cookie and refreshing /admin/, we are
    #   redirected to /admin/login/ (302) — we are logged out. The cookie holds
    #   no user data; it is only a random key pointing to a row in the server's
    #   django_session table (which stores the _auth_user_id). With no cookie,
    #   the browser sends no key, so the server cannot look up that row and
    #   treats us as anonymous. The session row itself still exists in the DB
    #   until it expires or the user logs out.
    #   (This endpoint, /api/session/, likewise returns 403 without the cookie.)
    # Synthesis answer (how session fixation works):
    #   Re-adding the copied `sessionid` value and refreshing logs us straight
    #   back in as admin — no username or password needed — because the server
    #   still has the matching session row and only checks that the cookie's
    #   key exists in django_session. So an attacker only needs to steal the
    #   cookie value (e.g. by sniffing plain HTTP, XSS, or a shared machine)
    #   while the session is active; they "hijack" a session the real user
    #   already authenticated. That is session hijacking. Defences: HTTPS +
    #   Secure/HttpOnly cookies, short expiry, and logging out (which deletes
    #   the server-side row and makes the stolen cookie useless).
    #   (Related but different: session *fixation* is when the attacker plants
    #   a known session ID on the victim before login; Django prevents it by
    #   rotating the session key on login.)

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
    #   401 Unauthorized — the server looks the token in the DB, finds no match, and then it rejects the request.
    
    # Q2 answer (algorithm used to hash admin's password in the DB):
    #   pbkdf2_sha256 — Django never stores the raw password. It runs it through
    #   PBKDF2 with SHA-256 and a random salt so that even if the DB is leaked,
    #   an attacker cannot reverse the hash back to "admin123".
    
    # Synthesis answer (revoking opaque token vs JWT):
    #   To permanently invalidate a stolen opaque token, an admin must delete its
    #   row from the authtoken_token table — only someone with DB or admin access can do that.
    #   A JWT cannot be revoked the same way because it is never stored; the only
    #   options are to let it expire naturally or maintain a server-side blocklist,
    #   which reintroduces the stateful DB lookup JWT was designed to avoid.

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
    #   Decoding the access token on jwt.io reveals the payload:
    #     token_type  -> "access"  (distinguishes this from a refresh token)
    #     exp         -> Unix expiry timestamp; set to 30 minutes after issue
    #                    by SIMPLE_JWT.ACCESS_TOKEN_LIFETIME in settings.py
    #     iat         -> issued-at Unix timestamp
    #     jti         -> unique token ID (used for revocation/blocklists)
    #     user_id     -> the identifying piece of user data ("1" for admin);
    #                    this is what tells the server WHICH user the token
    #                    represents, all without any database query.
    #
    # Q2 answer (how the server validates the token without a DB lookup):
    #   The third segment of the JWT is a signature — an HMAC-SHA256 hash of
    #   the header + payload computed with the server's SECRET_KEY. On every
    #   request, JWTAuthentication re-computes that hash and compares it to
    #   the signature in the token. If they match, the payload is trustworthy
    #   and no database query is needed; if they differ, the token is rejected.
    #
    # Synthesis answer (tampered JWT rejection):
    #   After editing user_id from "1" to "2" on jwt.io and resending, the
    #   server returned 401 Unauthorized with "Token is invalid". The payload
    #   is still structurally valid JSON, but it no longer matches the
    #   signature — the server recomputes the signature with its SECRET_KEY
    #   over the modified header+payload and gets a different value, so
    #   verification fails. This proves the signature is what makes a JWT
    #   tamper-evident: without the SECRET_KEY an attacker cannot forge a
    #   matching signature, so any change to the payload is detected.

    return Response({"message": "JWT authenticated.", "user": request.user.username})