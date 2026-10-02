# Client-Side Information Leaks

## Vulnerability: Session Enumeration via Exposed `/sessions` Endpoint

## Concept
Many web apps store session state server-side (in memory, Redis, a file store,
etc.) and only give the client an opaque session ID via a cookie. The server
is supposed to treat that ID as a secret bearer token: whoever presents it is
authenticated as the user it belongs to, with no further verification.

This design breaks down the moment **any information about the session store
itself is leaked** to the client side — a debug route, a verbose error page,
an exposed admin panel, even something accidentally printed to a public page.
If an attacker can read *any* valid session ID (not just their own), they can
simply swap their cookie for it and be instantly authenticated as that
session's owner, including privileged accounts like `admin`. No password,
no XSS, no active attack on another user's browser required — just reading
data the server should never have exposed in the first place.

This class of bug is a **client-side information leak**: sensitive
server-side state (session IDs, usernames, internal routes) ends up visible
to, or discoverable by, the client, and the app's trust model collapses
because it assumed that information would stay private.

## Challenge: picoCTF / CyLab — "Old Sessions" (Easy)

### How this challenge demonstrates the concept
- The app has a public comment feed. One comment, from `mary_jones_8992`,
  hints: *"Hey I found a strange page at /sessions"* — pointing to a hidden
  debug endpoint.
- Visiting `/sessions` dumps the **entire session store** in plaintext:
  session ID → `{'_permanent': True, 'key': <username>}`. One entry has
  `key: 'admin'`.
- A separate comment from user `Admin` ("Hello world!") confirms `admin` is
  a real, active account — not a decoy.
- Overwriting your own `session` cookie with the leaked admin session ID
  authenticates you as `admin` on reload, with no credentials involved.

### Proof of Concept

| Step | Evidence |
|---|---|
| 1. Starting session cookie (`key: blah`) | ![Session cookie in DevTools](./images/cookie-devtools.png) |
| 2. `/sessions` leaks all session IDs + owners | ![Leaked sessions dump](./images/sessions-leak.png) |
| 3. Cookie swapped to admin's session ID → authenticated as admin | ![Welcome admin homepage](./images/welcome-admin.png) |
| *(for comparison)* same app under the other leaked session | ![Welcome blah homepage](./images/welcome-blah.png) |

**Flag:** `academy{REDACTED}` — found on the authenticated admin homepage
after the cookie swap.

### Root Cause
- Debug endpoint (`/sessions`) left reachable with no auth or network restriction.
- Session IDs are the *sole* proof of identity — no binding to IP/user-agent,
  no signing, nothing that invalidates a copied ID outside its original context.
- Session metadata (usernames) is stored/exposed in a readable format instead
  of being opaque.

### Impact
Full account takeover of any leaked session, including `admin`, via a pure
information-disclosure bug — no exploitation of the victim required

### real life example
A session ID works like a hotel key card: whoever holds it gets in, and the door doesn't check who they are. If the hotel accidentally posts a list of valid key cards on a public notice board, anyone can walk into any room.

If you stay logged in to an account like Instagram on a shared computer, the session cookie stays active in that browser. Anyone using the computer afterwards could reuse that session, because websites generally treat the session value as proof of identity for the website's backend.

In both cases the attacker never needs the password. The difference is how they get the session: from a browser left logged in, or, in this challenge, from the server leaking every session ID through `/sessions`.

### Remediation
**Fix the leak itself**
- Remove the `/sessions` debug route, or put it behind authentication and network restrictions and disable it in prduction builds.
- Never return session store contents (IDs, usernames, metadata) from any client-reachable route, including error pages and logs.
- Treat internal routes as secret-adjacent: don't reference them in user-facing content such as comments.

**Limit the damage if a session ID leaks**
- Use short idle and absolute expiry times, and avoid permanent sessions (`_permanent: True`).
- Invalidate sessions server-side on logout, password change and privilege changes.
- Store a hash of the session ID server-side, so a leaked store doesn't contain usable IDs.
- Use shorter lifetimes or re-authentication for privileged (admin) sessions.

**Defense in depth (helps, but doesn't fix this bug on its own)**
- Set `HttpOnly`, `Secure` and `SameSite` on session cookies. These reduce theft through XSS and network sniffing, not a server that hands IDs out.
- Signed or encrypted cookies stop an attacker forging an ID, but not reusing a valid one they have copied.
- Binding sessions to IP or user-agent can flag anomalies, but both can be spoofed, so don't rely on them.
- Regenerate the session ID on login. This defends against session fixation, a related but different bug.


### Classification
- **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor (the core bug)
- **CWE-489:** Active Debug Code (the leftover `/sessions` route)
- **CWE-306:** Missing Authentication for Critical Function (no auth on that route)
- **CWE-613:** Insufficient Session Expiration (permanent sessions stay valid once leaked)
- **OWASP Top 10 (2021):** A01 Broken Access Control, A04 Insecure Design, A05 Security Misconfiguration, A07 Identification and Authentication Failures
