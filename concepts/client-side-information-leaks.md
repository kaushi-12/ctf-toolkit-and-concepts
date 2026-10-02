# Client-Side Information Leaks

## Vulnerability: Session Enumeration via Exposed `/sessions` Endpoint

### Question
cylab , pico ctf : 'old sessions'
level:easy 

### Summary
The application exposes a debug/diagnostic endpoint at `/sessions` that dumps
the entire server-side session store in plaintext — including session IDs and
the associated username (`key`) for every active session, such as `admin`.
Because the application trusts the `session` cookie value as a bearer token
with no additional binding (e.g. to IP, user-agent, or a signed/encrypted
payload validated against tampering), an attacker can simply copy a leaked
session ID into their own cookie and be authenticated as that user —
including `admin` — without ever knowing a password.


### Discovery
While browsing the public comments feed on the homepage, one comment
(posted by user `mary_jones_8992`) reads:

> "Hey I found a strange page at /sessions"

This comment acts as an in-app hint pointing toward a hidden endpoint that
was never meant to be publicly reachable.

### Steps to Reproduce

**1. Check your current session cookie**

Load the target application in the browser and open DevTools → Storage →
Cookies. Note your current `session` cookie value (e.g. `0x7camKWH...`).

![Session cookie in DevTools](./images/cookie-devtools.png)

**2. Follow the hint in the comments**

Browse the homepage comments and notice the hint from `mary_jones_8992`
referencing `/sessions`.

**3. Visit the leaked endpoint**

Navigate to `http://chatelaine.cylabacademy.net:33957/sessions` and observe
the full session store dumped in plaintext:


![Leaked sessions dump](./images/sessions-leak.png)

**4. Confirm `admin` is a real account**

Check the Comments section on the homepage, where a comment from user
`Admin` ("Hello world!") proves the account is legitimate and has
activity history — not a decoy.

**5. Swap the session cookie**

In DevTools → Storage → Cookies, edit the `session` cookie value for the
current domain, replacing it with the leaked admin session ID:
`0x7camKWHuwy67bllj4Ir6fC8dGmjqts7KewW4HrgpY`.

**6. Confirm account takeover**

Refresh the homepage. The application now renders "Welcome *admin*"
instead of the original user, confirming a full account takeover.

![Welcome admin homepage](./images/welcome-admin.png)

*(For comparison, here is the homepage under the other leaked session,
`key: blah`, showing the same mechanism works for any session ID in the
dump — not just admin's.)*

![Welcome blah homepage](./images/welcome-blah.png)

**7. Flag**

The flag is revealed on the authenticated admin homepage:
`academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}`

### Evidence
- `/sessions` endpoint leaking raw session store contents (session ID → username mapping)
- Admin's own comment in the public feed, proving the account's legitimacy and activity history
- Successful cookie swap resulting in "Welcome admin" on reload

### Root Cause
- A debug/administrative route (`/sessions`) was left accessible in a
  production-like environment with no authentication or access control.
- Session identifiers are used as the sole proof of identity, with no
  server-side revalidation (e.g. checking IP/user-agent consistency) and
  no cryptographic signing that would make a copied ID useless outside
  its original context.
- Sensitive session metadata (usernames) is stored and exposed in a
  human-readable, guessable-adjacent format rather than being opaque.

### Impact
Full account takeover of any user — including administrators — simply by
reading an exposed endpoint and copying a cookie value. No credentials,
XSS, or active exploitation of the victim's browser is required; this is
a pure server-side information disclosure bug that leaks the equivalent
of a bearer token.

### Remediation
1. **Remove or restrict** the `/sessions` debug endpoint entirely in any
   non-development environment; gate it behind strong authentication and
   an internal-only network if it must exist at all.
2. **Never expose session store contents** (IDs, usernames, or any session
   data) through any public-facing route.
3. **Rotate session IDs** on privilege change (e.g. login) and set short,
   enforced expirations — don't rely on `_permanent: True` sessions that
   never expire.
4. **Bind sessions to additional signals** (e.g. IP address, user-agent
   fingerprint) or use signed/encrypted client-side session cookies
   (e.g. Flask's default signed cookie sessions) so a raw session ID
   cannot be reused outside its original context.
5. **Audit public-facing content** (like user comments) for accidental
   hints/leaks about internal routes, and ensure discovery of an internal
   path alone is never sufficient to compromise the system.

### Classification
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **CWE-384**: Session Fixation (related — the app accepts attacker-chosen/reused session IDs)
- **OWASP Top 10**: A01:2021 – Broken Access Control / A04:2021 – Insecure Design
