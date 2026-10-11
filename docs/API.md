# Private API and automation

The backend is part of the desktop process. It reserves an ephemeral port on
127.0.0.1 and publishes `instance.json` in the private profile. This contains a
random 256-bit bearer token, instance UUID, port and certificate fingerprint.
Owner-only permissions are mandatory. Never copy the locator or keys into an issue.

Every REST request and WebSocket handshake requires `Authorization: Bearer TOKEN`.
Browser origins are separately checked. The private CA in `tls/ca.pem` is trusted
only by application clients; no system trust-store change is needed. TLS validation,
hostname checks and instance-identity verification remain enabled. Certificates
are renewed, including expired certificates, before the server starts.

Example read-only script, run as the profile owner while the desktop is open:

```python
import asyncio
import ssl
import httpx
from backend.bootstrap import read_locator, verify_existing
from backend.platform_utils import get_config_dir

async def main():
    profile = get_config_dir()
    locator = read_locator(profile)
    if locator is None or not await verify_existing(profile, locator):
        raise RuntimeError("Open the desktop first")
    trust = ssl.create_default_context(cafile=str(profile / "tls/ca.pem"))
    async with httpx.AsyncClient(
        base_url=f"https://127.0.0.1:{locator.port}", verify=trust,
        trust_env=False, follow_redirects=False, timeout=10,
        headers={"Authorization": "Bearer " + locator.token.get_secret_value()},
    ) as client:
        response = await client.get("/api/v1/health")
        response.raise_for_status()
        print(response.json()["version"])

asyncio.run(main())
```

Fetch `/openapi.json` through the authenticated client for schemas and routes.
Swagger `/docs` is also protected; ordinary browser navigation does not supply
the bearer header automatically. Never place it in a URL.

Mutations require a UUID `X-Request-ID`, retained for retries of that exact action.
A conflicting duplicate is rejected. An unknown or pending external command is
never repeated automatically: inspect its original framework identity and activity
before intentionally submitting a new action. Do not replace an uncertain ID merely
to bypass this check. Workspace UUIDs accompany scoped operations; switching the UI
does not change a running job's ownership. Vault routes also require the issued
`X-Vault-Token`; reveal/export require reauthentication.

WebSocket clients use the same TLS context and Authorization header. Subscriber
queues are bounded; reconnect/resynchronization reloads current state without
replaying commands. Analysis permits two running jobs and 32 waiting jobs. API
responses do not grant authority to test targets; ownership confirmation and target
validation are still enforced inside analysis services.

All WebSocket routes share an application-wide boundary: at most 65,536 UTF-8/binary bytes per message and 100 messages in a sliding second, independently for receive and send. Size violations close with 1009; rate violations close with 1013 and require REST resynchronization. Activity, desktop and connection events all travel through /ws/events and therefore share these limits; /ws/jobs and future WebSocket routers use the same middleware. The current streams reject inbound commands. Existing transport queue and subscriber bounds remain in effect.
