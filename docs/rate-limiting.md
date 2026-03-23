# Rate Limiting

File upload endpoints are high-value targets for abuse. Without
rate limiting, attackers can exhaust server resources through
rapid-fire uploads, even when each individual file passes
validation. **safeuploads validates file content — rate limiting
protects the endpoint itself.**

## Why Rate Limiting Matters for Uploads

| Threat | Impact | Mitigation |
|---|---|---|
| Denial of service via bulk uploads | CPU/memory/disk exhaustion | Per-IP request limits |
| Credential-stuffing with file payloads | Account compromise | Per-user throttling |
| Storage exhaustion | Disk full, service outage | Global upload quotas |
| Zip bomb floods | CPU exhaustion during analysis | Combined with `ResourceMonitor` |

## Recommended Limits

| Endpoint type | Suggested rate | Burst |
|---|---|---|
| Image upload | 10 req/min per IP | 3 |
| ZIP upload | 5 req/min per IP | 2 |
| Batch upload | 3 req/min per IP | 1 |
| Authenticated user | 30 req/min per user | 10 |

Adjust based on your application's expected traffic patterns.

---

## FastAPI with SlowApi

[SlowApi](https://github.com/laurents/slowapi) wraps
[limits](https://limits.readthedocs.io/) for use with Starlette
and FastAPI.

### Installation

```bash
pip install slowapi
```

### Basic Setup

```python
from fastapi import FastAPI, Request, UploadFile
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from safeuploads import FileValidator

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded, _rate_limit_exceeded_handler
)

validator = FileValidator()


@app.post("/upload/image")
@limiter.limit("10/minute")
async def upload_image(request: Request, file: UploadFile):
    await validator.validate_image_file(file)
    return {"filename": file.filename}


@app.post("/upload/zip")
@limiter.limit("5/minute")
async def upload_zip(request: Request, file: UploadFile):
    await validator.validate_zip_file(file)
    return {"filename": file.filename}
```

### Per-User Limits (Authenticated)

```python
from fastapi import Depends


def get_user_id(request: Request) -> str:
    """Extract user identifier for rate limiting."""
    # Replace with your auth logic
    user = request.state.user
    return str(user.id)


user_limiter = Limiter(key_func=get_user_id)


@app.post("/upload/image")
@user_limiter.limit("30/minute")
async def upload_image_authed(
    request: Request,
    file: UploadFile,
    user=Depends(get_current_user),
):
    await validator.validate_image_file(file)
    return {"filename": file.filename}
```

### Custom Error Response

```python
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded


async def rate_limit_handler(
    request: Request, exc: RateLimitExceeded
):
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "message": "Too many upload requests",
            "retry_after": exc.detail,
        },
        headers={"Retry-After": str(exc.detail)},
    )


app.add_exception_handler(
    RateLimitExceeded, rate_limit_handler
)
```

---

## Custom Middleware (No Dependencies)

If you prefer not to add `slowapi`, a simple token-bucket
middleware works for basic per-IP limiting:

```python
import time
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Token bucket per IP
_buckets: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = 10  # requests
WINDOW = 60  # seconds


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if not request.url.path.startswith("/upload"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()

    # Remove expired timestamps
    _buckets[client_ip] = [
        ts for ts in _buckets[client_ip]
        if now - ts < WINDOW
    ]

    if len(_buckets[client_ip]) >= RATE_LIMIT:
        return JSONResponse(
            status_code=429,
            content={
                "error": "rate_limit_exceeded",
                "message": "Too many upload requests",
            },
        )

    _buckets[client_ip].append(now)
    return await call_next(request)
```

!!! warning
    This in-memory approach does not work across multiple
    workers or server instances. Use Redis-backed storage
    (via SlowApi or similar) for production deployments.

---

## Reverse Proxy Rate Limiting

For production, rate limiting at the reverse proxy layer is
more efficient and protects the application before requests
reach Python.

### nginx

```nginx
# Define a rate limit zone (10 req/min per IP)
limit_req_zone $binary_remote_addr
    zone=uploads:10m rate=10r/m;

server {
    # Apply to upload endpoints
    location /upload {
        limit_req zone=uploads burst=3 nodelay;
        limit_req_status 429;

        # Also limit upload body size
        client_max_body_size 20m;

        proxy_pass http://app:8000;
    }
}
```

### Caddy

```caddy
example.com {
    route /upload/* {
        rate_limit {
            zone upload_zone {
                key {remote_host}
                events 10
                window 1m
            }
        }
        reverse_proxy app:8000
    }
}
```

### Traefik

```yaml
# Dynamic configuration
http:
  middlewares:
    upload-rate-limit:
      rateLimit:
        average: 10
        burst: 3
        period: 1m

  routers:
    upload:
      rule: "PathPrefix(`/upload`)"
      middlewares:
        - upload-rate-limit
      service: app
```

---

## Combining with safeuploads

Rate limiting and file validation are complementary layers:

```
Client Request
  │
  ▼
┌──────────────────────┐
│  Reverse Proxy       │  ← nginx/Caddy rate limit + body size
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Application         │  ← SlowApi per-IP/per-user limits
│  Rate Limiter        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  safeuploads         │  ← File validation + resource limits
│  FileValidator       │
└──────────┬───────────┘
           │
           ▼
     File accepted
```

- **Reverse proxy**: Stops floods before they reach Python.
- **Application limiter**: Enforces per-user or per-endpoint
  quotas after authentication.
- **safeuploads**: Validates file content, detects attacks,
  enforces resource limits via `ResourceMonitor`.

See [examples/fastapi_example.py](https://github.com/endurain-project/safeuploads/blob/main/examples/fastapi_example.py)
for a complete working example with rate limiting integrated.
