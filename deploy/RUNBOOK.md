# Iris Dashboard — VPS Runbook (root@pixelcity.top)

One-time setup to serve the dashboard at **https://dashboard.pixelcity.dev**
via the existing Caddy in `/opt/caddy`, using Keycloak at **id.pixelcity.dev**
and payments at **payments.pixelcity.dev**.

---

## 0. Prerequisites check (on the VPS)

```bash
docker network ls                     # note the network your caddy container uses
docker ps | grep -Ei 'caddy|keycloak|payment'
dig +short dashboard.pixelcity.dev    # must resolve to this VPS (add DNS A record if not)
```

If `dashboard.pixelcity.dev` has no DNS record yet, create an `A` record → VPS IP
(same zone as `payments.pixelcity.dev` / `id.pixelcity.dev`). Caddy obtains the
TLS certificate automatically on first request.

## 1. Create the Keycloak client (id.pixelcity.dev)

Admin console → realm `pixelcity` → **Clients → Create client**:

| Field | Value |
|---|---|
| Client type | OpenID Connect |
| Client ID | `iris-dashboard` |
| Client authentication | **On** (confidential) |
| Standard flow | Enabled |
| Root URL | `https://dashboard.pixelcity.dev` |
| Valid redirect URIs | `https://dashboard.pixelcity.dev/auth/callback` |
| Web origins | `https://dashboard.pixelcity.dev` |

Save → **Credentials** tab → copy the **Client secret**.

Also create/verify the public CLI client (used by `iris cloud login`):

| Field | Value |
|---|---|
| Client ID | `iris-cli` |
| Client authentication | **Off** (public) |
| Standard flow | Enabled |
| Direct access grants | Off |
| OAuth 2.0 Device Authorization Grant | **Enabled** (needed for CLI device flow) |

## 2. Upload & start the dashboard

From your machine (repo root):

```bash
ssh root@pixelcity.top "mkdir -p /opt/iris-dashboard"
scp -r deploy/docker-compose.yml deploy/Dockerfile deploy/.env.example dashboard/ \
    root@pixelcity.top:/opt/iris-dashboard/
```

On the VPS:

```bash
cd /opt/iris-dashboard
cp .env.example .env
nano .env    # fill SESSION_SECRET + OIDC_CLIENT_SECRET (+ PAYMENTS_BASE, CADDY_NETWORK)
docker compose up -d --build
docker compose logs -f        # expect: "Iris dashboard listening on :8080"
```

## 3. Wire it into Caddy (/opt/caddy)

Append `deploy/Caddyfile.snippet` to the Caddyfile mounted by the Caddy
container, then reload:

```bash
docker exec -w /etc/caddy caddy caddy reload --config /etc/caddy/Caddyfile
curl -sI https://dashboard.pixelcity.dev | head -5
```

> If the Caddy container cannot resolve `iris-dashboard`, both containers
> must share a docker network: `docker network connect caddy_public caddy`.

## 4. Smoke test

```bash
# OIDC discovery through Keycloak
curl -s https://id.pixelcity.dev/realms/pixelcity/.well-known/openid-configuration | head -c 200

# Dashboard login redirect (expect 302 → id.pixelcity.dev)
curl -sI https://dashboard.pixelcity.dev/auth/login | head -3
```

Open **https://dashboard.pixelcity.dev** in a browser → "Sign in with
PixelCity ID" → should land back on the dashboard showing Free plan.

On your machine, test the CLI:

```bash
iris cloud login     # device flow: opens id.pixelcity.dev, enter the code
iris cloud status
```

## 5. Payments wiring

The dashboard proxies checkout calls to `PAYMENTS_BASE`. Ensure the payments
service (zoneless container behind payments.pixelcity.dev):

1. Exposes `POST /api/v1/billing/checkout` accepting `plan`, `interval`,
   `return_url` and returning `{ "url": "<checkout-url>", "session_id": ... }`.
2. Validates the `Authorization: Bearer <Keycloak access token>` it receives
   (token issued by id.pixelcity.dev, audience `iris-dashboard` or account).
3. Calls back Keycloak/admin API or the dashboard to set the user's `tier`
   attribute to `pro`/`enterprise` after successful payment (or expose
   `GET /api/v1/plan` reading tier from Keycloak groups/attributes).

Recommended: keep `PAYMENTS_BASE` on the docker network
(`http://payments:8080`) so bearer tokens never traverse the public internet
twice.

## 6. Updating

```bash
cd /opt/iris-dashboard
# replace binary sources (scp -r dashboard/ again), then:
docker compose up -d --build
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `OIDC discovery failed` at startup | Keycloak unreachable from container — check network; try `PAYMENTS_BASE`-style public issuer reachability |
| Redirect loop on login | Wrong `OIDC_REDIRECT_URL` vs Keycloak client redirect URI (must match exactly, incl. https) |
| Caddy 502 | `docker network connect caddy_public iris-dashboard` then `caddy reload` |
| Certificate pending | DNS not pointing to VPS yet; `docker logs caddy` shows ACME errors |
| 401 on /api/v1/* | Session cookie missing/expired — sign in again; check `SESSION_SECRET` unchanged since login |
