# Firewatch EDR

AI-powered Endpoint Detection & Response platform with autonomous remediation engine.

## Install

```bash
wget -q https://raw.githubusercontent.com/pabloaverbuj/firewatch-edr/main/docker-compose.yml
wget -q https://raw.githubusercontent.com/pabloaverbuj/firewatch-edr/main/.env.example -O .env
```

Edit `.env` — the only required value is `ANTHROPIC_API_KEY`:

```bash
nano .env
```

Launch:

```bash
docker compose up -d
```

Open **http://localhost** and complete the setup wizard.

---

## Update

```bash
docker compose pull
docker compose up -d
```

## Stop

```bash
docker compose down
```

## Uninstall (removes all data)

```bash
docker compose down -v
```

---

## Configuration

All configuration is via `.env`. The only required field is `ANTHROPIC_API_KEY`.

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | **Required.** Your Anthropic API key |
| `PORT` | `80` | Port to expose the web interface |
| `DB_PASSWORD` | `firewatch_secret` | PostgreSQL password |
| `SECRET_KEY` | `change-me` | JWT secret (change in production) |

## Architecture

```
Browser → nginx → FastAPI backend → PostgreSQL + Redis
                      ↓
              Remediation Engine
              (Claude AI + Adapters)
              ↓           ↓
         MikroTik     Entra ID
```
