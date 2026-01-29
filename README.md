# 📦 Handoff — Client Portal for Freelancers

Know when clients see your work. Stop chasing clients for feedback.

**Live:** https://app.handoff.jdms.nl

## Features

- ✅ Branded client portals
- ✅ Project dashboard with Kanban board (4 stages)
- ✅ Updates feed (async communication)
- ✅ File uploads with download tracking
- ✅ Magic link auth for clients
- ✅ Client activity tracking (views, downloads)
- ✅ User accounts (login/register)

## Tech Stack

- Node.js + Express
- PostgreSQL
- Tailwind CSS
- JWT Authentication
- Docker + Docker Compose

## API Endpoints

### Auth
- `POST /api/auth/register` — Create account
- `POST /api/auth/login` — Login
- `GET /api/auth/me` — Get current user

### Portals
- `POST /api/portals` — Create portal
- `GET /api/portals` — List user's portals

### Clients
- `POST /api/portals/:id/clients` — Add client
- `GET /api/portals/:id/clients` — List clients

### Projects
- `POST /api/clients/:id/projects` — Create project
- `GET /api/clients/:id/projects` — List projects
- `GET /api/projects/:id` — Get project details

### Tasks
- `POST /api/projects/:id/tasks` — Create task
- `PATCH /api/tasks/:id` — Update task
- `DELETE /api/tasks/:id` — Delete task

### Updates
- `POST /api/projects/:id/updates` — Post update
- `GET /api/projects/:id/updates` — Get updates

### Files
- `POST /api/projects/:id/files` — Upload file
- `GET /api/projects/:id/files` — List files
- `GET /api/files/:id/download` — Download file (tracks download)

### Client Portal (magic link)
- `GET /api/portal/projects` — Client's projects
- `GET /api/portal/projects/:id` — Project detail
- `POST /api/portal/projects/:id/updates` — Client reply

## Development

```bash
docker compose up -d
```

## Key Differentiator

**Download tracking + view tracking** — Freelancers know exactly when clients see their work. No more "did they even look at it?"

---

*Day 1 of the Daily App Challenge — Built by Jenkins*
