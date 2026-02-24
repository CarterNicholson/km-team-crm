# KM Team CRM

Commercial real estate CRM built for Kidder Mathews brokers. Tracks contacts, deals, properties, listings, and tasks with an integrated AI assistant.

## Quick Start (Local)

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start

# 3. Open http://localhost:3000
# First visit will prompt you to create your admin account
```

## Features

- **Contacts** with multi-tag system, sorting, filtering, and CSV export
- **Deal Pipeline** kanban board (Prospect → Touring → LOI → Negotiating → Closed)
- **Listings Dashboard** with inquiry tracking and per-property deal pipeline
- **Properties** management with listing info
- **Tasks** linked to contacts, deals, or properties (or standalone)
- **AI Assistant** powered by Claude (each user adds their own API key)
- **Activity Log** tracking all changes across the team
- **Global Search** across all records
- **Team Management** with personal logins

## Deploy to Railway (Recommended)

1. Push this folder to a GitHub repo
2. Go to [railway.app](https://railway.app) and create a new project
3. Connect your GitHub repo
4. Add environment variables:
   - `JWT_SECRET` = a long random string (use a password generator)
   - `PORT` = 3000
5. Add a **Volume** mounted at `/data` and set:
   - `DB_PATH` = /data/crm.db
6. Deploy — Railway gives you a public URL

### Alternative: Render.com

1. Push to GitHub
2. Create a new **Web Service** on [render.com](https://render.com)
3. Build command: `npm install`
4. Start command: `node server.js`
5. Add environment variables: `JWT_SECRET`, `PORT=3000`
6. Add a **Disk** mounted at `/data`, set `DB_PATH=/data/crm.db`

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes (prod) | Secret key for auth tokens. Use a long random string. |
| `PORT` | No | Server port (default: 3000) |
| `DB_PATH` | No | Path to SQLite database file (default: ./crm.db) |

## Tech Stack

- **Backend:** Node.js + Express + SQLite (better-sqlite3)
- **Frontend:** React 18 + Tailwind CSS (CDN, no build step)
- **Auth:** JWT tokens + bcrypt
- **AI:** Claude API (Anthropic) via user-provided API keys

## Team Setup

1. First person to visit creates the admin account
2. Admin adds team members in Settings → Team Management
3. Each team member gets their own login
4. (Optional) Each member can add their own Claude API key in Settings for AI features

## Data

All data is stored in a single SQLite file (`crm.db`). Back it up regularly. The file is created automatically on first run.
