# BruteShield AI

A safe, lab-only brute-force detection and prevention platform for academic demonstrations. The application uses synthetic authentication events and never targets external sites or real accounts.

## Architecture

- `frontend/`: React + Vite SOC console, deployed to Vercel.
- `backend/`: FastAPI service with explainable rule-based risk scoring, WebSocket-ready live events, safe simulator, defense controls, and in-memory lab data, deployed to Render.
- Synthetic events are explicitly labelled and can be generated from the Safe Test Laboratory.

## Local run

```bash
# backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# frontend, in another terminal
cd frontend
npm install
VITE_API_URL=http://localhost:8000 npm run dev
```

Open the Vite URL. For deployment, set Vercel variable `VITE_API_URL` to the Render service URL.

## Safety boundary

All automatic blocking is restricted to synthetic events and the local demo environment. Dry-run mode is enabled by default. No passwords are stored; no external authentication targets are contacted.
