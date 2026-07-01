# web/ — operator dashboard (React + Vite + TypeScript)

A real single-page operator dashboard for `forge-backend`, replacing the earlier
static stub. Typed API client in `src/api.ts`, UI in `src/App.tsx`.

## Develop / build

```bash
cd web
npm install
npm run dev      # http://localhost:5173
npm run build    # type-check (tsc --noEmit) + production bundle in dist/
```

Point the dashboard's *API base URL* at a running backend
(`cargo run -p forge-backend`, default `http://127.0.0.1:8080`).

> CORS: the scaffold backend does not emit CORS headers; serve same-origin or via a
> proxy for browser use.
