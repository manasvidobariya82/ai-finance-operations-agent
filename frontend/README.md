# Finance Operations Agent — Frontend

React + TypeScript + Vite dashboard for the invoice pipeline backend (`../app`).

## Pages

- `/` — invoice list, filterable by approval status
- `/upload` — upload a PDF/PNG/JPEG invoice and run it through the pipeline
- `/invoices/:id` — extracted fields, validation/duplicate/fraud results, approve/reject actions,
  and the resulting journal entry once approved

## Running

```
npm install
npm run dev
```

Talks to the backend at `VITE_API_BASE_URL` (see `.env.example`), defaulting to
`http://localhost:8000`. The backend must be running separately (`../README.md`) with CORS
configured to allow this dev server's origin.

## Build

```
npm run build
```

Type-checks (`tsc -b`) then produces a production build in `dist/`.
