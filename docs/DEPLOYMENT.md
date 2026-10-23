# Deployment Guide (Vercel)

**Live Production URL:** [https://cyberops-simulator.vercel.app](https://cyberops-simulator.vercel.app)

CyberOps Simulator is a static Vite single-page application (SPA) designed to deploy seamlessly on the **Vercel Hobby (Free)** plan with zero backend dependencies or API keys.

## Vercel Configuration

The repository includes `vercel.json` to ensure direct navigation or browser refreshes on client-side routes (`/soc`, `/lab`, `/settings`, `/mission/:id/briefing`, `/mission/:id/investigate`, `/mission/:id/debrief`) rewrite cleanly to `/index.html`:

```json
{
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

## Deploying via Vercel CLI

```bash
# Verify local production build first
npm test
npm run build

# Deploy to production on Vercel
vercel --prod --yes
```

## Post-Deployment Verification Checklist

1. Open the production URL and verify the Main Menu renders with no console errors.
2. Navigate directly to `/soc` and `/mission/mission-1-noisy-login/investigate` and refresh the page to confirm SPA rewrite routing works without a 404.
3. Run a structured query, collect evidence, execute a simulated response action, and refresh the browser to confirm local persistence (`localStorage` + `IndexedDB`) restores the workspace.
4. Submit an incident report and test exporting the report JSON.
