# Toolkit proxy Worker

Live Cloudflare Worker name: `toolkit`.

It serves [https://toolkit.starswarm.workers.dev/](https://toolkit.starswarm.workers.dev/) by fetching the GitHub Pages build named in `UPSTREAM` inside `worker.js`. If that Pages path changes, update `UPSTREAM` and redeploy. The app itself stays a static site.

This file matches the Worker already deployed. It has no secrets.
