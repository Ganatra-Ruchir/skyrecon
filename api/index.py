"""
Vercel serverless entrypoint.

Vercel runs Python as a function, not as a long-lived server, which changes two
things that matter to this application:

1. The filesystem is read-only apart from /tmp, and /tmp is wiped when the
   function goes cold. A SQLite database there survives minutes, not days, so
   accounts, indicators, alerts and the audit chain all reset on their own.
   Point SKYRECON_DATABASE_URL at a hosted PostgreSQL to keep them.

2. Every cold start is a new process. The in-process rate limiter and the
   anomaly model start empty each time, so both are weaker here than in a
   container that stays up.

Neither is a bug - it is what serverless is. For an instance that keeps its
data and its detection state, deploy the Dockerfile to Render or Fly; both
render.yaml and fly.toml are in the repository root.
"""

import os

os.environ.setdefault("SKYRECON_DATABASE_URL", "sqlite:////tmp/skyrecon.db")

from app.main import app  # noqa: E402  (env must be set before settings load)

__all__ = ["app"]
