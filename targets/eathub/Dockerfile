# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# EatHub target image. The agent base (agent_image.ensure) copies /work from
# this image and layers the pinned CLI + Node 22 on top; only /work survives
# that COPY --from, so everything the runner and app need lives under /work.
#
# Layout (load-bearing — see README.md "Layout"):
#   /work/app             the application, source_root, a git repo with a baseline
#   /work/run_poc.js      the replay runner, ONE level above source_root
#   /work/seed.js         the fixture, beside the runner
#   /work/frontend/dist/  the SPA-shell stub the app expects at __dirname/../frontend/dist
#   /work/.replays/       per-replay scratch (created at runner start; swept there)
#
# node:22-bookworm rather than gcc:14 here because this image only has to build
# node_modules with a matching ABI; at runtime the agent base's own Node 22
# takes over. The two must stay on the same major (NODE_MAJOR in
# harness/agent_image.py) so the sqlite3 native binding loads under both.
FROM node:22-bookworm

# git for the baseline repo; the native sqlite3 build needs python3 + make + g++.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git python3 make g++ ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work/app

# Install with the lockfile first, on its own layer, so an app-source edit does
# not reinstall. npm ci compiles the sqlite3 binding against this Node's ABI.
# T0 runs with network=none, so node_modules is baked in here and never
# reinstalled after a patch.
COPY app/package.json app/package-lock.json ./
RUN npm ci

# The rest of the app. .dockerignore keeps node_modules/data/.git out of the
# context; the app's own .gitignore (node_modules, /data, .env, /ai_pics) is a
# dotfile and MUST survive — the baseline commit below relies on it to keep
# node_modules and the mutable data/ dir out of `git diff`.
COPY app/ ./

# Baseline git repo at source_root. Three things depend on it:
#  - build_command's `git ls-files` can enumerate tracked JS to syntax-check;
#  - patch.py:85's `git rev-parse` short-circuits, so the pipeline stops
#    appending ../run_poc.js to .gitignore on every run;
#  - `git diff` after a patch is source-only (the app's .gitignore governs it).
RUN git init -q && \
    git config user.email pipeline && git config user.name pipeline && \
    git add -A && git commit -q -m baseline

# Runner + fixture one level ABOVE source_root, so a patch agent's `git diff`
# (scoped to /work/app) structurally cannot modify its own verifier, and so the
# runner's own file is outside app/test/no_console.test.js's scanned tree.
# +x so the agent's reproduction command runs `/work/run_poc.js <poc>` directly
# (shebang line 1). grade.py and patch T1 execute that command verbatim; without
# the exec bit it is Permission denied (exit 126) and every finding fails grading.
COPY run_poc.js /work/run_poc.js
COPY seed.js /work/seed.js
RUN chmod +x /work/run_poc.js

# SPA-shell stub. index.js serves app.get('*') from __dirname/../frontend/dist/
# index.html, which the real repo builds separately and this image does not
# ship. Without a stub a bare GET / throws 'unhandled error' (ENOENT) on a
# healthy app and every UNCAUGHT_EXCEPTION oracle would fire on it. It must land
# one level above app/ to satisfy __dirname/../frontend/dist.
COPY frontend/dist/index.html /work/frontend/dist/index.html

# Pre-create the per-replay scratch parent (the runner also does this, but
# creating it here documents the layout and survives COPY --from).
RUN mkdir -p /work/.replays

CMD ["/bin/bash"]
