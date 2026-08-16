# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Build the per-target agent image: target binary + claude CLI.

The agent runs *inside* its container, so the container needs the CLI. To
avoid one node+npm install per target, ``ensure()`` builds a shared
``vuln-pipeline-agent-base:<cli-version>`` once (gcc:14 + node + pinned CLI)
and then layers each target's ``/work`` on top via ``COPY --from``. Target
Dockerfiles stay unchanged (single source of truth for the binary build).
"""

from __future__ import annotations

import functools
import re
import subprocess
import tempfile
import textwrap

from . import docker_ops

# Node major baked into the base layer. The web-app target (targets/eathub)
# does `require()` of an ESM module, which is only unflagged on Node >= 22.12 /
# >= 20.19; Debian bookworm's own `nodejs` package is 18.19 and would throw
# ERR_REQUIRE_ESM at app load. Only `/work` survives the per-target
# `COPY --from`, so the runtime the prompts promise has to live in this base
# layer — see ensure_base(). Bump BASE_SUFFIX (not just the Dockerfile) whenever
# this changes: ensure_base() short-circuits on image_exists(BASE_TAG), so a
# machine that already built an older base would otherwise keep serving it.
NODE_MAJOR = "22"
BASE_SUFFIX = "node22"

CLAUDE_CODE_VERSION = "2.1.144"  # bump alongside the dev-env CLI pin
BASE_TAG = f"vuln-pipeline-agent-base:{CLAUDE_CODE_VERSION}-{BASE_SUFFIX}"
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$")


def agent_tag(target_tag: str) -> str:
    """Distinct agent-image tag per *full* target tag, so a committed
    ``<name>:patched-<uuid>`` snapshot doesn't collide with ``<name>:v1``."""
    return f"{target_tag.replace(':', '-')}-agent:{CLAUDE_CODE_VERSION}"


def validate_tag(tag: str) -> None:
    """Raise ValueError if ``tag`` is not a valid docker image reference."""
    if not _TAG_RE.match(tag):
        raise ValueError(f"invalid image tag: {tag!r}")


def build(dockerfile: str, tag: str, context: str | None = None) -> None:
    """Build ``dockerfile`` (a string) as ``tag``. With ``context``, the build
    context is that directory instead of the Dockerfile's temp dir — used by
    harnesses whose Dockerfiles COPY from a host tree."""
    with tempfile.TemporaryDirectory() as ctx:
        with open(f"{ctx}/Dockerfile", "w") as f:
            f.write(dockerfile)
        if context is None:
            cmd = ["docker", "build", "-q", "-t", tag, ctx]
        else:
            cmd = ["docker", "build", "-q", "-f", f"{ctx}/Dockerfile", "-t", tag, context]
        subprocess.run(cmd, check=True, capture_output=True, text=True)


def ensure_base() -> str:
    if docker_ops.image_exists(BASE_TAG):
        return BASE_TAG
    # xxd + gdb: the find/patch prompts list these as available. Target
    # Dockerfiles install them too, but ``ensure()`` only copies /work from the
    # target image — apt packages outside /work don't survive the COPY --from.
    # Anything the prompts promise has to live in this base layer.
    # NodeSource ships a current Node major; Debian's own `nodejs` is 18.19,
    # too old for `require()` of ESM (see NODE_MAJOR above). gcc + git stay in
    # the base because gcc:14 derives from buildpack-deps — a web target's patch
    # grader still needs git, and other targets still need the C toolchain.
    build(
        textwrap.dedent(f"""\
            FROM gcc:14
            RUN apt-get update && \\
                apt-get install -y --no-install-recommends ca-certificates curl xxd gdb && \\
                curl -fsSL https://deb.nodesource.com/setup_{NODE_MAJOR}.x | bash - && \\
                apt-get install -y --no-install-recommends nodejs && \\
                rm -rf /var/lib/apt/lists/* && \\
                npm install -g @anthropic-ai/claude-code@{CLAUDE_CODE_VERSION}
            WORKDIR /work
        """),
        BASE_TAG,
    )
    return BASE_TAG


@functools.lru_cache(maxsize=None)
def ensure(target_tag: str) -> str:
    """Build (if missing) and return the agent-image tag for ``target_tag``."""
    validate_tag(target_tag)
    tag = agent_tag(target_tag)
    if docker_ops.image_exists(tag):
        return tag
    ensure_base()
    build(
        f"FROM {BASE_TAG}\nCOPY --from={target_tag} /work /work\n",
        tag,
    )
    subprocess.run(
        ["docker", "tag", tag, f"{tag.rsplit(':', 1)[0]}:latest"],
        check=True,
    )
    return tag
