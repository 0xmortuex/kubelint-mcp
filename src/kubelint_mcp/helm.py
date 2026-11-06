"""render_helm: the one place a subprocess is started. Opt-in, argument list only, with a timeout.

`helm template` renders locally. Nothing here passes --validate or --dry-run, so helm never contacts a cluster.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

from .errors import UserError, shorten
from .files import Sandbox

TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 10_000_000
_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")


def helm_binary() -> str | None:
    return shutil.which("helm")


def render(sb: Sandbox, chart_dir: str, values_files: list[str], release: str, namespace: str, allow_exec: bool) -> tuple[str, str]:
    """Returns (rendered YAML, label). Raises UserError for every refusal and failure."""
    if not allow_exec:
        raise UserError(
            "render_helm runs the local `helm template` binary. It is off unless you pass allow_exec=true, "
            "and you should only do that when the user asked you to render a chart. "
            "Otherwise run `helm template` yourself and point lint_manifests at the output file."
        )
    if not _DNS_LABEL.match(release):
        raise UserError(f"release_name {shorten(release)!r} must be a lowercase DNS label (letters, digits, '-').")
    if namespace and not _DNS_LABEL.match(namespace):
        raise UserError(f"namespace {shorten(namespace)!r} must be a lowercase DNS label (letters, digits, '-').")
    chart = sb.resolve(chart_dir)
    if not os.path.isdir(chart) or not os.path.isfile(os.path.join(chart, "Chart.yaml")):
        raise UserError(f"{shorten(chart_dir)!r} is not a Helm chart directory (no Chart.yaml found).")
    args = ["template", release, chart]
    if namespace:
        args += ["--namespace", namespace]
    for v in values_files:
        real = sb.resolve(v)
        if not os.path.isfile(real):
            raise UserError(f"values file {shorten(v)!r} not found.")
        args += ["--values", real]
    helm = helm_binary()
    if helm is None:
        raise UserError("The `helm` binary was not found on PATH. Install Helm, or render the chart yourself "
                        "(`helm template <release> <chart> > out.yaml`) and lint out.yaml.")
    cmd = [helm, *args]
    env = {k: val for k, val in os.environ.items() if k not in ("KUBECONFIG", "HELM_KUBECONTEXT", "HELM_KUBEAPISERVER", "HELM_KUBETOKEN")}
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT_SECONDS, env=env, stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired as e:
        raise UserError(f"`helm template` did not finish within {TIMEOUT_SECONDS} seconds.") from e
    except OSError as e:
        raise UserError(f"could not start helm: {e.strerror or type(e).__name__}") from e
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise UserError(f"`helm template` failed (exit code {proc.returncode}): {shorten(err, 600)}")
    if len(proc.stdout) > MAX_OUTPUT_BYTES:
        raise UserError(f"`helm template` produced more than {MAX_OUTPUT_BYTES} bytes; render a smaller chart or subchart.")
    return proc.stdout.decode("utf-8", errors="replace"), f"helm template {release} ({sb.display(chart)})"
