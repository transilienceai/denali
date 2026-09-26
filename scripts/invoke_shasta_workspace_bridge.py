"""Invoke the already-deployed, operator-bound Shasta Workspace pilot function.

This does not deploy a temporary Modal app. Run only after the reviewed production
release and matching per-source HMAC configuration are complete.
"""

from __future__ import annotations

import modal


def main() -> None:
    function = modal.Function.from_name(
        "denali-production", "collect_shasta_pilot_workspace", environment_name="denali-prod"
    )
    receipt = function.remote()
    print(
        "source_id={source_id} snapshot_id={snapshot_id} replayed={replayed} "
        "body_sha256={body_sha256}".format(**receipt)
    )


if __name__ == "__main__":
    main()
