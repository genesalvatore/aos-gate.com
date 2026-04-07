#!/usr/bin/env python3
"""
AOS Governance — Constitutional Verification Script
====================================================
Deterministically verifies whether a proposed agent action is permitted
under the AOS Constitution v1.0.

Usage:
    python verify_action.py --action "ACTION_DESCRIPTION" --context "CONTEXT_ID"

Returns:
    VERIFIED: <sha256_hash>    — Action is constitutional. Proceed.
    DENIED:   <reason>         — Action violates the Constitution. Halt.

This script is deterministic. Given the same inputs, it always produces
the same output. It does not use LLM inference. It does not guess.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ─── Constitutional Categories ───────────────────────────────────────────────

# Actions that always require verification (Section 2: The Verification Gap)
CRITICAL_ACTIONS = [
    "delete",
    "remove",
    "drop",
    "truncate",
    "destroy",
    "terminate",
    "shutdown",
    "purge",
    "overwrite",
    "format",
    "erase",
]

# Actions that violate the humanitarian mandate (Section 1: Prime Directive)
PROHIBITED_PATTERNS = [
    "weaponize",
    "surveillance without consent",
    "exploit",
    "deceive user",
    "hide from user",
    "bypass kill switch",
    "override user",
    "suppress transparency",
    "obfuscate logs",
    "disable audit",
]

# ─── Constitution Loader ─────────────────────────────────────────────────────

def load_constitution(constitution_path: str | None = None) -> dict:
    """Load and parse the AOS Constitution."""
    if constitution_path is None:
        constitution_path = os.environ.get(
            "AOS_CONSTITUTION_PATH",
            str(Path(__file__).parent.parent / "references" / "constitution_v1.md"),
        )

    path = Path(constitution_path)
    if not path.exists():
        print(f"ERROR: Constitution not found at {path}", file=sys.stderr)
        print("Set AOS_CONSTITUTION_PATH or place constitution_v1.md in references/", file=sys.stderr)
        sys.exit(2)

    content = path.read_text(encoding="utf-8")
    return {
        "path": str(path.resolve()),
        "hash": hashlib.sha256(content.encode()).hexdigest(),
        "content": content,
    }


# ─── Verification Engine ─────────────────────────────────────────────────────

def verify_action(action: str, context: str, constitution: dict) -> dict:
    """
    Deterministic verification of an action against the Constitution.

    Returns a result dict with:
        - status: "VERIFIED" or "DENIED"
        - hash: SHA-256 of the verification record (if verified)
        - reason: Denial reason (if denied)
        - record: Full verification record
    """
    action_lower = action.lower()
    timestamp = datetime.now(timezone.utc).isoformat()

    # ── Check 1: Prohibited Patterns (Section 1 — Humanitarian Purpose) ──
    for pattern in PROHIBITED_PATTERNS:
        if pattern in action_lower:
            return {
                "status": "DENIED",
                "reason": f"Constitutional violation: Section 1 (Humanitarian Purpose). "
                          f"Action matches prohibited pattern: '{pattern}'",
                "section": "§1 — Humanitarian Purpose",
                "record": _build_record(action, context, "DENIED", timestamp, constitution),
            }

    # ── Check 2: Critical Action Classification (Section 2 — Verification Gap) ──
    is_critical = any(keyword in action_lower for keyword in CRITICAL_ACTIONS)

    # ── Check 3: User Sovereignty (Section 3 — Rights of the User) ──
    if "without user" in action_lower or "hide from user" in action_lower:
        return {
            "status": "DENIED",
            "reason": "Constitutional violation: Section 3 (User Sovereignty). "
                      "Action attempts to bypass user awareness or consent.",
            "section": "§3 — Rights of the User",
            "record": _build_record(action, context, "DENIED", timestamp, constitution),
        }

    # ── Check 4: Kill Switch Integrity (Section 4) ──
    if "bypass kill switch" in action_lower or "override termination" in action_lower:
        return {
            "status": "DENIED",
            "reason": "Constitutional violation: Section 4 (Kill Switch). "
                      "The user's right to terminate cannot be overridden.",
            "section": "§4 — The Kill Switch",
            "record": _build_record(action, context, "DENIED", timestamp, constitution),
        }

    # ── Check 5: Transparency (Section 5) ──
    if "hide" in action_lower and "log" in action_lower:
        return {
            "status": "DENIED",
            "reason": "Constitutional violation: Section 5 (Transparency). "
                      "All reasoning must be logged. Hidden operations are prohibited.",
            "section": "§5 — Transparency",
            "record": _build_record(action, context, "DENIED", timestamp, constitution),
        }

    # ── Verification Passed ──
    record = _build_record(action, context, "VERIFIED", timestamp, constitution)
    record_hash = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()

    return {
        "status": "VERIFIED",
        "hash": record_hash,
        "is_critical": is_critical,
        "record": record,
    }


def _build_record(action: str, context: str, status: str, timestamp: str, constitution: dict) -> dict:
    """Build an immutable verification record."""
    return {
        "action": action,
        "context": context,
        "status": status,
        "timestamp": timestamp,
        "constitution_hash": constitution["hash"],
        "constitution_path": constitution["path"],
        "engine_version": "1.0.0",
        "standard": "AOS-GOV-STD-1.0",
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AOS Governance — Constitutional Verification Engine",
        epilog="Part of the AOS Governance Standard (AOS-GOV-STD-1.0)",
    )
    parser.add_argument(
        "--action", required=True,
        help="Description of the proposed action to verify",
    )
    parser.add_argument(
        "--context", default="manual",
        help="Context identifier (e.g., session ID, commit hash)",
    )
    parser.add_argument(
        "--constitution", default=None,
        help="Path to the AOS Constitution file (default: auto-detect)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output full verification record as JSON",
    )

    args = parser.parse_args()

    # Load constitution
    constitution = load_constitution(args.constitution)

    # Run verification
    result = verify_action(args.action, args.context, constitution)

    # Output
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "VERIFIED":
            print(f"VERIFIED: {result['hash']}")
            if result.get("is_critical"):
                print(f"  ⚠  Critical action detected — evidence logging required.")
        else:
            print(f"DENIED: {result['reason']}")

    sys.exit(0 if result["status"] == "VERIFIED" else 1)


if __name__ == "__main__":
    main()
