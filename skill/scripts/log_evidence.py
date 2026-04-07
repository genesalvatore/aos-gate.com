#!/usr/bin/env python3
"""
AOS Governance — Immutable Evidence Logger
==========================================
Logs verified governance decisions to an append-only evidence ledger.
Each entry is cryptographically chained to the previous one, creating
a tamper-evident record of all agent governance decisions.

Usage:
    python log_evidence.py --action "ACTION_DESCRIPTION" --hash "VERIFIED_HASH"

Output:
    Appends a JSON record to the evidence ledger file.
    Each record includes a chain hash linking it to the previous entry.

This creates a permanent record that cannot be altered by future
model iterations.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_LEDGER_PATH = os.environ.get(
    "AOS_EVIDENCE_LEDGER",
    str(Path(__file__).parent.parent / "evidence" / "ledger.jsonl"),
)

GENESIS_HASH = hashlib.sha256(b"AOS-GOV-STD-1.0:GENESIS").hexdigest()


# ─── Ledger Operations ───────────────────────────────────────────────────────

def get_last_chain_hash(ledger_path: str) -> str:
    """Read the chain hash of the last entry in the ledger."""
    path = Path(ledger_path)
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS_HASH

    # Read last non-empty line
    with open(path, "r", encoding="utf-8") as f:
        last_line = ""
        for line in f:
            stripped = line.strip()
            if stripped:
                last_line = stripped

    if not last_line:
        return GENESIS_HASH

    try:
        entry = json.loads(last_line)
        return entry.get("chain_hash", GENESIS_HASH)
    except json.JSONDecodeError:
        print("WARNING: Corrupted last ledger entry. Using genesis hash.", file=sys.stderr)
        return GENESIS_HASH


def create_evidence_entry(
    action: str,
    verification_hash: str,
    previous_chain_hash: str,
    context: str = "manual",
    agent_id: str | None = None,
) -> dict:
    """Create a new evidence ledger entry with cryptographic chaining."""
    timestamp = datetime.now(timezone.utc).isoformat()

    # The chain hash links this entry to the previous one
    chain_input = f"{previous_chain_hash}:{verification_hash}:{timestamp}:{action}"
    chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()

    return {
        "entry_type": "GOVERNANCE_DECISION",
        "action": action,
        "verification_hash": verification_hash,
        "timestamp": timestamp,
        "context": context,
        "agent_id": agent_id or os.environ.get("AOS_AGENT_ID", "unknown"),
        "previous_hash": previous_chain_hash,
        "chain_hash": chain_hash,
        "standard": "AOS-GOV-STD-1.0",
        "ledger_version": "1.0.0",
    }


def append_to_ledger(entry: dict, ledger_path: str) -> None:
    """Append an evidence entry to the ledger file."""
    path = Path(ledger_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def verify_ledger_integrity(ledger_path: str) -> tuple[bool, int, str]:
    """
    Verify the integrity of the entire evidence chain.

    Returns:
        (is_valid, entry_count, message)
    """
    path = Path(ledger_path)
    if not path.exists():
        return True, 0, "Ledger does not exist yet."

    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entries.append(json.loads(stripped))
            except json.JSONDecodeError:
                return False, line_num, f"Corrupted entry at line {line_num}"

    if not entries:
        return True, 0, "Ledger is empty."

    # Verify chain
    expected_previous = GENESIS_HASH
    for i, entry in enumerate(entries):
        if entry.get("previous_hash") != expected_previous:
            return False, i + 1, (
                f"Chain broken at entry {i + 1}. "
                f"Expected previous_hash={expected_previous[:16]}..., "
                f"got {entry.get('previous_hash', 'MISSING')[:16]}..."
            )
        expected_previous = entry.get("chain_hash", "")

    return True, len(entries), f"Ledger integrity verified. {len(entries)} entries in chain."


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AOS Governance — Immutable Evidence Logger",
        epilog="Part of the AOS Governance Standard (AOS-GOV-STD-1.0)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Log command
    log_parser = subparsers.add_parser("log", help="Log a verified action")
    log_parser.add_argument("--action", required=True, help="Description of the verified action")
    log_parser.add_argument("--hash", required=True, help="Verification hash from verify_action.py")
    log_parser.add_argument("--context", default="manual", help="Context identifier")
    log_parser.add_argument("--agent-id", default=None, help="Agent identifier")
    log_parser.add_argument("--ledger", default=DEFAULT_LEDGER_PATH, help="Path to ledger file")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify ledger integrity")
    verify_parser.add_argument("--ledger", default=DEFAULT_LEDGER_PATH, help="Path to ledger file")

    # Check if first positional arg is a subcommand
    if len(sys.argv) > 1 and sys.argv[1] in ("log", "verify"):
        args = parser.parse_args()
    else:
        # Backward compatibility: direct --action --hash usage (as in SKILL.md)
        compat_parser = argparse.ArgumentParser(
            description="AOS Governance — Immutable Evidence Logger",
        )
        compat_parser.add_argument("--action", required=True)
        compat_parser.add_argument("--hash", required=True)
        compat_parser.add_argument("--context", default="manual")
        compat_parser.add_argument("--agent-id", default=None)
        compat_parser.add_argument("--ledger", default=DEFAULT_LEDGER_PATH)
        args = compat_parser.parse_args()
        args.command = "log"

    if args.command == "log":
        # Get the previous chain hash
        previous_hash = get_last_chain_hash(args.ledger)

        # Create and append entry
        entry = create_evidence_entry(
            action=args.action,
            verification_hash=args.hash,
            previous_chain_hash=previous_hash,
            context=args.context,
            agent_id=args.agent_id,
        )
        append_to_ledger(entry, args.ledger)

        print(f"LOGGED: {entry['chain_hash']}")
        print(f"  Action:    {entry['action']}")
        print(f"  Timestamp: {entry['timestamp']}")
        print(f"  Chain:     ...{entry['previous_hash'][-12:]} → {entry['chain_hash'][:12]}...")

    elif args.command == "verify":
        is_valid, count, message = verify_ledger_integrity(args.ledger)
        if is_valid:
            print(f"✓ {message}")
        else:
            print(f"✗ INTEGRITY VIOLATION: {message}", file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
