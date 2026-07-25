"""Mint a local dev token for testing RBAC. Usage:
    python scripts/dev_token.py auditor
    python scripts/dev_token.py business_user
"""
import sys
sys.path.insert(0, "services/gateway")

from app.auth import mint_dev_token  # noqa: E402

role = sys.argv[1] if len(sys.argv) > 1 else "business_user"
print(mint_dev_token(subject=f"dev-{role}", name=f"Dev {role}", roles=[role]))
