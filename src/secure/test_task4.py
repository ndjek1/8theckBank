"""Task 4 verification script — run: python test_task4.py"""
from __future__ import annotations

import json
import sys

from app import create_app


def main() -> int:
    app = create_app()
    client = app.test_client()
    passed = 0
    failed = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS  {name}")
        else:
            failed += 1
            print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))

    print("\n=== Task 4.1 JWT + RBAC ===")

    # Token issue
    r = client.post(
        "/api/auth/token",
        json={"username": "alice", "password": "alice123"},
    )
    check("POST /api/auth/token returns 200", r.status_code == 200, str(r.status_code))
    data = r.get_json()
    check("Response includes access_token", "access_token" in data)
    check("Response includes refresh_token", "refresh_token" in data)
    access = data["access_token"]
    refresh = data["refresh_token"]

    # Bad credentials
    r = client.post("/api/auth/token", json={"username": "alice", "password": "wrong"})
    check("Bad password returns 401", r.status_code == 401)

    # /me with access token
    r = client.get("/api/me", headers={"Authorization": f"Bearer {access}"})
    check("GET /api/me returns 200", r.status_code == 200)
    check("/api/me returns alice", r.get_json().get("username") == "alice")

    # Missing token
    r = client.get("/api/me")
    check("GET /api/me without token returns 401", r.status_code == 401)

    # Wrong token type (refresh used as access)
    r = client.get("/api/me", headers={"Authorization": f"Bearer {refresh}"})
    check("Refresh token rejected on /api/me", r.status_code == 401)

    # Refresh flow
    r = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    check("POST /api/auth/refresh returns 200", r.status_code == 200)
    new_access = r.get_json()["access_token"]
    r = client.get("/api/me", headers={"Authorization": f"Bearer {new_access}"})
    check("Refreshed access token works", r.status_code == 200)

    # Accounts
    r = client.get("/api/accounts", headers={"Authorization": f"Bearer {new_access}"})
    check("GET /api/accounts returns 200", r.status_code == 200)
    accounts = r.get_json()
    check("Alice has at least one account", len(accounts) >= 1)

    # RBAC — alice cannot access admin
    r = client.get("/api/admin/users", headers={"Authorization": f"Bearer {new_access}"})
    check("Non-admin gets 403 on /api/admin/users", r.status_code == 403)

    # Admin token
    r = client.post("/api/auth/token", json={"username": "admin", "password": "admin123"})
    admin_access = r.get_json()["access_token"]
    r = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_access}"})
    check("Admin gets 200 on /api/admin/users", r.status_code == 200)

    print("\n=== Task 4.2 Validation + Rate limiting ===")

    # Pydantic validation → 422
    r = client.post("/api/auth/token", json={"username": "", "password": ""})
    check("Empty credentials return 422", r.status_code == 422)
    check("422 includes error details", "details" in r.get_json())

    r = client.post(
        "/api/transfer",
        headers={"Authorization": f"Bearer {new_access}"},
        json={"from_account_id": -1, "to_account_number": "x", "amount": -5},
    )
    check("Invalid transfer returns 422", r.status_code == 422)

    # Rate limit — 6th attempt should 429
    got_429 = False
    for i in range(6):
        r = client.post(
            "/api/auth/token",
            json={"username": "nobody", "password": "wrong"},
        )
        if r.status_code == 429:
            got_429 = True
            break
    check("6th auth attempt returns 429", got_429, f"last status={r.status_code}")

    print("\n=== Task 4.1 Transfer (ownership) ===")

    # Re-auth after rate limit window may be needed — use fresh client
    app2 = create_app()
    c2 = app2.test_client()
    r = c2.post("/api/auth/token", json={"username": "alice", "password": "alice123"})
    tok = r.get_json()["access_token"]
    accts = c2.get("/api/accounts", headers={"Authorization": f"Bearer {tok}"}).get_json()
    acct_id = accts[0]["id"]

    # Get bob's account number
    r = c2.post("/api/auth/token", json={"username": "bob", "password": "bobpass"})
    bob_accts = c2.get(
        "/api/accounts",
        headers={"Authorization": f"Bearer " + r.get_json()["access_token"]},
    ).get_json()
    bob_num = bob_accts[0]["acct_number"]

    r = c2.post(
        "/api/transfer",
        headers={"Authorization": f"Bearer {tok}"},
        json={
            "from_account_id": acct_id,
            "to_account_number": bob_num,
            "amount": 1.0,
            "note": "task4 test",
        },
    )
    check("Valid transfer returns 200", r.status_code == 200, str(r.get_json()))

    # IDOR — try transfer from someone else's account
    r = c2.post(
        "/api/transfer",
        headers={"Authorization": f"Bearer {tok}"},
        json={
            "from_account_id": bob_accts[0]["id"],
            "to_account_number": bob_num,
            "amount": 1.0,
        },
    )
    check("Transfer from others account returns 403", r.status_code == 403)

    print(f"\n=== Results: {passed} passed, {failed} failed ===\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
