from app import lookup_user

query = lookup_user("1' OR '1'='1")
if "OR '1'='1" not in query:
    raise SystemExit(1)
print("harness: interpolation reachable")
