from app import render_name

out = render_name("<script>alert(1)</script>")
if "<script>" in out:
    raise SystemExit(1)
if "&lt;script&gt;" not in out:
    raise SystemExit(1)
print("harness: escape holds")
