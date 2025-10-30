from app import app
for r in app.url_map.iter_rules():
    print(str(r), r.methods)
