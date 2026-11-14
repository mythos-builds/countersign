import json, sys
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page()
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto("http://127.0.0.1:8765/index.html")
    pg.wait_for_selector("#out", timeout=15000)
    print(json.dumps(pg.evaluate("window.__RESULT__")), "errors:", errs)
    b.close()
