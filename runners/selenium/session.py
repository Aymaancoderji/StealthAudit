"""Selenium runner: a long-lived Python process controlled over stdin/stdout
via newline-delimited JSON messages. Spawned and owned by the Go
orchestrator (pkg/orchestrator/selenium.go) — one process per session.

Protocol is identical to the Node runners (runners/playwright,
runners/puppeteer):
  in:  {"id": <int>, "method": "launch"|"navigate"|"evaluate"|"close", "params": {...}}
  out: {"id": <int>, "result": <any>}  or  {"id": <int>, "error": "<message>"}
"""
import json
import sys
from urllib.parse import urlparse

driver = None


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle_launch(params):
    global driver
    browser = params.get("browser") or "chromium"

    if browser in ("chromium", "chrome"):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service

        opts = Options()
        if params.get("headless", True):
            opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        if params.get("proxyURL"):
            opts.add_argument(f"--proxy-server={params['proxyURL']}")
        if params.get("userAgent"):
            opts.add_argument(f"--user-agent={params['userAgent']}")
        for arg in params.get("extraArgs") or []:
            opts.add_argument(arg)
        if params.get("chromeBinary"):
            opts.binary_location = params["chromeBinary"]
        if params.get("ignoreHTTPSErrors"):
            opts.add_argument("--ignore-certificate-errors")
            opts.set_capability("acceptInsecureCerts", True)

        # An explicit, version-matched driver avoids two failure modes seen
        # with the system default: silently picking up a chromedriver that
        # doesn't match the installed Chrome (crashes on connect), and
        # Selenium Manager's own driver auto-download hanging when it can't
        # reach its resolution endpoint.
        service = Service(executable_path=params["chromedriverBinary"]) if params.get("chromedriverBinary") else Service()

        driver = webdriver.Chrome(options=opts, service=service)

        if params.get("stealthPlugin"):
            try:
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {
                        "source": (
                            "Object.defineProperty(Navigator.prototype, 'webdriver', "
                            "{get: () => undefined});"
                        )
                    },
                )
            except Exception:
                pass  # CDP unsupported/blocked; leave webdriver flag as-is

    elif browser == "firefox":
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        from selenium.webdriver.firefox.service import Service

        opts = Options()
        if params.get("firefoxBinary"):
            opts.binary_location = params["firefoxBinary"]
        if params.get("ignoreHTTPSErrors"):
            opts.set_capability("acceptInsecureCerts", True)
        if params.get("headless", True):
            opts.add_argument("-headless")
        if params.get("userAgent"):
            opts.set_preference("general.useragent.override", params["userAgent"])
        if params.get("proxyURL"):
            u = urlparse(params["proxyURL"])
            opts.set_preference("network.proxy.type", 1)
            if u.scheme.startswith("socks"):
                opts.set_preference("network.proxy.socks", u.hostname)
                opts.set_preference("network.proxy.socks_port", u.port)
            else:
                opts.set_preference("network.proxy.http", u.hostname)
                opts.set_preference("network.proxy.http_port", u.port)
                opts.set_preference("network.proxy.ssl", u.hostname)
                opts.set_preference("network.proxy.ssl_port", u.port)
        for arg in params.get("extraArgs") or []:
            opts.add_argument(arg)

        service = Service(executable_path=params["geckodriverBinary"]) if params.get("geckodriverBinary") else Service()
        driver = webdriver.Firefox(options=opts, service=service)
        # Firefox has no CDP equivalent; stealthPlugin is a no-op beyond UA override.

    else:
        raise RuntimeError(f"unsupported browser: {browser}")

    driver.set_script_timeout(30)
    driver.set_page_load_timeout(60)
    return {"ok": True}


def handle_navigate(params):
    if driver is None:
        raise RuntimeError("no active driver; call launch first")
    driver.get(params["url"])
    return {"ok": True}


def handle_evaluate(params):
    if driver is None:
        raise RuntimeError("no active driver; call launch first")
    script = params["script"]
    # script may be a plain expression ("document.title") or an async IIFE
    # (audit.js); Promise.resolve(...) normalizes both into a thenable so a
    # single callback-based async script handles either case.
    wrapper = (
        "var callback = arguments[arguments.length - 1];"
        f"Promise.resolve({script})"
        ".then(function(r) { callback({value: r}); })"
        ".catch(function(e) { callback({error: String((e && e.message) || e)}); });"
    )
    result = driver.execute_async_script(wrapper)
    if isinstance(result, dict) and "error" in result:
        raise RuntimeError(result["error"])
    return result.get("value") if isinstance(result, dict) else None


def handle_close(params):
    global driver
    if driver is not None:
        driver.quit()
        driver = None
    return {"ok": True}


HANDLERS = {
    "launch": handle_launch,
    "navigate": handle_navigate,
    "evaluate": handle_evaluate,
    "close": handle_close,
}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception as e:
            send({"id": None, "error": f"invalid JSON: {e}"})
            continue

        method = msg.get("method")
        handler = HANDLERS.get(method)
        if handler is None:
            send({"id": msg.get("id"), "error": f"unknown method: {method}"})
            continue

        try:
            result = handler(msg.get("params") or {})
            send({"id": msg.get("id"), "result": result})
        except Exception as e:
            send({"id": msg.get("id"), "error": str(e)})

        if method == "close":
            sys.exit(0)


if __name__ == "__main__":
    main()
