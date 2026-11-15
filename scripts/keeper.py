#!/usr/bin/env python3
"""Zephyrus keeper — quota guard + self-heal for the relay codespace.

Reads the relay heartbeat (relay_url.json on this repo):
  - desired_on_until in the future          -> ensure the codespace is Running
                                               (create it if missing)
  - horizon expired + relay idle/unreachable -> stop the codespace (saves
                                               core-hour quota)

While the relay runs, it renews the horizon every <=3 minutes, so a live
session is never interrupted. A 15-min boot grace covers the engine's cold
start after a wake.
"""
import os, time
import requests

GH = os.environ["GH_PAT"]
REPO = "zahidSkywalker/zephyrus-digi-art"
LINK_RAW = "https://raw.githubusercontent.com/zahidSkywalker/zephyrus-link/main/relay_url.json"
H = {"Authorization": f"Bearer {GH}", "Accept": "application/vnd.github+json"}
MACHINE = "basicLinux32gb"


def api(method, path, **kw):
    return requests.request(method, f"https://api.github.com{path}", headers=H, timeout=30, **kw)


def main():
    now_ms = int(time.time() * 1000)
    desired, url = False, ""
    try:
        j = requests.get(f"{LINK_RAW}?t={now_ms}", timeout=15).json()
        url = (j.get("url") or "").strip()
        desired = int(j.get("desired_on_until") or 0) > now_ms
    except Exception as e:
        print(f"link read failed: {type(e).__name__}: {e}")

    status_ok, status_active = False, False
    if url:
        try:
            s = requests.get(url + "/api/status", timeout=10).json()
            status_ok = True
            status_active = bool(
                s.get("engine_online") or s.get("queue_len") or s.get("inflight")
                or (s.get("ui_clients") or 0) > 0
            )
        except Exception:
            status_ok = False

    active = desired or (status_ok and status_active)

    lst = api("GET", f"/repos/{REPO}/codespaces?per_page=10").json()
    cs = None
    for c in lst.get("codespaces", []):
        cs = c
        break
    name = cs["name"] if cs else None
    state = cs["state"] if cs else "none"
    print(f"desired={desired} relay_ok={status_ok} relay_active={status_active} active={active} codespace={name} state={state}")

    if cs is None:
        if active:
            print("cold but desired — creating codespace")
            r = api("POST", f"/repos/{REPO}/codespaces", json={"machine": MACHINE})
            if r.status_code in (400, 422):
                r = api("POST", f"/repos/{REPO}/codespaces", json={})
            print("create:", r.status_code)
        else:
            print("cold, undesired — nothing to do")
        return

    if state != "Running" and active:
        r = api("POST", f"/repos/{REPO}/codespaces/{name}/start")
        print("start:", r.status_code)
        return

    if state == "Running":
        # best-effort: bump the idle timeout each pass
        api("PATCH", f"/user/codespaces/{name}", json={"idle_timeout_minutes": 240})
        if not active:
            r = api("POST", f"/repos/{REPO}/codespaces/{name}/stop")
            print("stop (idle — quota guard):", r.status_code)
        else:
            print("active — leaving running")


if __name__ == "__main__":
    main()
