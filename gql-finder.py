#!/usr/bin/env python3
"""
gql-finder — Hidden GraphQL endpoint finder

Highlights:
- Dual baselines: HOME + learned 404 template (normalized with 1 redirect hop)
- Probes each candidate with GET + POST (safe GraphQL body) + optional POST2 fallback shape
- Redirect-following probes with browser-like behavior:
    * POST -> GET on 301/302/303 (like browsers) when --redirect-mode browser
    * Preserve method/body on 307/308
filter signals
- By default (no --filter): uses ALL signals (status, ctype, graphql, len, similarity)
- With --filter: only the selected signals can trigger "interesting"

Signals:
  status      -> non-404 / non-error status changes
  ctype       -> JSON / GraphQL JSON content-type
  graphql     -> GraphQL-ish body hints ("errors", "data", "Cannot query field", etc.)
  len         -> length delta vs closest baseline (home OR 404 template)
  similarity  -> similarity score vs closest baseline below cutoff

Usage:
  python find_graphql_endpoint.py https://target.com
  python find_graphql_endpoint.py https://target.com --verbose
  python find_graphql_endpoint.py https://target.com --filter status,graphql
  python find_graphql_endpoint.py https://target.com --filter status --filter len
  
Note:By default i have commented out the flagging of lenght as "interesting", if you require it uncomment lines 569-585 and adjust as needed
"""

import argparse
import json
import sys
import time
import difflib
import random
import string
from urllib.parse import urljoin, urlparse

import requests


DEFAULT_SUFFIXES = [
    # === Most Common ===
    "/graphql",
    "/api/graphql",
    "/graphql/api",
    "/gql",
    "/api/gql",
    "/query",
    "/api/query",
    "/graphiql",
    "/playground",
    "/graphql/playground",
    "/graphql/console",
    "/graphql-ui",
    "/graphql-ui/playground",
    "/api",

    # === Versioned ===
    "/v1/graphql",
    "/v2/graphql",
    "/v3/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/api/v3/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/graphql/v3",

    # === Admin / Internal ===
    "/admin/graphql",
    "/internal/graphql",
    "/private/graphql",
    "/staff/graphql",
    "/console/graphql",
    "/dashboard/graphql",
    "/management/graphql",
    "/backend/graphql",
    "/panel/graphql",

    # === Common App Prefixes ===
    "/app/graphql",
    "/apps/graphql",
    "/mobile/graphql",
    "/web/graphql",
    "/client/graphql",
    "/frontend/graphql",
    "/storefront/graphql",
    "/shop/graphql",
    "/checkout/graphql",
    "/customer/graphql",
    "/users/graphql",
    "/user/graphql",

    # === Framework Defaults ===
    "/hasura/graphql",
    "/apollo/graphql",
    "/strapi/graphql",
    "/graphql-engine",
    "/graphql-engine/v1/graphql",
    "/api/graphql-engine",
    "/graphql-server",
    "/graphql-server/graphql",

    # === Cloud / Serverless ===
    "/.netlify/functions/graphql",
    "/.vercel/functions/graphql",
    "/functions/graphql",
    "/lambda/graphql",
    "/prod/graphql",
    "/dev/graphql",
    "/staging/graphql",
    "/test/graphql",

    # === Commerce / Shopify / Magento Patterns ===
    "/admin/api/graphql.json",
    "/api/graphql.json",
    "/graphql.json",
    "/storefront/api/graphql",
    "/storefront/graphql",
    "/magento/graphql",
    "/rest/graphql",

    # === Console / Dev Tools Exposed ===
    "/graphql-devtools",
    "/graphql/explorer",
    "/explorer",
    "/voyager",
    "/graphql/voyager",
    "/altair",
    "/graphql/altair",
    "/insomnia",
    "/graphql/insomnia",

    # === Misc Disclosed in Bug Bounties ===
    "/api/v1/gql",
    "/api/v2/gql",
    "/gateway/graphql",
    "/edge/graphql",
    "/public/graphql",
    "/partner/graphql",
    "/beta/graphql",
    "/alpha/graphql",
    "/preview/graphql",
    "/live/graphql",
    "/services/graphql",
    "/service/graphql",
    "/platform/graphql",
    "/core/graphql",
    "/graph/graphql",
    "/graph",
    "/graphql-api",
    "/graphql_service",
    "/api/graph",
    "/graphapi",
    "/api/graphapi",

    # === Mobile / iOS / Android ===
    "/ios/graphql",
    "/android/graphql",
    "/mobile-api/graphql",
    "/m/graphql",

    # === Nested API Patterns ===
    "/api/internal/graphql",
    "/api/private/graphql",
    "/api/admin/graphql",
    "/api/backend/graphql",
    "/api/public/graphql",

    # === Subdirectory Variants ===
    "/api/app/graphql",
    "/api/web/graphql",
    "/api/store/graphql",
    "/api/mobile/graphql",

    # === Oddball / Real-World Variants ===
    "/graphql2",
    "/graphqlv2",
    "/graphql-prod",
    "/graphql-test",
    "/graphql-beta",
    "/graphql-alpha",
    "/graphql-old",
    "/graphql-new",
    "/graphql_internal",
    "/graphql-public",
    "/graphql-private",
    "/api/graphql-private",
    "/api/graphql-public",
]


VALID_SIGNALS = {"all", "status", "ctype", "graphql", "len", "similarity"}
VALID_REDIRECT_MODES = {"preserve", "browser"}

def normalize_base_url(base: str) -> str:
    base = base.strip()
    parsed = urlparse(base)
    if not parsed.scheme:
        base = "https://" + base
    return base


def build_candidate_url(base: str, suffix: str) -> str:
    # If suffix starts with /, urljoin treats it as root path on the domain,
    # which is usually correct for GraphQL endpoints.
    return urljoin(base if base.endswith("/") else base + "/", suffix.lstrip("/"))


def response_fingerprint(resp: requests.Response) -> dict:
    content_type = resp.headers.get("Content-Type", "")
    text_sample = resp.text[:5000] if resp.text else ""
    return {
        "status": resp.status_code,
        "len": len(resp.content) if resp.content else 0,
        "ctype": content_type.split(";")[0].strip().lower(),
        "sample": text_sample,
    }


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def safe_request(session: requests.Session, method: str, url: str, **kwargs):
    try:
        return session.request(method=method, url=url, allow_redirects=False, **kwargs)
    except requests.RequestException as e:
        return e


def rand_path(prefix="__nope__") -> str:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return f"/{prefix}_{token}"


def is_redirect(status: int) -> bool:
    return status in (301, 302, 303, 307, 308)


def resolve_redirect_target(base_url: str, resp: requests.Response) -> str:
    loc = resp.headers.get("Location", "")
    if not loc:
        return ""
    return urljoin(base_url, loc)


def fetch_normalized_get(session: requests.Session, url: str, timeout: float, verify: bool) -> dict | None:
    """
    GET url, and if it redirects, follow ONE hop to normalize the "real" response.
    Returns fingerprint or None.
    """
    r1 = safe_request(session, "GET", url, timeout=timeout, verify=verify)
    if not isinstance(r1, requests.Response):
        return None

    if is_redirect(r1.status_code):
        target = resolve_redirect_target(url, r1)
        if target:
            r2 = safe_request(session, "GET", target, timeout=timeout, verify=verify)
            if isinstance(r2, requests.Response):
                return response_fingerprint(r2)
        return response_fingerprint(r1)

    return response_fingerprint(r1)


def best_baseline_match(candidate_fp: dict, baselines: list[dict]) -> dict:
    """
    Choose the baseline (HOME or 404-template) that most closely matches candidate.
    """
    best = baselines[0]
    best_score = similarity(best["sample"], candidate_fp["sample"])
    for b in baselines[1:]:
        score = similarity(b["sample"], candidate_fp["sample"])
        if score > best_score:
            best_score = score
            best = b
    return {"baseline": best, "sim": best_score}


def parse_filters(filter_args: list[str] | None) -> set[str]:

    if not filter_args:
        return {"all"}

    selected: set[str] = set()
    for item in filter_args:
        # allow comma-separated
        parts = [p.strip().lower() for p in item.split(",") if p.strip()]
        selected.update(parts)

    unknown = selected - VALID_SIGNALS
    if unknown:
        raise ValueError(f"Unknown filter(s): {', '.join(sorted(unknown))}. Valid: {', '.join(sorted(VALID_SIGNALS))}")

    if "all" in selected:
        return {"all"}

    if not selected:
        return {"all"}

    return selected


def enabled(selected_filters: set[str], signal: str) -> bool:
    return "all" in selected_filters or signal in selected_filters


def request_with_redirects(
    session: requests.Session,
    method: str,
    url: str,
    max_redirects: int,
    redirect_mode: str = "browser",
    **kwargs,
):
    """
    Sends a request and manually follows up to max_redirects redirects.

    redirect_mode:
      - preserve: keep original method/body across redirects
      - browser:  POST -> GET on 301/302/303 (like browsers), preserve on 307/308
    """
    current_url = url
    last_resp = None

    # make a copy to avoid mutating caller dict
    base_kwargs = dict(kwargs)
    base_kwargs.pop("max_redirects", None)
    base_kwargs.pop("redirect_mode", None)

    current_method = method.upper()
    current_kwargs = dict(base_kwargs)

    for _ in range(max_redirects + 1):
        resp = safe_request(session, current_method, current_url, **current_kwargs)
        last_resp = resp

        if not isinstance(resp, requests.Response):
            return resp

        if not is_redirect(resp.status_code):
            return resp

        nxt = resolve_redirect_target(current_url, resp)
        if not nxt:
            return resp

        code = resp.status_code

        # Browser-like behavior: POST -> GET on 301/302/303
        if redirect_mode == "browser":
            if current_method == "POST" and code in (301, 302, 303):
                current_method = "GET"

                # Drop body-related args when switching to GET
                for k in ("data", "json", "files"):
                    current_kwargs.pop(k, None)

                # Also drop Content-Type to avoid confusing servers/CDNs
                if "headers" in current_kwargs and isinstance(current_kwargs["headers"], dict):
                    # keep Accept/User-Agent etc., remove Content-Type
                    current_kwargs["headers"] = dict(current_kwargs["headers"])
                    current_kwargs["headers"].pop("Content-Type", None)

        # For 307/308, preserve method/body automatically (no change needed)

        current_url = nxt

    return last_resp

def make_colors(no_color: bool):
    use = (not no_color) and sys.stdout.isatty()

    class C:
        if use:
            RED = "\033[31m"
            BLUE = "\033[34m"
            CYAN = "\033[36m"
            GREEN = "\033[32m"
            YELLOW = "\033[33m"
            BOLD = "\033[1m"
            DIM = "\033[2m"
            RESET = "\033[0m"
        else:
            RED = BLUE = CYAN = GREEN = YELLOW = BOLD = DIM = RESET = ""

    return C


def banner(C):
    art = rf"""{C.CYAN}{C.BOLD}
   ______      __     ____ _           __           
  / ____/___ _/ /    / __/(_)___  ____/ /___  _____ 
 / / __/ __ `/ /    / /_ / / __ \/ __  / __ \/ ___/ 
/ /_/ / /_/ / /    / __// / / / / /_/ /  __/ /     
\____/\__, /_/____/_/  /_/_/ /_/\__,_/\___/_/      
        /_/ /_____/
{C.RESET}"""
    info = f"""{C.RED}{C.BOLD}[*] made by KIZA https://x.com/abdool_hameed_ {C.RESET}
{C.DIM}[!] Authorized testing only. Use responsibly.{C.RESET}
{C.DIM}[*] use -h for help{C.RESET}
"""
    print(art)
    print(info)



def main():
    parser = argparse.ArgumentParser(description="Find likely GraphQL endpoint candidates by probing common paths.")
    parser.add_argument("url", help="Base URL, e.g. https://target.com or https://target.com/shop")
    parser.add_argument("--suffixes", help="Path to a JSON file containing an array of suffixes to try.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout (seconds). Default: 10")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds). Default: 0")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (labs sometimes).")
    parser.add_argument("--verbose", action="store_true", help="Print more detail.")
    parser.add_argument("--redirect-mode", choices=["preserve", "browser"], default="browser", help="Redirect behavior. 'browser' converts POST to GET on 301/302/303. 'preserve' keeps method/body. Default: browser")
    parser.add_argument("--max-redirects", type=int, default=1, help="Max redirect hops to follow for probe requests (GET/POST). Default: 1. Use 0 to disable.")
    # Multi-filter: can be repeated and/or comma-separated.
    parser.add_argument("--filter", action="append", help="Limit which signals can flag 'interesting'. Repeatable and/or comma-separated." "Signals: all,status,ctype,graphql,len,similarity. Example: --filter status,graphql --filter len")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    
    
    args = parser.parse_args()
    C = make_colors(args.no_color)
    
    
    try:
        selected_filters = parse_filters(args.filter)
    except ValueError as e:
        print(f"{C.RED}[!]{C.RESET} {e}")
        sys.exit(2)

    base = normalize_base_url(args.url)

    suffixes = DEFAULT_SUFFIXES
    if args.suffixes:
        try:
            with open(args.suffixes, "r", encoding="utf-8") as f:
                lines = f.readlines()

            parsed = []
            for line in lines:
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Ensure suffix starts with /
                if not line.startswith("/"):
                    line = "/" + line

                parsed.append(line)

            if not parsed:
                print("[!] Suffix file is empty after filtering comments/blank lines.")
                sys.exit(1)

            suffixes = parsed

        except Exception as e:
            print(f"[!] Failed to read suffix file: {e}")
            sys.exit(1)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "ps-graphql-finder/3.0",
        "Accept": "*/*",
    })

    verify_tls = not args.insecure

    # --- baselines ---
    baseline_home_fp = fetch_normalized_get(session, base, timeout=args.timeout, verify=verify_tls)

    random_url = urljoin(base if base.endswith("/") else base + "/", rand_path())
    baseline_404_fp = fetch_normalized_get(session, random_url, timeout=args.timeout, verify=verify_tls)

    baselines = [b for b in (baseline_home_fp, baseline_404_fp) if b is not None]
    if not baselines:
        print("[!] Could not establish any baseline (network/TLS issue?).")
        sys.exit(1)

    if args.verbose:
        print(f"[*] Enabled signals: {', '.join(sorted(selected_filters))}")
        if baseline_home_fp:
            print(f"[baseline HOME] {base} -> {baseline_home_fp['status']} len={baseline_home_fp['len']} ctype={baseline_home_fp['ctype']}")
        if baseline_404_fp:
            print(f"[baseline 404 ] {random_url} -> {baseline_404_fp['status']} len={baseline_404_fp['len']} ctype={baseline_404_fp['ctype']}")

    # GraphQL probe bodies
    gql_body = {"query": "query { __typename }"}
    gql_body_alt = {"operationName": None, "variables": {}, "query": "query { __typename }"}

    banner(C)
    print(f"{C.GREEN}[*]{C.RESET} Probing {len(suffixes)} suffixes against base: {C.BOLD}{base}{C.RESET}")
    print(f"{C.DIM}[*] signals enabled: {', '.join(sorted(selected_filters))}{C.RESET}")
    print(f"{C.DIM}[*] redirects: max={args.max_redirects}, mode={args.redirect_mode}{C.RESET}\n")
    hits = []

    for suffix in suffixes:
        candidate = build_candidate_url(base, suffix)

        # ---- GET probe ----
        get_resp = request_with_redirects(#safe_request(
            session, "GET", candidate,
            max_redirects=args.max_redirects,
            redirect_mode=args.redirect_mode,
            timeout=args.timeout,
            verify=verify_tls,
            headers={"Accept": "application/json, text/html;q=0.9, */*;q=0.8"},
        )

        # ---- POST probe (JSON) ----
        post_resp = request_with_redirects(#safe_request(
            session, "POST", candidate,
            max_redirects=args.max_redirects,
            redirect_mode=args.redirect_mode,
            timeout=args.timeout,
            verify=verify_tls,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json=gql_body,
        )

        # ---- POST fallback (alt shape) on common "shape/ctype" failures ----
        post_resp2 = None
        if isinstance(post_resp, requests.Response) and post_resp.status_code in (400, 415, 422):
            post_resp2 = request_with_redirects(#safe_request(
                session, "POST", candidate,
                max_redirects=args.max_redirects,
                redirect_mode=args.redirect_mode,
                timeout=args.timeout,
                verify=verify_tls,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json=gql_body_alt,
            )

        if args.delay > 0:
            time.sleep(args.delay)

        def summarize(resp):
            if isinstance(resp, requests.Response):
                return response_fingerprint(resp)
            return {"status": "ERR", "len": 0, "ctype": "", "sample": str(resp)}

        get_fp = summarize(get_resp)
        post_fp = summarize(post_resp)
        post_fp_alt = summarize(post_resp2) if post_resp2 is not None else None

        # choose closest baseline for each response type
        match_get = best_baseline_match(get_fp, baselines) if baselines else None
        match_post = best_baseline_match(post_fp, baselines) if baselines else None
        match_post2 = best_baseline_match(post_fp_alt, baselines) if (baselines and post_fp_alt) else None

        sim_get = match_get["sim"] if match_get else None
        sim_post = match_post["sim"] if match_post else None
        sim_post2 = match_post2["sim"] if match_post2 else None

        ref_get = match_get["baseline"] if match_get else None
        ref_post = match_post["baseline"] if match_post else None
        ref_post2 = match_post2["baseline"] if match_post2 else None

        interesting = False
        reasons = []

        def check(fp, method: str):
            nonlocal interesting

            # Status signals
            if enabled(selected_filters, "status"):
                if fp["status"] != "ERR" and fp["status"] != 404:
                    interesting = True
                    reasons.append(f"{method}:status={fp['status']}")

            # Content-type signals
            if enabled(selected_filters, "ctype"):
                if fp["ctype"] in ("application/json", "application/graphql-response+json"):
                    interesting = True
                    reasons.append(f"{method}:json-ctype")

            # GraphQL-ish body hints
            if enabled(selected_filters, "graphql"):
                s = (fp.get("sample") or "").lower()
                if any(k in s for k in ('"data"', '"errors"', "graphql", "cannot query field", "syntax error")):
                    interesting = True
                    reasons.append(f"{method}:graphql-hint")
            """
            # Length difference vs closest baseline
            if enabled(selected_filters, "len"):
                ref = None
                if method == "GET":
                    ref = ref_get
                elif method == "POST":
                    ref = ref_post
                elif method == "POST2":
                    ref = ref_post2

                if ref and fp["status"] != "ERR":
                    threshold = max(200, int(0.30 * max(ref["len"], 1)))
                    if abs(fp["len"] - ref["len"]) >= threshold:
                        interesting = True
                        reasons.append(f"{method}:len-diff")
            """           
            # Similarity signal (difference vs closest baseline)
            if enabled(selected_filters, "similarity"):
                sim = None
                if method == "GET":
                    sim = sim_get
                elif method == "POST":
                    sim = sim_post
                elif method == "POST2":
                    sim = sim_post2

                # Tuneable cutoff
                if sim is not None and sim < 0.85:
                    interesting = True
                    reasons.append(f"{method}:sim<{sim:.2f}")

        check(get_fp, "GET")
        check(post_fp, "POST")
        if post_fp_alt:
            check(post_fp_alt, "POST2")

        if interesting:
            hits.append({
                "url": candidate,
                "suffix": suffix,
                "GET": get_fp,
                "POST": post_fp,
                "POST2": post_fp_alt,
                "sim_get": sim_get,
                "sim_post": sim_post,
                "sim_post2": sim_post2,
                "reasons": reasons,
            })

            print(f"\n{C.RED}{C.BOLD}[+] Interesting:{C.RESET} {candidate}")
            print(f"    {C.BLUE}reasons:{C.RESET} {', '.join(reasons)}")
            print(
                f"    GET : status={get_fp['status']} len={get_fp['len']} ctype={get_fp['ctype']}"
                + (f" sim={sim_get:.3f}" if sim_get is not None else "")
            )
            print(
                f"    POST: status={post_fp['status']} len={post_fp['len']} ctype={post_fp['ctype']}"
                + (f" sim={sim_post:.3f}" if sim_post is not None else "")
            )
            if post_fp_alt:
                print(
                    f"    POST2: status={post_fp_alt['status']} len={post_fp_alt['len']} ctype={post_fp_alt['ctype']}"
                    + (f" sim={sim_post2:.3f}" if sim_post2 is not None else "")
                )

            if args.verbose:
                snippet_src = post_fp_alt["sample"] if post_fp_alt else post_fp["sample"]
                snippet = (snippet_src or "")[:300].replace("\n", "\\n")
                print(f"    sample: {snippet}...")

        elif args.verbose:
            print(f"[-] {candidate} | GET {get_fp['status']} | POST {post_fp['status']}")

    print(f"\n{C.GREEN}[*]{C.RESET} Done.")
    if not hits:
        print(f"{C.YELLOW}[!]{C.RESET} No strong candidates found with current suffix list.")
        print("    Tip: feed additional app-specific paths via --suffixes custom.json")
    else:
        print(f"{C.GREEN}[+]{C.RESET} Found {len(hits)} interesting candidates (review the top few first).")


if __name__ == "__main__":
    main()
