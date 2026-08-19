#!/usr/bin/env python3
"""
Web VAPT Suite
Comprehensive, non-destructive web security posture scanner for authorized targets.

Covers safe detection/triage for:
- URL/IP/DNS information
- HTTP status/redirects
- Security headers
- Cookies
- CORS
- HTTP methods
- TLS metadata
- robots.txt / sitemap / security.txt
- common exposed files
- directory listing indicators
- forms/password forms
- mixed content
- HTML comments and source disclosure indicators
- common framework/server disclosure
- basic subdomain discovery from certificate + common DNS names
- JWT inspection (tokens found in HTML/headers)
- basic URL encoding/decoding helpers
- response/header anomalies

It intentionally does NOT exploit SQLi/XSS/SSRF/RCE, brute-force credentials,
upload files, or modify application state.
"""

import argparse, base64, json, re, socket, ssl, sys
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qsl, unquote, quote

import requests
from bs4 import BeautifulSoup

UA="WebVAPT-Suite/2.0 (authorized security assessment)"
TIMEOUT=8
COMMON_PATHS=[
    "robots.txt","sitemap.xml",".well-known/security.txt","security.txt",
    ".env",".git/HEAD","server-status","phpinfo.php","crossdomain.xml",
    "clientaccesspolicy.xml","swagger.json","openapi.json"
]
COMMON_SUBS=["www","api","dev","test","staging","stage","admin","mail","portal","vpn","cdn","static","assets"]
SEC_HEADERS={
 "content-security-policy":("Medium","CSP is missing."),
 "strict-transport-security":("Medium","HSTS is missing on HTTPS."),
 "x-content-type-options":("Low","MIME sniffing protection is missing."),
 "x-frame-options":("Low","Clickjacking protection header is missing."),
 "referrer-policy":("Low","Referrer-Policy is missing."),
 "permissions-policy":("Info","Permissions-Policy is missing.")
}

def norm(x):
    x=x.strip()
    if not re.match(r"^https?://",x,re.I): x="https://"+x
    p=urlparse(x)
    if not p.hostname: raise ValueError("Invalid domain/URL")
    return x.rstrip("/")

def add(fs,sev,title,evidence,reco,cat):
    fs.append({"severity":sev,"title":title,"evidence":evidence,"recommendation":reco,"category":cat})

def get(s,m,u,**kw):
    kw.setdefault("timeout",TIMEOUT); kw.setdefault("allow_redirects",True)
    return s.request(m,u,**kw)

def dns_info(host):
    out={"hostname":host,"ip_addresses":[]}
    try: out["ip_addresses"]=sorted(set(socket.gethostbyname_ex(host)[2]))
    except Exception: pass
    return out

def tls_info(host):
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,443),timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as ss:
                c=ss.getpeercert()
                sans=[x[1] for x in c.get("subjectAltName",[]) if x[0]=="DNS"]
                return {"version":ss.version(),"cipher":ss.cipher()[0] if ss.cipher() else None,
                        "subject":c.get("subject"),"issuer":c.get("issuer"),
                        "notAfter":c.get("notAfter"),"san":sans}
    except Exception as e: return {"error":str(e)}

def jwt_decode(token):
    parts=token.split(".")
    if len(parts)!=3: return None
    try:
        def dec(x):
            x += "="*((4-len(x)%4)%4)
            return json.loads(base64.urlsafe_b64decode(x.encode()).decode())
        return {"header":dec(parts[0]),"payload":dec(parts[1])}
    except Exception: return None

def extract_jwts(text):
    tokens=re.findall(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",text)
    return [{"token":t,"decoded":jwt_decode(t)} for t in tokens[:10]]

def inspect_headers(resp,fs):
    h={k.lower():v for k,v in resp.headers.items()}
    for name,(sev,reason) in SEC_HEADERS.items():
        if name not in h:
            add(fs,sev,f"Missing {name}",reason,
                f"Configure {name} with an application-appropriate policy.","Security Headers")
    if h.get("server"):
        add(fs,"Info","Server banner disclosed",f"Server: {h['server']}",
            "Minimize unnecessary product/version disclosure.","Information Disclosure")
    if h.get("x-powered-by"):
        add(fs,"Low","X-Powered-By disclosed",f"X-Powered-By: {h['x-powered-by']}",
            "Remove unnecessary runtime/framework disclosure.","Information Disclosure")
    acao=h.get("access-control-allow-origin","")
    acac=h.get("access-control-allow-credentials","")
    if acao=="*" and acac.lower()=="true":
        add(fs,"High","Wildcard CORS with credentials",
            "Access-Control-Allow-Origin: * and credentials=true.",
            "Restrict origins and review credentialed cross-origin access.","CORS")
    elif acao=="*":
        add(fs,"Low","Wildcard CORS policy",acao,
            "Restrict origins where public cross-origin access is unnecessary.","CORS")
    allow=h.get("allow","")
    if "TRACE" in allow.upper():
        add(fs,"Medium","TRACE method advertised",allow,
            "Disable TRACE unless explicitly required.","HTTP Methods")

def inspect_cookies(resp,fs):
    # requests combines repeated Set-Cookie in headers inconsistently; inspect raw header where possible.
    raw=resp.headers.get("Set-Cookie","")
    for c in [x.strip() for x in re.split(r",\s*(?=[A-Za-z0-9_\-]+=)",raw) if x.strip()]:
        name=c.split("=",1)[0]
        low=c.lower()
        if "secure" not in low:
            add(fs,"Medium",f"Cookie missing Secure: {name}","Secure attribute absent.",
                "Set Secure on sensitive cookies.","Cookie Security")
        if "httponly" not in low:
            add(fs,"Low",f"Cookie missing HttpOnly: {name}","HttpOnly absent.",
                "Use HttpOnly for cookies not needing client-side access.","Cookie Security")
        if "samesite" not in low:
            add(fs,"Low",f"Cookie missing SameSite: {name}","SameSite absent.",
                "Set an appropriate SameSite policy.","Cookie Security")

def inspect_html(s,resp,fs,base):
    if "text/html" not in resp.headers.get("Content-Type","").lower(): return
    soup=BeautifulSoup(resp.text,"html.parser")
    forms=soup.find_all("form")
    pw=soup.find_all("input",attrs={"type":re.compile("^password$",re.I)})
    if pw and urlparse(resp.url).scheme!="https":
        add(fs,"High","Password field served over HTTP",resp.url,
            "Use HTTPS for authentication pages and form submissions.","Transport Security")
    if forms:
        add(fs,"Info","Forms discovered",f"{len(forms)} form(s), {len(pw)} password field(s)",
            "Manually assess authentication, authorization, CSRF and input validation.","Application Security")
    # comments
    comments=re.findall(r"<!--(.*?)-->",resp.text,re.S)
    suspicious=[c.strip()[:160] for c in comments if re.search(r"password|secret|todo|debug|api[_-]?key|token",c,re.I)]
    if suspicious:
        add(fs,"Low","Potentially sensitive HTML comments",str(suspicious[:5]),
            "Remove secrets/debug notes from production source.","Information Disclosure")
    # mixed content
    if urlparse(resp.url).scheme=="https":
        mixed=[]
        for tag,attr in [("script","src"),("img","src"),("iframe","src"),("link","href"),("form","action")]:
            for e in soup.find_all(tag):
                v=e.get(attr)
                if v and v.lower().startswith("http://"): mixed.append(v)
        if mixed:
            add(fs,"Medium","Mixed content references",f"{len(mixed)} HTTP references",
                "Serve referenced resources over HTTPS.","Transport Security")
    title=soup.title.get_text(" ",strip=True).lower() if soup.title else ""
    body=soup.get_text(" ",strip=True).lower()
    if "index of /" in title or re.search(r"\bindex of\s*/",body):
        add(fs,"Medium","Possible directory listing","Directory index markers detected.",
            "Disable directory indexing where not required.","Information Disclosure")
    # obvious client-side debug/source maps
    if ".map" in resp.text.lower():
        add(fs,"Info","Source-map reference detected","HTML references a .map resource.",
            "Review whether production source maps should be public.","Information Disclosure")

def common_resources(s,base,fs,found):
    for path in COMMON_PATHS:
        u=urljoin(base+"/",path)
        try:
            r=get(s,"GET",u)
            if r.status_code in (200,206):
                size=len(r.content)
                if path in (".env",".git/HEAD"):
                    add(fs,"High",f"Potential sensitive resource exposed: /{path}",
                        f"HTTP {r.status_code}; {size} bytes.",
                        "Remove/restrict the resource and rotate any exposed secrets.","Exposed Resources")
                elif path in ("server-status","phpinfo.php","swagger.json","openapi.json"):
                    add(fs,"Medium",f"Potentially sensitive endpoint: /{path}",
                        f"HTTP {r.status_code}; {size} bytes.",
                        "Restrict administrative/debug/API documentation endpoints as appropriate.","Exposed Resources")
                else:
                    found.append({"path":path,"status":r.status_code,"size":size})
        except requests.RequestException: pass

def methods(s,url,fs):
    try:
        r=get(s,"OPTIONS",url)
        if r.headers.get("Allow"):
            add(fs,"Info","HTTP methods disclosed",r.headers["Allow"],
                "Review whether every advertised method is necessary.","HTTP Methods")
    except requests.RequestException: pass

def security_txt(s,url,found):
    for path in (".well-known/security.txt","security.txt"):
        try:
            r=get(s,"GET",urljoin(url+"/",path))
            if r.status_code==200: found[path]=r.text[:2000]
        except requests.RequestException: pass

def score(fs):
    w={"Critical":30,"High":15,"Medium":7,"Low":2,"Info":0}
    n=min(100,sum(w.get(x["severity"],0) for x in fs))
    return n, ("Critical" if n>=60 else "High" if n>=35 else "Medium" if n>=18 else "Low" if n else "Good")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-o","--output",default="web_vapt_report.json")
    args=ap.parse_args()
    try: target=norm(args.target)
    except ValueError as e: print("[!] "+str(e)); return 1

    s=requests.Session(); s.headers["User-Agent"]=UA
    fs=[]; discovered=[]; exposed=[]; sec_txt={}

    try: resp=get(s,"GET",target)
    except requests.RequestException as e: print("[!] Connection failed:",e); return 1

    p=urlparse(resp.url); host=p.hostname
    dns=dns_info(host)
    tls=tls_info(host) if p.scheme=="https" else None
    inspect_headers(resp,fs); inspect_cookies(resp,fs); methods(s,resp.url,fs)
    inspect_html(s,resp,fs,target)
    common_resources(s,target,fs,exposed)
    security_txt(s,target,sec_txt)

    # basic subdomain discovery (DNS resolution only)
    for sub in COMMON_SUBS:
        h=f"{sub}.{host}"
        try:
            ips=socket.gethostbyname_ex(h)[2]
            if ips: discovered.append({"hostname":h,"ips":sorted(set(ips))})
        except Exception: pass

    jwts=extract_jwts(resp.text + "\n" + "\n".join(f"{k}: {v}" for k,v in resp.headers.items()))
    if jwts:
        for j in jwts:
            d=j["decoded"]
            if d and isinstance(d.get("payload"),dict):
                payload=d["payload"]
                if "exp" not in payload:
                    add(fs,"Low","JWT without visible exp claim",
                        "A JWT-like token was found without an exp claim.",
                        "Review token lifetime and server-side session invalidation.","JWT")
                if payload.get("alg")=="none":
                    add(fs,"High","JWT alg=none observed","JWT header specifies alg=none.",
                        "Reject unsigned JWTs and enforce an allow-list of algorithms.","JWT")
    risk,rating=score(fs)
    report={
        "target":target,"final_url":resp.url,"generated_at":datetime.now().isoformat(timespec="seconds"),
        "http_status":resp.status_code,"dns":dns,"tls":tls,"risk_score":risk,"risk_rating":rating,
        "findings":sorted(fs,key=lambda x:{"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}[x["severity"]]),
        "discovered_subdomains":discovered,"public_resources":exposed,
        "security_txt":sec_txt,"jwt_observations":[x["decoded"] for x in jwts if x["decoded"]]
    }
    with open(args.output,"w",encoding="utf-8") as f: json.dump(report,f,indent=2,default=str)

    print("\n"+"="*72+"\n WEB VAPT SUITE\n"+"="*72)
    print("Target:",target); print("HTTP:",resp.status_code); print("IP:",dns["ip_addresses"])
    print(f"Risk: {rating} ({risk}/100)")
    print("-"*72)
    for f in report["findings"]:
        print(f"\n[{f['severity']}] {f['title']}")
        print(" Evidence:",f["evidence"])
        print(" Recommend:",f["recommendation"])
    print(f"\n[+] Report: {args.output}")
    print("[!] Scanner is non-destructive and findings require manual validation.")
    return 0

if __name__=="__main__": raise SystemExit(main())
