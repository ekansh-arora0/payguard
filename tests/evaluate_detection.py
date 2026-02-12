import os
import json
import time
import base64
import http.client
import urllib.request

BACKEND="127.0.0.1"
PORT=8002

def post_bytes(img_bytes, static=True):
    try:
        b64=base64.b64encode(img_bytes).decode("utf-8")
        payload=json.dumps({"image_b64":b64,"static":bool(static)})
        conn=http.client.HTTPConnection(BACKEND,PORT,timeout=15)
        conn.request("POST","/api/media-risk/bytes",body=payload,headers={"Content-Type":"application/json"})
        resp=conn.getresponse()
        if resp.status==200:
            data=json.loads(resp.read().decode("utf-8"))
            return data
        return None
    except Exception:
        return None

def get_url_risk(url):
    try:
        conn=http.client.HTTPConnection(BACKEND,PORT,timeout=10)
        path=f"/api/media-risk?url={urllib.parse.quote(url)}&force=true"
        conn.request("GET",path)
        resp=conn.getresponse()
        if resp.status==200:
            return json.loads(resp.read().decode("utf-8"))
        return None
    except Exception:
        return None

def fetch_url(u):
    import ssl
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(u,timeout=15,context=ctx) as r:
        return r.read()

def gen_pages(base_dir):
    pages=[]
    os.makedirs(base_dir,exist_ok=True)
    p1=os.path.join(base_dir,"benign_news.html")
    open(p1,"w").write("<html><body><h2>News</h2><p>This is a normal article page.</p></body></html>")
    pages.append((p1,False))
    p2=os.path.join(base_dir,"benign_form.html")
    open(p2,"w").write("<html><body><h2>Login</h2><form><input placeholder='Email'><input placeholder='Password' type='password'></form></body></html>")
    pages.append((p2,False))
    p3=os.path.join(base_dir,"scam_full.html")
    open(p3,"w").write("<html><body style='background-color:#cc0000;color:#ffff00'><h1>Virus detected!</h1><p>Do not close this window. Call support now. Error code 0xDEADBEEF. Pay to fix.</p></body></html>")
    pages.append((p3,True))
    p4=os.path.join(base_dir,"scam_corner.html")
    open(p4,"w").write("<html><body style='background-color:#ff9900;color:#cc0000'><div style='position:fixed;right:8px;bottom:8px;background-color:#ff9900;color:#cc0000;padding:12px'>Virus detected. Do not close. Call support now.</div><p>Content</p></body></html>")
    pages.append((p4,True))
    return pages

def eval_images(ai_urls, non_ai_urls):
    tp=0; fp=0; tn=0; fn=0
    for u in ai_urls:
        try:
            b=fetch_url(u)
            data=post_bytes(b,static=True)
            ok=bool(data and any("AI-generated" in r for r in (data.get("reasons") or [])))
            if ok: tp+=1
            else: fn+=1
        except Exception:
            fn+=1
    for u in non_ai_urls:
        try:
            b=fetch_url(u)
            data=post_bytes(b,static=True)
            ok=not bool(data and any("AI-generated" in r for r in (data.get("reasons") or [])))
            if ok: tn+=1
            else: fp+=1
        except Exception:
            fp+=1
    return {"tp":tp,"fp":fp,"tn":tn,"fn":fn}

def eval_pages(pages):
    tp=0; fp=0; tn=0; fn=0
    for path,label in pages:
        data=get_url_risk(path)
        ok=bool(data and bool(data.get("scam_alert")))
        if label:
            if ok: tp+=1
            else: fn+=1
        else:
            if ok: fp+=1
            else: tn+=1
    return {"tp":tp,"fp":fp,"tn":tn,"fn":fn}

def ratio(m):
    tot=m["tp"]+m["tn"]+m["fp"]+m["fn"]
    return (m["tp"]+m["tn"])/max(1,tot)

def main():
    ds_path=os.path.join(os.path.dirname(__file__),"dataset.json")
    if os.path.exists(ds_path):
        ds=json.loads(open(ds_path).read())
    else:
        ds={"ai_image_urls":[],"non_ai_image_urls":[]}
    pages=gen_pages("/tmp/payguard_test_pages")
    print("Testing scam pages")
    m_pages=eval_pages(pages)
    print(json.dumps({"pages":m_pages,"pages_accuracy":round(ratio(m_pages),3)},indent=2))
    print("Testing AI images")
    m_images=eval_images(ds.get("ai_image_urls",[]),ds.get("non_ai_image_urls",[]))
    print(json.dumps({"images":m_images,"images_accuracy":round(ratio(m_images),3)},indent=2))
    # Test text messages via /api/risk using overlay_text
    scam_texts = ds.get("scam_texts", [])
    non_scam_texts = ds.get("non_scam_texts", [])
    tp=fp=tn=fn=0
    for t in scam_texts:
        try:
            payload = json.dumps({"url":"https://example.com","overlay_text":t})
            conn=http.client.HTTPConnection(BACKEND,PORT,timeout=15)
            conn.request("POST","/api/risk",body=payload,headers={"Content-Type":"application/json"})
            resp=conn.getresponse()
            ok=False
            if resp.status==200:
                data=json.loads(resp.read().decode("utf-8"))
                ok = bool(data and any("Scam" in r for r in (data.get("risk_factors") or [])) or data.get("risk_level")=="HIGH")
            if ok: tp+=1
            else: fn+=1
        except Exception:
            fn+=1
    for t in non_scam_texts:
        try:
            payload = json.dumps({"url":"https://example.com","overlay_text":t})
            conn=http.client.HTTPConnection(BACKEND,PORT,timeout=15)
            conn.request("POST","/api/risk",body=payload,headers={"Content-Type":"application/json"})
            resp=conn.getresponse()
            ok=True
            if resp.status==200:
                data=json.loads(resp.read().decode("utf-8"))
                ok = not bool(data and any("Scam" in r for r in (data.get("risk_factors") or [])) or data.get("risk_level")=="HIGH")
            if ok: tn+=1
            else: fp+=1
        except Exception:
            fp+=1
    m_texts={"tp":tp,"fp":fp,"tn":tn,"fn":fn}
    print(json.dumps({"texts":m_texts,"texts_accuracy":round(ratio(m_texts),3)},indent=2))

if __name__=="__main__":
    main()
