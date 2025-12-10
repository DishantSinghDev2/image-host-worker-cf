// image-worker (final)
// Bindings: IMAGES (R2), METADATA (KV), BulkProcessor (Durable Object)
// Note: KV_PROGRESS binding is listed in requirements but replaced by Durable Object storage for better consistency.

const DEF_MAX_MB = 35;
const R2_BINDING = "IMAGES";
const META_BINDING = "METADATA";
const DO_BINDING = "BulkProcessor";

const now = () => Math.floor(Date.now() / 1000);
const BULK_LIMIT = 100;

// --- Helper Functions ---

const randId = (n = 6) => {
    const A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let s = "";
    crypto.getRandomValues(new Uint8Array(n)).forEach(x => s += A[x % A.length]);
    return s;
};

const toB64Url = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const hmac = async (secret, msg) => {
    const te = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", te.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, te.encode(msg));
    return toB64Url(new Uint8Array(sig));
};

const extOf = m => {
    if (!m) return "bin";
    if (m.includes("jpeg") || m.includes("jpg")) return "jpeg";
    if (m.includes("png")) return "png";
    if (m.includes("webp")) return "webp";
    if (m.includes("gif")) return "gif";
    return m.split("/").pop();
};

const b64arr = b => {
    const bin = atob(b);
    const a = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
};

const detectMime = buf => {
    try {
        const x = new Uint8Array(buf).subarray(0, 12);
        const h = [...x].map(v => v.toString(16).padStart(2, "0")).join("");
        if (h.startsWith("ffd8")) return "image/jpeg";
        if (h.startsWith("89504e47")) return "image/png";
        if (h.startsWith("52494646")) return "image/webp";
        if (h.startsWith("47494638")) return "image/gif";
        return null;
    } catch { return null; }
};

const getDims = async blob => {
    try {
        const img = await createImageBitmap(blob);
        const d = { width: img.width, height: img.height };
        img.close?.();
        return d;
    } catch { return { width: 0, height: 0 }; }
};

const saveR2 = (env, key, body, type) => env[R2_BINDING].put(key, body, { httpMetadata: { contentType: type } });

const getR2 = async (env, key) => {
    try {
        const o = await env[R2_BINDING].get(key);
        if (!o) return null;
        const ab = await o.arrayBuffer();
        const h = new Headers();
        if (o.httpMetadata?.contentType) h.set("content-type", o.httpMetadata.contentType);
        return { ab, h, size: o.size || ab.byteLength };
    } catch { return null; }
};

const CACHE_HEADERS = { "Cache-Control": "public, max-age=31536000, immutable" };

const jsonErrNoStore = (c, m) => new Response(JSON.stringify({ success: false, status: c, message: m }), {
    status: c,
    headers: { "content-type": "application/json", "Cache-Control": "no-store, no-cache, must-revalidate" }
});

const jsonErr = (c, m) => new Response(JSON.stringify({ success: false, status: c, message: m }), {
    status: c,
    headers: { "content-type": "application/json" }
});

const jsonOK = obj => new Response(JSON.stringify(obj), { headers: { "content-type": "application/json" } });

const fmtResp = m => ({
    data: {
        id: String(m.id),
        title: String(m.name || m.id),
        url_viewer: m.url,
        url: m.url,
        display_url: m.url,
        width: String(m.width || 0),
        height: String(m.height || 0),
        size: String(m.size || 0),
        time: String(m.time || now()),
        expiration: String(m.expiration || 0),
        image: {
            filename: String(m.filename || ""),
            name: String(m.name || ""),
            mime: String(m.mime || ""),
            extension: String(m.extension || ""),
            url: String(m.url || "")
        },
        delete_url: String(m.delete_url || ""),
        plan: String(m.plan || "free")
    },
    success: true,
    status: 200
});

async function purgeLocalCache(hostname, id) {
    try {
        const cache = caches.default;
        const protocols = ["https://", "http://"];
        const uris = [`${hostname}/i/${id}`, `${hostname}/i/${id}/`];
        
        const promises = [];
        for (const proto of protocols) {
            for (const uri of uris) {
                promises.push(cache.delete(new Request(proto + uri)));
            }
        }
        await Promise.all(promises);
    } catch { }
}

async function cleanupExpired(env, id, meta, hostname) {
    try { 
        if (meta?.filename) await env[R2_BINDING].delete(meta.filename).catch(() => { }); 
    } catch { }
    try { await env[META_BINDING].delete(id); } catch { }
    if (hostname) await purgeLocalCache(hostname, id);
}

async function checkAndExpire(env, id, meta, hostname) {
    if (!meta) return false;
    if (!meta.expiration || Number(meta.expiration) === 0) return false;
    if (now() <= Number(meta.expiration)) return false;
    await cleanupExpired(env, id, meta, hostname);
    return true;
}

// --- Main Worker Logic ---

export default {
    async fetch(req, env) {
        const url = new URL(req.url);
        const path = url.pathname.replace(/\/+$/, "") || "/";
        const MAX = Number(env.MAX_UPLOAD_MB || DEF_MAX_MB);

        async function handleStringInput(s) {
            s = (s || "").trim();
            if (!s) return { err: "empty" };

            // 1. Self-URL Import (Optimization: Copy R2 object directly)
            try {
                const u = new URL(s);
                const hostMatches =
                    u.hostname === url.hostname ||
                    (env.LEGACY_BASE && new URL(env.LEGACY_BASE).hostname === u.hostname);
                
                const parts = u.pathname.split("/").filter(Boolean);
                // Matches /i/ID structure
                if (hostMatches && parts.length >= 2 && parts[0] === "i") {
                    const id = parts[1];
                    const metaRaw = await env[META_BINDING].get(id);
                    if (!metaRaw) return { err: "bad url" };
                    const meta = JSON.parse(metaRaw);
                    
                    // Retrieve from R2 directly
                    const obj = await getR2(env, meta.filename);
                    if (!obj) return { err: "bad url" };
                    
                    const mime = obj.h.get("content-type") || detectMime(obj.ab) || "application/octet-stream";
                    return { ok: true, body: obj.ab, mime };
                }
            } catch { }

            // 2. External HTTP URL
            if (/^https?:\/\//i.test(s)) {
                try {
                    const r = await fetch(s);
                    if (!r.ok) return { err: "bad url" };
                    const sizeHeader = r.headers.get("content-length");
                    const limit = MAX * 1024 * 1024;
                    if (sizeHeader && Number(sizeHeader) > limit) return { err: "too large" };

                    const blob = await r.blob();
                    if (blob.size > limit) return { err: "too large" };
                    const arr = await blob.arrayBuffer();
                    const dm = detectMime(arr);
                    const mime = r.headers.get("content-type") || dm || "application/octet-stream";
                    return { ok: true, body: arr, mime };
                } catch { return { err: "bad url" }; }
            }

            // 3. Base64 / DataURI
            if (s.startsWith("data:")) {
                const m = s.match(/^data:(.+);base64,(.*)$/);
                if (!m) return { err: "bad datauri" };
                const mime = m[1];
                const arr = b64arr(m[2]);
                if (arr.byteLength > MAX * 1024 * 1024) return { err: "too large" };
                return { ok: true, body: arr.buffer, mime };
            }
            try {
                const arr = b64arr(s);
                if (arr.byteLength > MAX * 1024 * 1024) return { err: "too large" };
                const dm = detectMime(arr.buffer);
                const mime = dm || "application/octet-stream";
                return { ok: true, body: arr.buffer, mime };
            } catch { return { err: "invalid base64 or url" }; }
        }

        try {
            // --- Upload Endpoint ---
            if (req.method === "POST" && path === "/upload") {
                const key = req.headers.get("x-api-key");
                if (!key || key !== env.MASTER_API_KEY) return jsonErr(401, "Unauthorized");

                const ultraHdr = req.headers.get("x-ultra-key");
                const proHdr = req.headers.get("x-pro-key");
                let plan = "free";
                if (ultraHdr && env.ULTRA_KEY === ultraHdr) plan = "ultra";
                else if (proHdr && env.PRO_KEY === proHdr) plan = "pro";

                let name = "", expiration = 0, mime = "application/octet-stream", body = null;
                const ct = (req.headers.get("content-type") || "").toLowerCase();

                // Multipart Form
                if (ct.includes("multipart/form-data")) {
                    const form = await req.formData();
                    const item = form.get("image");
                    if (!item) return jsonErr(400, "image required");
                    name = (form.get("name") || "") + "";
                    expiration = Number(form.get("expiration") || 0);
                    
                    if (item instanceof Blob) {
                        const ab = await item.arrayBuffer();
                        if (ab.byteLength > MAX * 1024 * 1024) return jsonErr(413, "too large");
                        const dm = detectMime(ab);
                        mime = item.type && item.type !== "application/octet-stream" ? item.type : (dm || item.type || "application/octet-stream");
                        body = ab;
                    } else if (typeof item === "string") {
                        const out = await handleStringInput(item);
                        if (out.err) return jsonErr(400, out.err);
                        mime = out.mime || mime;
                        body = out.body;
                    } else return jsonErr(400, "invalid image field");
                }
                // JSON
                else {
                    const j = await req.json().catch(() => ({}));
                    const img = j.image;
                    name = (j.name || "") + "";
                    expiration = Number(j.expiration || 0);
                    if (!img) return jsonErr(400, "image missing");
                    const out = await handleStringInput(String(img));
                    if (out.err) return jsonErr(400, out.err);
                    mime = out.mime || mime;
                    body = out.body;
                }

                const id = randId();
                const nm = (name || id).replace(/\s+/g, "_");
                const ext = extOf(mime || "");
                const fname = `${id}.${ext}`;
                const host = url.hostname;
                const publicUrl = `https://${host}/i/${id}`;
                const ts = now();

                await saveR2(env, fname, body, mime);

                let width = 0, height = 0;
                try {
                    const d = await getDims(new Blob([body]));
                    width = d.width; height = d.height;
                } catch { }

                const meta = { id, name: nm, filename: fname, mime, extension: ext, url: publicUrl, width, height, size: body.byteLength || 0, time: ts, expiration: expiration || 0, plan };
                const token = await hmac(env.DELETE_SECRET, `${id}:${ts}`);
                meta.delete_url = `https://${host}/delete/${id}/${token}`;

                await env[META_BINDING].put(id, JSON.stringify(meta));
                return jsonOK(fmtResp(meta));
            }

            // --- Public View Endpoint ---
            if (req.method === "GET" && path.startsWith("/i/")) {
                const parts = path.split("/").filter(Boolean);
                const id = parts[1];
                if (!id) return jsonErr(404, "not found");

                const cache = caches.default;
                const ck = new Request(req.url);
                const cached = await cache.match(ck);
                if (cached) return cached;

                let meta = await env[META_BINDING].get(id).then(x => x ? JSON.parse(x) : null);
                if (await checkAndExpire(env, id, meta, url.hostname)) {
                    return jsonErrNoStore(410, "This file has expired.");
                }

                const mainFile = meta?.filename || `${id}.jpeg`;
                const ro = await getR2(env, mainFile);
                if (ro) {
                    const r = new Response(ro.ab, { headers: { ...Object.fromEntries(ro.h), ...CACHE_HEADERS, "Content-Disposition": `inline; filename="${mainFile}"` } });
                    // Cache the valid response
                    await cache.put(ck, r.clone());
                    return r;
                }
                return jsonErrNoStore(404, "not found");
            }

            // --- Bulk Upload Start (Durable Object) ---
            if (req.method === "POST" && path === "/bulk-upload") {
                const key = req.headers.get("x-api-key");
                if (!key || key !== env.MASTER_API_KEY) return jsonErr(401, "Unauthorized");

                const ct = (req.headers.get("content-type") || "").toLowerCase();
                if (!ct.includes("multipart/form-data")) return jsonErr(400, "multipart required");

                const form = await req.formData();
                const items = form.getAll("files[]");
                const expiration = form.get("expiration") || "0";

                if (!items.length) return jsonErr(400, "no files");
                if (items.length > BULK_LIMIT) return jsonErr(400, "limit exceeded");

                const batchId = randId(12);

                // Get Durable Object Stub
                const id = env[DO_BINDING].idFromName(batchId);
                const stub = env[DO_BINDING].get(id);

                const doForm = new FormData();
                items.forEach(f => doForm.append("files[]", f));
                doForm.append("expiration", expiration); 

                await stub.fetch("https://do/init", {
                    method: "POST",
                    body: doForm,
                    headers: {
                        "X-BATCH-ID": batchId,
                        "X-HOST": url.hostname
                    }
                });

                return jsonOK({ success: true, batchId, total: items.length });
            }

            // --- Bulk Status ---
            if (req.method === "GET" && path.startsWith("/bulk-status/")) {
                const batchId = path.split("/")[2];
                if (!batchId) return jsonErr(400, "invalid batch");

                const id = env[DO_BINDING].idFromName(batchId);
                const stub = env[DO_BINDING].get(id);
                return await stub.fetch("https://do/status");
            }

            // --- Delete Confirmation Page ---
            if (req.method === "GET" && path.startsWith("/delete/")) {
                const [_, id, token] = path.split("/").filter(Boolean);
                if (!id || !token) return jsonErr(400, "bad delete url");
                
                const raw = await env[META_BINDING].get(id);
                if (!raw) return jsonErr(404, "not found");
                
                const meta = JSON.parse(raw);
                const expected = await hmac(env.DELETE_SECRET, `${id}:${meta.time}`);
                if (expected !== token) return jsonErr(403, "invalid token");
                
                const html = `<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;padding:20px"><h3>Delete ${id}?</h3><form method="post" action="/delete-confirm/${id}/${token}"><button>Delete</button></form></body>`;
                return new Response(html, { headers: { "content-type": "text/html;charset=utf-8" } });
            }

            // --- Delete Execute ---
            if (req.method === "POST" && path.startsWith("/delete-confirm/")) {
                const [_, id, token] = path.split("/").filter(Boolean);
                if (!id || !token) return jsonErr(400, "bad delete url");
                
                const raw = await env[META_BINDING].get(id);
                if (!raw) return jsonErr(404, "not found");
                
                const meta = JSON.parse(raw);
                const expected = await hmac(env.DELETE_SECRET, `${id}:${meta.time}`);
                if (expected !== token) return jsonErr(403, "invalid token");

                // 1. Delete R2
                try { await env[R2_BINDING].delete(meta.filename); } catch { }
                
                // 2. Legacy Delete (optional)
                try {
                    const base = (env.LEGACY_BASE || "").replace(/\/$/, "");
                    if (base) await fetch(`${base}/delete/${id}`, { method: "POST", headers: { "X-Bypass-Worker": "1" } });
                } catch { }
                
                // 3. Delete Metadata
                await env[META_BINDING].delete(id);

                // 4. Aggressive Cache Purge
                await purgeLocalCache(url.hostname, id);

                return new Response(`<html><body><h3>Deleted ${id}</h3></body></html>`, {
                    headers: { "content-type": "text/html;charset=utf-8", "Cache-Control": "no-store, no-cache, must-revalidate" }
                });
            }

            return new Response("ok");
        } catch (err) {
            return jsonErr(500, String(err));
        }
    }
};

// --- Durable Object Class ---

export class BulkProcessor {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(req) {
    const url = new URL(req.url);

    // 1. INIT & START
    if (req.method === "POST" && url.pathname === "/init") {
      const batchId = req.headers.get("X-BATCH-ID");
      const host = req.headers.get("X-HOST");
      const form = await req.formData();
      const files = form.getAll("files[]");
      const expiration = form.get("expiration");

      const initialState = {
        batchId,
        total: files.length,
        completed: 0,
        failed: 0,
        items: [],
        percent: 0,
        done: false
      };
      await this.state.storage.put("status", initialState);

      this.state.waitUntil(this.processFiles(files, host, expiration));

      return new Response("started");
    }

    // 2. CHECK STATUS
    if (url.pathname === "/status") {
      const status = await this.state.storage.get("status");
      if (!status) return jsonErr(404, "Batch not found");
      return jsonOK(status);
    }

    return new Response("ok");
  }

  async processFiles(files, host, expiration) {
    let currentStatus = await this.state.storage.get("status");

    const processOne = async (file) => {
      try {
        const ab = await file.arrayBuffer();
        const mime = file.type || detectMime(ab) || "application/octet-stream";
        const ext = extOf(mime);
        const id = randId();
        const fname = `${id}.${ext}`;
        const publicUrl = `https://${host}/i/${id}`;

        // Upload to R2
        await this.env[R2_BINDING].put(fname, ab, { httpMetadata: { contentType: mime } });

        // Save Metadata (with expiration)
        const meta = {
          id, name: id, filename: fname, mime, extension: ext,
          time: now(), 
          expiration: Number(expiration) || 0,
          url: publicUrl, plan: "free"
        };
        await this.env[META_BINDING].put(id, JSON.stringify(meta));

        return { success: true, id, url: publicUrl };
      } catch (e) {
        return { success: false, error: e.message };
      }
    };

    // Parallel Processing (Chunks of 5)
    const CHUNK_SIZE = 5;
    for (let i = 0; i < files.length; i += CHUNK_SIZE) {
      const chunk = files.slice(i, i + CHUNK_SIZE);
      const results = await Promise.all(chunk.map(f => processOne(f)));

      currentStatus = await this.state.storage.get("status");
      
      for (const res of results) {
        if (res.success) {
          currentStatus.completed++;
          currentStatus.items.push({ id: res.id, url: res.url, done: true });
        } else {
          currentStatus.failed++;
          currentStatus.items.push({ error: res.error, done: true });
        }
      }

      currentStatus.percent = currentStatus.total ? Math.round(((currentStatus.completed + currentStatus.failed) / currentStatus.total) * 100) : 0;
      await this.state.storage.put("status", currentStatus);
    }
  }
}