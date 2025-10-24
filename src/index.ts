/// <reference types="@cloudflare/workers-types" />
/* Cloudflare Worker: Alexa Webhook mit kompletter Verifikation + Debug/Reason-Codes */

import * as jsrsasign from "jsrsasign";

type Env = { SKILL_ID: string; DEBUG?: string };

const ECHO_SAN = "echo-api.amazon.com";
const MAX_SKEW_SECONDS = 150;

/* -------------------- Helpers -------------------- */

function debug(env: Env) { return env.DEBUG === "1" || env.DEBUG === "true"; }
function log(env: Env, ...args: any[]) { if (debug(env)) console.log(...args); }
function fail(env: Env, status: number, code: string, msg?: string) {
    if (debug(env)) console.error("FAIL", code, msg ?? "");
    return new Response(JSON.stringify({ error: code }), {
        status,
        headers: { "Content-Type": "application/json", "X-Reason": code }
    });
}

function alexaResponse(text: string, end = true) {
    return {
        version: "1.0",
        response: { outputSpeech: { type: "PlainText", text }, shouldEndSession: end },
        sessionAttributes: {}
    };
}

function utf8ToHex(s: string): string {
    const bytes = new TextEncoder().encode(s);
    const out: string[] = [];
    for (const b of bytes) {
        const h = b.toString(16);
        out.push(h.length === 1 ? ("0" + h) : h);
    }
    return out.join("");
}

function parseCertTimeToDate(zulu: string): Date {
    const m = zulu.match(/^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) return new Date(NaN);
    let yyyy = m[1]!;
    const yy = yyyy.length === 2 ? parseInt(yyyy, 10) : NaN;
    if (yyyy.length === 2) yyyy = (yy >= 50 ? 1900 + yy : 2000 + yy).toString();
    return new Date(`${yyyy}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`);
}

function normalizeCertUrl(raw: string): URL | null {
    try {
        const u = new URL(raw);
        return new URL(`${u.protocol}//${u.host}${u.pathname.replace(/\/{2,}/g, "/")}${u.search}`);
    } catch { return null; }
}

function isValidSignatureCertChainUrl(u: URL) {
    return u.protocol.toLowerCase() === "https:" &&
        u.hostname.toLowerCase() === "s3.amazonaws.com" &&
        u.pathname.startsWith("/echo.api/") &&
        (u.port === "" || u.port === "443");
}

function splitPemChain(pem: string): string[] {
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    return blocks ? [...blocks] : [];
}

function pemHasEchoSan(certPem: string): boolean {
    const x = new (jsrsasign as any).X509();
    x.readCertPEM(certPem);
    const entries: any = x.getExtSubjectAltName?.() ?? x.getExtSubjectAltName2?.();
    const hasEcho = (v: any) =>
        typeof v === "string"
            ? v.toLowerCase().includes(ECHO_SAN)
            : typeof v === "object" && Object.values(v).some(val => String(val ?? "").toLowerCase().includes(ECHO_SAN));
    return Array.isArray(entries) ? entries.some(hasEcho) : hasEcho(entries);
}

function certIsTimeValid(certPem: string, now = new Date()) {
    const x = new (jsrsasign as any).X509();
    x.readCertPEM(certPem);
    const notBefore = parseCertTimeToDate(x.getNotBefore());
    const notAfter  = parseCertTimeToDate(x.getNotAfter());
    return notBefore <= now && now <= notAfter;
}

async function fetchCertPem(env: Env, url: URL): Promise<string> {
    // Cloudflare: caches.default hat eigene Typen → manuell casten
    const cache = (caches as unknown as { default: Cache }).default;
    const req = new Request(url.toString());
    const hit = await cache.match(req);
    if (hit && hit.ok) { log(env, "cache HIT", url.toString()); return await hit.text(); }
    log(env, "cache MISS", url.toString());

    const init: RequestInit & { cf?: RequestInitCfProperties } = { cf: { cacheTtl: 3600, cacheEverything: true } };
    const resp = await fetch(url.toString(), init);
    if (!resp.ok) throw new Error(`Cert fetch failed: ${resp.status}`);
    const text = await resp.text();
    await cache.put(req, new Response(text, { headers: { "Content-Type": "application/x-pem-file" } }));
    return text;
}

function verifyBodySignature(leafCertPem: string, body: string, b64sig: string, alg: "SHA256withRSA" | "SHA1withRSA") {
    const Signature = (jsrsasign as any).KJUR.crypto.Signature;
    const sig = new Signature({ alg });
    sig.init(leafCertPem);
    sig.updateHex(utf8ToHex(body));
    return sig.verify((jsrsasign as any).b64tohex(b64sig));
}

function extractAppId(evt: any) {
    return evt?.session?.application?.applicationId || evt?.context?.System?.application?.applicationId;
}

function withinTimestampSkew(tsIso?: string, now = new Date()) {
    if (!tsIso) return false;
    const ts = new Date(tsIso);
    if (Number.isNaN(ts.getTime())) return false;
    return Math.abs(now.getTime() - ts.getTime()) / 1000 <= MAX_SKEW_SECONDS;
}

/* -------------------- Worker -------------------- */

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        if (request.method === "GET" && url.pathname === "/") return new Response("OK", { status: 200 });
        if (url.pathname !== "/alexa") return new Response("Not Found", { status: 404 });
        if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: { "Allow": "POST" } });

        // Debug: ausgewählte Header loggen
        if (debug(env)) {
            const hdrs: Record<string, string> = {};
            request.headers.forEach((v, k) => { if (/^signature|content|user-agent/i.test(k)) hdrs[k] = v; });
            console.log("REQ", { method: request.method, url: url.toString(), headers: hdrs });
        }

        const certUrlRaw = request.headers.get("SignatureCertChainUrl");
        const sigB64 = request.headers.get("Signature-256") ?? request.headers.get("Signature");
        const usedAlg: "SHA256withRSA" | "SHA1withRSA" = request.headers.get("Signature-256") ? "SHA256withRSA" : "SHA1withRSA";
        if (!certUrlRaw || !sigB64) return fail(env, 400, "E1_MISSING_SIGNATURE_HEADERS");

        const certUrl = normalizeCertUrl(certUrlRaw);
        if (!certUrl || !isValidSignatureCertChainUrl(certUrl)) return fail(env, 400, "E2_INVALID_CERT_URL");

        const rawBody = await request.text();
        if (!rawBody) return fail(env, 400, "E3_EMPTY_BODY");

        // Zertifikat prüfen
        let leafPem: string | undefined;
        try {
            const pemChain = await fetchCertPem(env, certUrl);
            const blocks = splitPemChain(pemChain);
            if (!blocks || blocks.length === 0) return fail(env, 400, "E4_NO_CERTS_IN_CHAIN");
            leafPem = blocks[0]; // garantiert string dank splitPemChain()
            if (!certIsTimeValid(leafPem)) return fail(env, 400, "E5_CERT_TIME_INVALID");
            if (!pemHasEchoSan(leafPem)) return fail(env, 400, "E6_SAN_MISSING");
        } catch {
            return fail(env, 400, "E7_CERT_FETCH_OR_PARSE");
        }

        // Signatur verifizieren (über den ORIGINAL-Body)
        try {
            const ok = verifyBodySignature(leafPem!, rawBody, sigB64, usedAlg);
            if (!ok) return fail(env, 400, "E8_SIGNATURE_VERIFY_FAILED");
        } catch {
            return fail(env, 400, "E8_SIGNATURE_VERIFY_FAILED");
        }

        // JSON parsen
        let event: any;
        try { event = JSON.parse(rawBody); }
        catch { return fail(env, 400, "E9_JSON_PARSE"); }

        if (!withinTimestampSkew(event?.request?.timestamp)) return fail(env, 400, "E10_TIMESTAMP_SKEW");

        const incomingSkillId = extractAppId(event);
        if (!env.SKILL_ID || !incomingSkillId || incomingSkillId !== env.SKILL_ID) return fail(env, 401, "E11_SKILL_ID_MISMATCH");

        // Skill-Logik
        const type = event?.request?.type;
        if (type === "LaunchRequest")        return json(alexaResponse("Willkommen! Dein Cloudflare Worker ist bereit."));
        if (type === "IntentRequest")        return json(alexaResponse(`Intent ${(event?.request?.intent?.name) || "UnknownIntent"} empfangen.`));
        if (type === "SessionEndedRequest")  return json(alexaResponse("Bis bald!", true));
        return json(alexaResponse("Anfrage-Typ nicht erkannt.", true));
    }
} satisfies ExportedHandler<Env>;

function json(obj: unknown, status = 200): Response {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json" }
    });
}
