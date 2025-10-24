/// <reference types="@cloudflare/workers-types" />
/* Cloudflare Worker: Alexa Webhook mit kompletter Verifikation
   - Prüft SignatureCertChainUrl (https, s3.amazonaws.com, /echo.api/, Port 443)
   - Lädt Zertifikatskette, prüft Leaf-Zertifikat:
       * NotBefore/NotAfter (nicht abgelaufen)
       * SAN enthält "echo-api.amazon.com"
   - Verifiziert "Signature-256" (RSASSA-PKCS1-v1_5 + SHA-256) über den ORIGINAL-Request-Body
   - Prüft Timestamp (±150s)
   - Prüft Skill-ID
   - Antwortet im Alexa-JSON-Format
*/

import * as jsrsasign from "jsrsasign";

type Env = {
  SKILL_ID: string; // per wrangler secret/vars
};

interface AlexaRequest {
  version?: string;
  session?: { application?: { applicationId?: string } };
  context?: { System?: { application?: { applicationId?: string } } };
  request?: {
    type?: string;
    intent?: { name?: string };
    timestamp?: string; // ISO 8601
    requestId?: string;
  };
}

function alexaResponse(text: string, end = true) {
  return {
    version: "1.0",
    response: {
      outputSpeech: { type: "PlainText", text },
      shouldEndSession: end
    },
    sessionAttributes: {}
  };
}

const ECHO_SAN = "echo-api.amazon.com";
const MAX_SKEW_SECONDS = 150;

// --- Utilities ---------------------------------------------------------------

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
  let yyyy: string = m[1] as string;
  const yy = yyyy.length === 2 ? parseInt(yyyy, 10) : NaN;
  if (yyyy.length === 2) {
    yyyy = (yy >= 50 ? 1900 + yy : 2000 + yy).toString();
  }
  const [MM, DD, hh, mm, ss] = [m[2], m[3], m[4], m[5], m[6]];
  return new Date(`${yyyy}-${MM}-${DD}T${hh}:${mm}:${ss}Z`);
}

function normalizeCertUrl(raw: string): URL | null {
  try {
    const u = new URL(raw);
    const cleanPath = u.pathname.replace(/\/{2,}/g, "/");
    return new URL(`${u.protocol}//${u.host}${cleanPath}${u.search}`);
  } catch {
    return null;
  }
}

function isValidSignatureCertChainUrl(u: URL): boolean {
  const protocolOk = u.protocol.toLowerCase() === "https:";
  const hostOk = u.hostname.toLowerCase() === "s3.amazonaws.com";
  const pathOk = u.pathname.startsWith("/echo.api/");
  const port = u.port;
  const portOk = port === "" || port === "443";
  return protocolOk && hostOk && pathOk && portOk;
}

function splitPemChain(pem: string): string[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return blocks || [];
}

function pemHasEchoSan(certPem: string): boolean {
  const x = new (jsrsasign as any).X509();
  x.readCertPEM(certPem);
  let entries: any = x.getExtSubjectAltName?.(undefined, undefined) ?? x.getExtSubjectAltName2?.();
  if (!entries) return false;

  const hasEcho = (v: any) => {
    if (!v) return false;
    if (typeof v === "string") return v.toLowerCase().includes(ECHO_SAN);
    if (typeof v === "object") {
      for (const key of Object.keys(v)) {
        const val = String((v as any)[key] ?? "").toLowerCase();
        if (val.includes(ECHO_SAN)) return true;
      }
    }
    return false;
  };

  return Array.isArray(entries) ? entries.some(hasEcho) : hasEcho(entries);
}

function certIsTimeValid(certPem: string, now = new Date()): boolean {
  const x = new (jsrsasign as any).X509();
  x.readCertPEM(certPem);
  const nb: string = x.getNotBefore();
  const na: string = x.getNotAfter();
  const notBefore = parseCertTimeToDate(nb);
  const notAfter = parseCertTimeToDate(na);
  return notBefore <= now && now <= notAfter;
}

async function fetchCertPem(url: URL): Promise<string> {
  // Cachen – Zertifikate rotieren periodisch
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(url.toString());
  const cached = await cache.match(cacheKey);
  if (cached && cached.ok) return await cached.text();

  const init: RequestInit & { cf?: RequestInitCfProperties } = {
    cf: { cacheTtl: 3600, cacheEverything: true }
  };
  const resp = await fetch(url.toString(), init);
  if (!resp.ok) throw new Error(`Cert fetch failed: ${resp.status}`);
  const text = await resp.text();
  await cache.put(cacheKey, new Response(text, { headers: { "Content-Type": "application/x-pem-file" } }));
  return text;
}

function verifyBodySignature(leafCertPem: string, body: string, b64sig: string, alg: "SHA256withRSA" | "SHA1withRSA"): boolean {
  const Signature = (jsrsasign as any).KJUR.crypto.Signature;
  const sig = new Signature({ alg });
  sig.init(leafCertPem);
  const bodyHex = utf8ToHex(body);
  sig.updateHex(bodyHex);
  const sigHex = (jsrsasign as any).b64tohex(b64sig);
  return sig.verify(sigHex);
}

function extractAppId(evt: AlexaRequest): string | undefined {
  return (
    evt?.session?.application?.applicationId ||
    evt?.context?.System?.application?.applicationId
  );
}

function withinTimestampSkew(tsIso?: string, now = new Date()): boolean {
  if (!tsIso) return false;
  const ts = new Date(tsIso);
  if (Number.isNaN(ts.getTime())) return false;
  const diff = Math.abs(now.getTime() - ts.getTime()) / 1000;
  return diff <= MAX_SKEW_SECONDS;
}

// --- Alexa Handler -----------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Healthcheck
    if (request.method === "GET" && url.pathname === "/") {
      return new Response("OK", { status: 200 });
    }

    if (url.pathname !== "/alexa") {
      return new Response("Not Found", { status: 404 });
    }
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405, headers: { "Allow": "POST" } });
    }

    // --- 1) Headers einsammeln
    const certUrlRaw = request.headers.get("SignatureCertChainUrl");
    const sigB64 = request.headers.get("Signature-256") ?? request.headers.get("Signature");
    const usedAlg: "SHA256withRSA" | "SHA1withRSA" = request.headers.get("Signature-256") ? "SHA256withRSA" : "SHA1withRSA";

    if (!certUrlRaw || !sigB64) {
      return new Response("Bad Request: missing signature headers", { status: 400 });
    }

    // --- 2) Cert-URL normalisieren & prüfen
    const certUrl = normalizeCertUrl(certUrlRaw);
    if (!certUrl || !isValidSignatureCertChainUrl(certUrl)) {
      return new Response("Bad Request: invalid SignatureCertChainUrl", { status: 400 });
    }

    // --- 3) Body als TEXT (original) lesen
    const rawBody = await request.text();
    if (!rawBody) {
      return new Response("Bad Request: empty body", { status: 400 });
    }

    // --- 4) Zertifikat(e) laden & Leaf validieren
    let leafPem: string;
    try {
      const pemChain = await fetchCertPem(certUrl);
      const blocks = splitPemChain(pemChain);
      if (blocks.length === 0) throw new Error("no certs");
      leafPem = blocks[0];
      if (!certIsTimeValid(leafPem)) throw new Error("cert expired/notYetValid");
      if (!pemHasEchoSan(leafPem)) throw new Error("SAN missing echo-api.amazon.com");
    } catch (e) {
      return new Response("Bad Request: certificate invalid", { status: 400 });
    }

    // --- 5) RSA-Signatur über den ORIGINAL-Body prüfen
    try {
      const ok = verifyBodySignature(leafPem, rawBody, sigB64, usedAlg);
      if (!ok) throw new Error("signature mismatch");
    } catch {
      return new Response("Bad Request: signature verification failed", { status: 400 });
    }

    // --- 6) JSON parsen (nach erfolgreicher Signaturprüfung)
    let event: AlexaRequest;
    try {
      event = JSON.parse(rawBody);
    } catch {
      return new Response("Bad Request: invalid JSON", { status: 400 });
    }

    // --- 7) Timestamp ≤ 150s
    if (!withinTimestampSkew(event?.request?.timestamp)) {
      return new Response("Bad Request: timestamp out of tolerance", { status: 400 });
    }

    // --- 8) Skill-ID prüfen
    const incomingSkillId = extractAppId(event);
    if (!env.SKILL_ID || !incomingSkillId || incomingSkillId !== env.SKILL_ID) {
      return new Response("Unauthorized: skillId mismatch", { status: 401 });
    }

    // --- 9) Skill-Logik
    const type = event?.request?.type;
    if (type === "LaunchRequest") {
      return json(alexaResponse("Willkommen! Dein Cloudflare Worker ist bereit."));
    }
    if (type === "IntentRequest") {
      const intentName = event?.request?.intent?.name || "UnknownIntent";
      return json(alexaResponse(`Intent ${intentName} empfangen.`));
    }
    if (type === "SessionEndedRequest") {
      return json(alexaResponse("Bis bald!", true));
    }

    return json(alexaResponse("Anfrage-Typ nicht erkannt.", true));
  }
} satisfies ExportedHandler<Env>;

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
