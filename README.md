# Alexa Password Worker (Cloudflare Workers)

Bereitstellt `/alexa` als HTTPS-Webhook für einen Alexa Custom Skill mit vollständiger Verifikation.

## Schnellstart

```bash
npm i
# Skill-ID als Secret setzen (empfohlen):
npx wrangler secret put SKILL_ID
# Eingeben: amzn1.ask.skill.<DEINE-ID>

# Lokal testen (ohne echte Alexa-Header gibt's 400 – erwartbar)
npm run dev

# Deploy
npm run deploy
```

## IDE/TypeScript-Hinweise
- Stelle sicher, dass die **Workspace-TypeScript-Version** genutzt wird und die `tsconfig.json` geladen ist.
- Wir binden `@cloudflare/workers-types` ein und referenzieren sie zusätzlich in `src/index.ts`:
  ```ts
  /// <reference types="@cloudflare/workers-types" />
  ```

In der Alexa Developer Console die **komplette URL inkl. `/alexa`** als Endpoint eintragen.
