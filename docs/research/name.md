# Name research: replacement for "Tenantry"

Date: 2026-10-11. Checked: npm (registry.npmjs.org/<name>), PyPI (pypi.org/pypi/<name>/json), GitHub (github.com/<name> via WebFetch + GitHub user search), plus WebSearch for software/company conflicts.

## Key finding on GitHub
Every short coined name I checked already has a GitHub **user** handle, almost always dormant (0 repos). No bare handle was free. Plan on an org like `<name>-dev` or `<name>hq` (checked free: matura-dev, maturahq, keystrahq, sturdihq). The Go module path follows the org: `github.com/matura-dev/matura`.

## Candidates screened (~60) and why they were dropped
Common words are all taken on npm and PyPI: plinth, ballast, gantry, trellis, tessera, holdfast, bulwark, vellum, sigil, covenant, tenet, hallmark, armature, onramp, gradus, stratum, rampart, proven, attest, signet, halyard, sturdy, portcullis, lodestar, procure, stoa, agora, mantle, cadre, marque, atrium, lintel, keelson, corpora, ordinal, quire, portico, dais, kernl, gradia, tenure.
Dropped for a software or company conflict:
- tenzo: Tenzo, a restaurant analytics SaaS (https://www.gotenzo.com, $5M Series A)
- vouchr: Vouchr, a fintech gifting SaaS (https://pitchbook.com/profiles/company/64006-30)
- bastio: too close to Bastion, SOC 2/compliance for SMBs (https://bastion.tech/about), and Bastazo (OT security)
- charterd: close to Medium's "Charted" data-viz tool, plus Charter Software
- trustd: Trustd Mobile Security app, and the macOS `trustd` daemon
- procur: Procurify, Procuros, and Procur (trade platform)
- enprise: Enprise Group, a listed NZ enterprise software company (NZX: ENS)
- sovrn: Sovrn (adtech). mainsail: Mainsail (Klipper OSS UI). bizly: Bizly (events SaaS). kitemark: BSI trademark.
- keelo: close to Keel (ops SaaS, $6M seed, https://earlybird.com/companies/keel)
- rampkit, gatehaus, uplevl: GitHub org already taken. upmark, fortly, attestr, vettd: npm taken.
Clean but weaker: enterly, graduo, tenly, ledgerd, orgready, bizgate, citadl, gradkit, entkit, keystn, readied.

## Shortlist

### 1. matura (RECOMMENDED)
- Meaning: the Matura is the European school-leaving exam you pass to graduate (DE/AT/CH/PL and others). It is also Latin for "ripe" or "mature". That fits "take a prototype to market-ready" closely: the app sits its maturity exam and passes. It also echoes compliance "maturity" models (SOC 2, ISO). `matura check` reads naturally.
- Pronunciation: ma-TOO-ra. 6 letters, typed with alternating hands.
- Conflicts: none found in auth, security, compliance or devtools. Hits are only exam-prep apps (e.g. https://apps.apple.com/vn/app/id6753290304). Generic word, so it is weak as a trademark but low-risk.
- npm: FREE (404). PyPI: FREE (404). GitHub `matura`: dormant user with 0 repos (taken). `matura-dev` and `maturahq`: free.
- Risk: in German-speaking markets the word first means the exam. That is mostly harmless and on-theme.

### 2. keystra
- Meaning: from "keystone", the stone that locks the arch, plus "-stra" (structure/orchestra). The one piece that makes an app stand up for enterprise buyers.
- Conflicts: none exact. Nearby names are Keyfactor (machine identity), Keystride, KeyTrak. Only the "Key" prefix overlaps, which is mild.
- npm FREE, PyPI FREE. GitHub `keystra`: user with 2 repos (taken). `keystrahq` free.
- Risk: the "key" prefix is crowded in identity and security.

### 3. sturdi
- Meaning: "sturdy". Production-grade, solid enough to sell to businesses.
- Conflicts: none found (a web search turned up only STRV and Stilus, which only look alike).
- npm FREE, PyPI FREE. GitHub `sturdi`: dormant user (taken). `sturdihq` free.
- Risk: it reads like a misspelling, and it says nothing about enterprise or compliance.

### 4. readyr
- Meaning: "ready-er", making an app enterprise-ready. Ties straight to the tagline.
- Conflicts: none found (closest is a READYRIDE trademark for a mobile app).
- npm FREE, PyPI FREE. GitHub `readyr`: dormant user (taken).
- Risk: people will hear and type it as "reader". A pronunciation trap.

### 5. sealr
- Meaning: a seal of approval or authenticity, which fits tamper-evident audit logs, attestations and trust pages.
- Conflicts: none exact. Nearby names are Seal (OSS Android downloader), Seal Subscriptions (Shopify), SealSuite (BytePlus endpoint management).
- npm FREE, PyPI FREE. GitHub `sealr`: dormant user (taken).
- Risk: the dropped-vowel "-r" style is dated, it sits near crowded "Seal*" names, and it leans toward audit and integrity rather than the whole layer.

## Pick: **matura**
It has the strongest story: graduate your app, prototype to mature. Package names are clean on both npm and PyPI. I found no software conflicts. It is easy to say and type (`matura check`, `matura init`), and it works as the npm package `matura`, the PyPI package `matura` and the Go module `github.com/matura-dev/matura`. Next steps: run a USPTO/EUIPO search in classes 9 and 42, reserve the `matura-dev` GitHub org and the npm/PyPI names, and check domains (matura.dev was not checked).
