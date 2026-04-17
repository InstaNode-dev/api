# instanode.dev — User Stories

**Goal:** Anonymous provisioning → upgrade URL in logs → claim → paid conversion, driven by real infrastructure (Postgres, Redis, MongoDB, queue, storage, webhooks).

**Success metric:** Teams adopt paid tiers after claiming resources discovered via in-log upgrade URLs.

---

## Story: Developer Clicks Upgrade URL and Sees Pre-Filled Landing Page

**As a** developer who saw the upgrade URL in logs  
**I want** to open that URL and land on a flow that already knows which resources I provisioned  
**So that** signup feels seamless  

**Acceptance Criteria (high level):**

- [ ] `GET /start?t={jwt}` validates the onboarding JWT and returns resource context (or drives the dashboard claim flow).
- [ ] Invalid or reused JWTs yield clear errors (`401` / `409` as documented).
- [ ] OAuth (e.g. GitHub) completes and ties the session to the claim flow where enabled.

**Priority:** P1 | **Effort:** M

---

## Story: Developer Signs Up and Claims Anonymous Resources

**As a** developer who used anonymous `POST /db/new` (and similar) from an agent  
**I want** one sign-in step to attach those resources to my team  
**So that** nothing is lost when anonymous TTL would have expired  

**Acceptance Criteria (high level):**

- [ ] `POST /claim` with a valid onboarding JWT transfers anonymous resources to the new team and enforces single-use JTI semantics.
- [ ] Concurrent claims with the same JWT result in exactly one success (`201`) and conflicts (`409`) for the rest.

**Priority:** P1 | **Effort:** L

---

## Story: Developer Upgrades to Pro via Razorpay

**As a** developer on Hobby  
**I want** to upgrade to Pro  
**So that** I get higher limits on new and promoted resources  

**Acceptance Criteria (high level):**

- [ ] Authenticated `POST /billing/checkout` starts Razorpay subscription checkout (`short_url` or equivalent).
- [ ] `POST /razorpay/webhook` verifies `RAZORPAY_WEBHOOK_SECRET` and updates `plan_tier` / resource tiers per handler rules.

**Priority:** P1 | **Effort:** L

---

## Story: Trial Expiry and Payment Prompt

**As a** developer on trial  
**I want** clear email and in-product prompts before trial ends  
**So that** I am not surprised by downgrades  

**Priority:** P1 | **Effort:** M

---

## Story: Observability Into the Conversion Funnel

**As a** operator  
**I want** metrics and structured logs for provision → claim → paid steps  
**So that** I can see where users drop off  

**Acceptance Criteria (high level):**

- [ ] `GET /metrics` exposes counters/histograms used for provisioning and funnel steps.
- [ ] Logs include `request_id` and safe fingerprint prefixes only.

**Priority:** P1 | **Effort:** M

---

## Story: Operator Detects Abuse at the Edge

**As an** operator  
**I want** fingerprint-based provisioning limits that fail open  
**So that** good actors always receive a usable credential while abuse is throttled  

**Priority:** P2 | **Effort:** M

---

## Story: Dev Team Runs the Stack Locally

**As a** backend developer  
**I want** docker-compose or k8s instructions that match production paths  
**So that** I can run integration tests and manual QA quickly  

**Priority:** P2 | **Effort:** M

---

## Story Priority Matrix

| Story | Priority | Must ship for launch |
|-------|----------|----------------------|
| Upgrade URL / start landing | P1 | Yes |
| Claim anonymous resources | P1 | Yes |
| Pro plan via Razorpay | P1 | Yes |
| Trial / payment prompts | P1 | Yes |
| Funnel observability | P1 | Yes |
| Abuse controls | P2 | No |
| Local dev stack | P2 | No |
