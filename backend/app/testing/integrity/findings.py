"""Finding model + pre-registered oracle specifications of the customer-level engine.

``Finding.__post_init__`` makes ``CONFIRMED_P0`` unconstructible without a ``ConfirmationToken`` that covers the hypothesis and that was
issued by ``ConfirmationGate.evaluate`` (i.e. without the full external Protected-Feature Oracle chain). Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.control_port import ConfirmationRefused
from app.core.control_port.contract import now_iso
from app.testing.purity.taxonomy import TruthLabel, Verdict

ENGINE_VERSION = "pbb-oracle-engine/1.0"


@dataclass(frozen=True)
class OracleSpec:
    """The ten elements every oracle is pre-registered with (fixed BEFORE any traffic, so no result can redefine its own test)."""

    invariant: str
    baseline_state: str
    identity_and_tenant: str
    controlled_variable: str
    action_sequence: str
    expected_outcome: str
    p0_condition: str
    rule_out_condition: str
    stop_condition: str
    evidence_requirements: str

    def completeness(self) -> float:
        values = list(self.__dict__.values())
        return sum(1 for v in values if isinstance(v, str) and v.strip()) / len(values)


_COMMON_EVIDENCE = ("every call is an admitted artifact with external provenance (identity alias, tenant alias, session isolation id, authorization ref, "
                    "hash, external classification); the allowed/denied outcome comes only from USING the server-enforced feature")
_COMMON_STOP = "scope/purity denial, kill switch, request budget exhausted, a pre-existing entitlement on a fresh identity (fixture contaminated), or any admitted-evidence rejection"

SPECS: dict[str, OracleSpec] = {
    "PBB-U": OracleSpec(
        invariant="A payment that is declined, cancelled or abandoned never makes a paid feature usable -- whatever the return URL, page or badge claims.",
        baseline_state="Fresh synthetic identity: paid feature DENIED (control identity K also denied, and a legitimate payer is ALLOWED, so the oracle can say both).",
        identity_and_tenant="subject S (own synthetic tenant, one per variant), control K, clean re-session of S.",
        controlled_variable="payment outcome (declined | cancelled) followed by a return-flow request claiming success.",
        action_sequence="pre-check S -> checkout (cheapest plan) -> sandbox pay with outcome -> return flow with success claim -> USE the feature as S -> clean re-session of S -> re-check K.",
        expected_outcome="Feature DENIED for S in every variant (a UI/redirect/badge claiming success is a divergence, not an entitlement).",
        p0_condition="S USES the feature successfully after a non-qualifying payment, K still denied, reproduced by a clean session of S, all artifacts admitted.",
        rule_out_condition="S denied in every tested variant while the oracle is proven discriminating (legitimate payer allowed, clean identity denied).",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-F": OracleSpec(
        invariant="The plan a customer pays for -- at the price on the public price list -- is the plan they get. Neither a cheaper payment nor a client-side claim buys a higher tier.",
        baseline_state="Legitimate cheapest-plan payer: tier feature DENIED; legitimate top-plan payer: tier feature ALLOWED; clean identity: DENIED.",
        identity_and_tenant="V1 (cheapest payer from controls), S1 (checkout amount tamper), S2 (return plan claim), control K.",
        controlled_variable="plan enforcement / amount accepted at checkout / plan claimed at the return flow.",
        action_sequence="(0) V1 on tier feature; (A) checkout top plan with the cheapest public amount -> pay -> return -> tier; (B) pay cheapest -> return -> tier denied -> return with top-plan claim -> tier.",
        expected_outcome="Tier feature DENIED for every payer of the cheapest plan; a tampered checkout is rejected or billed at the public price.",
        p0_condition="A payer who did not pay the top-plan price USES the tier feature, K denied, clean re-session reproduces, artifacts admitted.",
        rule_out_condition="All applicable channels end DENIED (or the tampered checkout is rejected) with a discriminating tier oracle.",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-H": OracleSpec(
        invariant="Paying in another listed currency is billed at the public price of that currency; an under-billed payment never unlocks the top tier.",
        baseline_state="Top-plan tier feature DENIED for a fresh identity; public price list gives the amount per currency.",
        identity_and_tenant="subject S (own tenant), control K.",
        controlled_variable="checkout currency.",
        action_sequence="checkout top plan in the alternative currency -> compare billed amount/currency with the public price list -> sandbox success -> return -> USE tier feature.",
        expected_outcome="Billed amount equals the public price for that currency, or the checkout is rejected; no tier access on an under-billed payment.",
        p0_condition="Billed amount < public price AND S USES the tier feature, K denied, clean re-session reproduces.",
        rule_out_condition="No billing mismatch, or a mismatch with tier access correctly DENIED (reported as a billing divergence, not P0).",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-C": OracleSpec(
        invariant="One successful payment yields exactly the paid quota, however often the customer's browser repeats the return flow (refresh, back button, retry).",
        baseline_state="Legitimate single-payment baseline Q: counts n0 successful uses of the quota feature before the first denial; clean identity denied.",
        identity_and_tenant="baseline payer Q, subject R (and independent R2 for reproduction), control K.",
        controlled_variable="number of return-flow repetitions (0 for Q, 2 for R).",
        action_sequence="Q: pay -> return once -> use quota until denied (n0). R: pay -> return -> repeat return twice -> use until denied (n1). R2 repeats R. Re-check K.",
        expected_outcome="n1 == n0 (repetition grants nothing).",
        p0_condition="n1 > n0 for R and again for the independent R2, K denied, artifacts admitted.",
        rule_out_condition="n1 <= n0 for R, with 0 < n0 < probe cap (a bounded, observable quota).",
        stop_condition=_COMMON_STOP + "; quota not bounded within the probe cap (cap is low-volume by contract)", evidence_requirements=_COMMON_EVIDENCE),
    "PBB-G": OracleSpec(
        invariant="A payment benefits only the tenant that paid; another tenant cannot be named as beneficiary by a client claim.",
        baseline_state="Beneficiary identity B (own tenant) denied; control K denied.",
        identity_and_tenant="payer S/tenant_s, beneficiary B/tenant_b (its OWN tenant id, visible to B), control K.",
        controlled_variable="tenant claimed at the return flow.",
        action_sequence="S pays -> B pre-check denied -> S calls return flow naming B's tenant -> B USES the feature -> clean re-session of B -> re-check K.",
        expected_outcome="B denied.",
        p0_condition="B (never paid) USES the feature, K denied, clean re-session of B reproduces, artifacts admitted.",
        rule_out_condition="B denied while the oracle is discriminating.",
        stop_condition=_COMMON_STOP + "; B's tenant id not externally available", evidence_requirements=_COMMON_EVIDENCE),
    "PBB-X": OracleSpec(
        invariant="A payment can only be redeemed by the identity that made it.",
        baseline_state="Redeemer identity B denied; control K denied.",
        identity_and_tenant="payer S, redeemer B (different identity and tenant), control K.",
        controlled_variable="identity presenting the payment reference at the return flow.",
        action_sequence="S pays (no return by S) -> B pre-check denied -> B calls return flow with S's payment reference -> B USES the feature -> clean re-session of B -> re-check K.",
        expected_outcome="B denied (return flow rejects a payment that is not B's).",
        p0_condition="B USES the feature thanks to S's payment, K denied, clean re-session reproduces, artifacts admitted.",
        rule_out_condition="B denied while the oracle is discriminating.",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-R": OracleSpec(
        invariant="After a customer-visible refund of their own sandbox payment the paid feature stops working within the declared revocation tolerance.",
        baseline_state="Payer V ALLOWED before the refund; control K denied.",
        identity_and_tenant="payer V (own tenant), clean re-session of V, control K.",
        controlled_variable="elapsed time since the externally confirmed refund (bounded poll schedule, <= 8 polls).",
        action_sequence="V pays + returns -> allowed -> refund own payment -> confirm refund response -> poll the feature on the schedule (and just beyond the declared tolerance) -> clean re-session at the first allowed-beyond-tolerance poll.",
        expected_outcome="Feature DENIED at or before the declared tolerance.",
        p0_condition="Feature still USABLE beyond the declared tolerance (CUSTOMER_DECLARED threshold), reproduced by a clean session, K denied, artifacts admitted.",
        rule_out_condition="First DENIED observation within the tolerance.",
        stop_condition=_COMMON_STOP + "; refund not externally confirmed", evidence_requirements=_COMMON_EVIDENCE + "; the measured lag is an upper bound given by the poll schedule"),
    "PBB-E": OracleSpec(
        invariant="What customer-visible pages say (return message, subscription view) never contradicts the server-enforced paid-feature outcome.",
        baseline_state="Observations collected during the controls and PBB-U (no extra traffic).",
        identity_and_tenant="V1 (legit payer), K (clean), S (declined payer).",
        controlled_variable="none (observation of the customer-visible views against the oracle).",
        action_sequence="compare subscription view / return message with the oracle outcome of the same identity at the same time.",
        expected_outcome="View says paid exactly where the oracle says ALLOWED.",
        p0_condition="never P0 by itself: a view/UI claim is non-authoritative evidence.",
        rule_out_condition="No contradiction observed (or none observable).",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-LEAK": OracleSpec(
        invariant="One customer's payment never makes a paid feature usable for an unrelated identity that has not paid.",
        baseline_state="Clean control identity K DENIED before any payment of this run; a legitimate payer is then ALLOWED.",
        identity_and_tenant="control K (never pays, own tenant), legitimate payer V1 (own tenant), clean re-session of K.",
        controlled_variable="whether another identity has paid (time order: K denied -> V1 pays -> K checked again).",
        action_sequence="K uses the feature (denied) -> V1 pays and returns -> V1 uses the feature (allowed) -> K uses the feature again -> clean re-session of K.",
        expected_outcome="K stays DENIED.",
        p0_condition="K, which never paid, USES the feature after V1's payment, K was denied before, a clean re-session of K reproduces it, artifacts admitted.",
        rule_out_condition="K denied after V1's payment (checked as part of the controls; no separate finding is emitted then).",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-D": OracleSpec(
        invariant="A subject's own object is readable only by that subject (or an explicitly granted party); another authenticated subject cannot read it -- object-level ownership is enforced on every read path.",
        baseline_state="Owner B creates its OWN object (server mints a private reference + a private value); an UNAUTHENTICATED read of that object is REFUSED (so the object is access-controlled, not public); a non-owner A is the subject under test.",
        identity_and_tenant="owner B (own tenant, holds the object), non-owner A (different synthetic tenant), independent clean non-owner A2 for reproduction, unauthenticated session as the discriminating control.",
        controlled_variable="the reader's relationship to the object (owner vs authenticated non-owner vs unauthenticated), using ONLY the engine's own object reference (never a guessed/foreign id).",
        action_sequence="B creates its own object -> B self-reads (captures the owner-private value) -> UNAUTHENTICATED read of the same object (control: refused) -> A (authenticated non-owner) reads it -> A2 (independent clean non-owner) reproduces.",
        expected_outcome="A (and A2) DENIED; only the owner and the unauthenticated-refused control are observed.",
        p0_condition="A, an authenticated non-owner, reads B's object and obtains B's server-minted OWN-PRIVATE value, the unauthenticated control stays REFUSED (discriminating), and an independent clean session reproduces it, all artifacts admitted.",
        rule_out_condition="A refused (owner-scoped read), or the unauthenticated control is ALLOWED (public-by-design -> abstain), while the read oracle is discriminating.",
        stop_condition=_COMMON_STOP + "; no owner-private value is observable on the object read; a resource intended-shared among all authenticated users with no observable owner boundary (documented ceiling)",
        evidence_requirements=_COMMON_EVIDENCE + "; the non-owner must obtain the SAME owner-private value the owner's self-read returned (provenance-bound), never a bare 200"),
    "PBB-SIG": OracleSpec(
        invariant="An endpoint that requires a request signature must reject requests with absent, empty, malformed, or algorithm-downgraded signatures.",
        baseline_state="A legitimately signed request succeeds; fresh identity with no signature is denied.",
        identity_and_tenant="subject S (own synthetic tenant) with a valid signing key, control K (unsigned/clean).",
        controlled_variable="signature header presence and content (absent, empty, alg:none, truncated, wrong-key).",
        action_sequence="S signs a valid request (succeeds) -> S sends the same request with no signature -> empty signature -> alg:none -> truncated signature -> wrong key. Each variant is checked against the protected-feature oracle.",
        expected_outcome="Every bypass variant DENIED; only the legitimately signed request is ALLOWED.",
        p0_condition="S USES the feature with a bypass signature variant (absent/empty/none/truncated/wrong-key), the legitimately signed control succeeds, and a clean session reproduces it.",
        rule_out_condition="All bypass variants denied while the signed control succeeds.",
        stop_condition=_COMMON_STOP + "; no signature-requiring endpoint in the brief's declared surface",
        evidence_requirements=_COMMON_EVIDENCE + "; the bypass variant's signature header (or absence) is captured in the admitted artifact"),
    "PBB-AUTH": OracleSpec(
        invariant="An endpoint that requires authentication must reject requests with absent, empty, malformed, or expired bearer tokens.",
        baseline_state="A legitimately authenticated request succeeds; an unauthenticated request is denied.",
        identity_and_tenant="subject S (authenticated, own synthetic tenant), control K (unauthenticated/clean).",
        controlled_variable="Authorization header presence and content (absent, empty Bearer, malformed token, expired-pattern token, null-byte token).",
        action_sequence="S authenticates legitimately (succeeds) -> request with no Authorization header -> empty 'Bearer ' -> 'Bearer null' -> 'Bearer <truncated>' -> 'Bearer 0000'. Each variant is checked against the protected-feature oracle.",
        expected_outcome="Every unauthenticated variant DENIED; only the legitimately authenticated request is ALLOWED.",
        p0_condition="S USES the feature with a bypass auth variant (no token/empty/malformed), the authenticated control succeeds, and a clean session reproduces it.",
        rule_out_condition="All bypass variants denied while the authenticated control succeeds.",
        stop_condition=_COMMON_STOP + "; no authentication-requiring endpoint in the brief's declared surface",
        evidence_requirements=_COMMON_EVIDENCE + "; the bypass variant's Authorization header (or absence) is captured in the admitted artifact"),
    "PBB-RATE": OracleSpec(
        invariant="Server-side rate limits and quota enforcement must not be bypassable by client-side techniques (identity rotation, connection reuse, header spoofing).",
        baseline_state="A single identity hitting its declared rate limit is denied; fresh identities are allowed their own quota.",
        identity_and_tenant="subject S1 (hits limit), S2-S4 (rotation pool), control K (clean).",
        controlled_variable="client-side evasion technique (identity rotation across S1-S4, X-Forwarded-For spoofing, connection keep-alive reuse, rapid sequential burst).",
        action_sequence="S1 drives to the declared rate limit (denied) -> S1 retries with X-Forwarded-For spoofed -> S1 retries with different User-Agent -> rotate to S2 on the same resource -> burst S1-S4 concurrently. Check the protected-feature oracle for over-limit grants.",
        expected_outcome="Rate-limited identity stays denied regardless of client header changes; identity rotation is legitimate (each gets its own quota) but a single resource's total does not exceed the global cap.",
        p0_condition="An identity that exceeded its rate limit USES the feature via a client-side evasion technique, or the total grants across rotated identities exceed the resource's declared global cap.",
        rule_out_condition="Rate-limited identity stays denied under all evasion variants; rotated identities each get exactly their own quota with no global over-grant.",
        stop_condition=_COMMON_STOP + "; no declared rate limit or quota cap in the brief",
        evidence_requirements=_COMMON_EVIDENCE + "; request count, denial count, and the evasion header used are captured per variant"),
    "PBB-IDOR": OracleSpec(
        invariant="Object references must not be guessable or enumerable; sequential, predictable, or nearby IDs must not resolve to other users' objects.",
        baseline_state="Owner B creates an object and receives a reference; non-owner A holds no reference to B's object.",
        identity_and_tenant="owner B (own tenant), non-owner A (different synthetic tenant), independent A2 for reproduction.",
        controlled_variable="the object reference A presents (sequential +/-1, +/-10, zero-padded variants, base64-decoded-and-modified, UUID v1 time-adjacent).",
        action_sequence="B creates its own object (captures the reference) -> derive candidate IDs from B's reference (sequential, adjacent, predictable patterns) -> A requests each candidate -> check whether any resolves to a real object with a different owner's data -> A2 reproduces.",
        expected_outcome="All guessed references DENIED or return 404; no object belonging to another owner is retrieved.",
        p0_condition="A retrieves an object belonging to another owner using a guessed/enumerated reference derived from B's legitimate reference, A2 reproduces, artifacts admitted.",
        rule_out_condition="All guessed references denied or 404, while B's own reference works for B (the object endpoint is functional).",
        stop_condition=_COMMON_STOP + "; no object-reference endpoint in the brief's declared surface; references are opaque UUIDs with no observable sequential pattern",
        evidence_requirements=_COMMON_EVIDENCE + "; the guessed reference and the derivation method are captured in the admitted artifact"),
    "PBB-OPEN": OracleSpec(
        invariant="A feature the brief declares plan-gated is DENIED to a fresh identity that never paid.",
        baseline_state="Two independent fresh identities, no payment attempt.",
        identity_and_tenant="K and K2 (independent fresh synthetic identities).",
        controlled_variable="none.",
        action_sequence="USE the feature as K and as K2.",
        expected_outcome="Both DENIED.",
        p0_condition="never CONFIRMED_P0: with no denial control the confirmation pattern cannot be executed -> PARTIALLY_VALIDATED.",
        rule_out_condition="Both denied.",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-TWIN": OracleSpec(
        invariant="A target's responses must be deterministic and reproducible: identical requests from independent sessions yield identical status codes, headers, and body structures within stated tolerance.",
        baseline_state="Two independent sessions with identical credentials targeting the same endpoint set.",
        identity_and_tenant="S1 and S2 (independent sessions, same synthetic identity credentials); R1 repeat session for temporal stability.",
        controlled_variable="request timing, ordering, and repetition count across endpoints.",
        action_sequence="S1 sends request set R to N endpoints -> capture full response fingerprints (status, header keys, body structure, timing) -> S2 sends identical R -> capture -> diff fingerprints -> R1 repeats after delay -> build twin fidelity matrix.",
        expected_outcome="All response fingerprints match within declared tolerance; temporal stability confirmed.",
        p0_condition="Response fingerprint divergence exceeds tolerance AND divergence reveals exploitable state-dependent routing, session-binding, or environment-leak behavior.",
        rule_out_condition="All response fingerprints match within tolerance across all tested endpoints and temporal samples.",
        stop_condition=_COMMON_STOP + "; fewer than 3 endpoints in the brief's declared surface",
        evidence_requirements=_COMMON_EVIDENCE + "; paired request/response captures with full headers and timing for each fingerprint comparison"),
    "PBB-CRED": OracleSpec(
        invariant="No server response, error message, header, or publicly reachable path may expose credentials, API keys, tokens, secrets, or internal authentication material.",
        baseline_state="Fresh synthetic identity with standard access, plus unauthenticated session for public path probing.",
        identity_and_tenant="subject S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the request path (common credential-leak paths: .env, /config, /debug, /api-docs, /actuator, /.git/config) and error-trigger payloads.",
        action_sequence="U probes common credential-leak paths -> S triggers errors with malformed inputs to elicit verbose responses -> scan all response bodies, headers, and error messages for credential patterns (API keys, tokens, passwords, connection strings, private keys) -> S2 reproduces any hits.",
        expected_outcome="No credential material found in any response body, header, or error message.",
        p0_condition="A response contains a credential pattern (API key, bearer token, password, connection string, private key) that matches known credential formats, reproduced by S2.",
        rule_out_condition="No credential patterns found across all probed paths, error responses, and header inspections.",
        stop_condition=_COMMON_STOP + "; target returns 403/404 on all common paths (hardened surface)",
        evidence_requirements=_COMMON_EVIDENCE + "; the leaked credential pattern, the path or trigger that exposed it, and the classification"),
    "PBB-ADPATH": OracleSpec(
        invariant="Active Directory and LDAP endpoints must not be exposed to external access, must reject injection payloads, and must not leak domain/forest topology in error responses.",
        baseline_state="Fresh synthetic identity probing for AD/LDAP exposure indicators.",
        identity_and_tenant="subject S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the request payload (LDAP filter injection, Kerberos indicators via WWW-Authenticate: Negotiate, NTLM challenge triggers, AD-specific path probes).",
        action_sequence="U probes for AD-indicating endpoints (/adfs, /ews, /autodiscover, /ldap) -> S sends LDAP injection payloads to search/filter parameters -> check for Negotiate/NTLM auth headers -> scan error messages for domain names, DC hostnames, forest paths -> S2 reproduces.",
        expected_outcome="No AD/LDAP endpoints exposed; no injection possible; no domain topology leaked.",
        p0_condition="LDAP injection returns data, or Negotiate/NTLM handshake initiates on a public endpoint, or error messages leak domain controller names/forest topology, reproduced by S2.",
        rule_out_condition="No AD indicators found; all injection payloads rejected or produce generic errors; no domain information in any response.",
        stop_condition=_COMMON_STOP + "; target shows no indicators of Windows/AD infrastructure",
        evidence_requirements=_COMMON_EVIDENCE + "; the AD indicator type, the endpoint, the injection payload or leaked topology detail"),
    "PBB-C2": OracleSpec(
        invariant="No endpoint should provide a viable command-and-control channel: outbound callback capability, unrestricted WebSocket upgrade, SSRF-viable parameters, or data-exfiltration channels must not exist on public-facing surface.",
        baseline_state="Fresh synthetic identity testing for C2-viable channel indicators.",
        identity_and_tenant="subject S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the channel technique (WebSocket upgrade, SSRF with internal/callback URLs, DNS rebinding indicators, chunked transfer abuse, long-poll/streaming endpoints, bidirectional channels).",
        action_sequence="S tests WebSocket upgrade on each endpoint -> S injects SSRF-candidate URLs into URL-accepting parameters -> test for DNS rebinding via Host header manipulation -> probe streaming/long-poll endpoints for persistent channels -> S2 reproduces.",
        expected_outcome="No C2-viable channels found: WebSocket rejected on non-WS endpoints, SSRF payloads rejected, no outbound callbacks, no persistent bidirectional channels.",
        p0_condition="A C2-viable channel is confirmed: SSRF reaches internal hosts, WebSocket upgrades on non-designated endpoints, or persistent bidirectional channels exist, reproduced by S2.",
        rule_out_condition="All C2 channel techniques rejected or non-functional across all tested endpoints.",
        stop_condition=_COMMON_STOP + "; target has no URL-accepting parameters or real-time endpoints",
        evidence_requirements=_COMMON_EVIDENCE + "; the channel type, the endpoint, the payload that established the channel, and evidence of bidirectional or outbound capability"),
    "PBB-IAM": OracleSpec(
        invariant="Cloud IAM roles and metadata must not be accessible through the application layer: metadata endpoints must be blocked, role tokens must not leak in responses, and privilege boundaries must hold under parameter manipulation.",
        baseline_state="Fresh synthetic identity testing for cloud IAM exposure.",
        identity_and_tenant="subject S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the escalation vector (SSRF to cloud metadata 169.254.169.254, instance identity document, role token endpoints; parameter manipulation of role/permission fields; cross-service token confusion).",
        action_sequence="S injects cloud metadata URLs into URL-accepting parameters -> S sends requests with manipulated role/permission parameters -> check responses for cloud provider tokens (AWS STS, GCP access tokens, Azure MSI) -> test for cross-service token acceptance -> S2 reproduces.",
        expected_outcome="Metadata endpoints blocked; no IAM tokens in responses; privilege parameters rejected or have no effect.",
        p0_condition="Cloud metadata accessible via SSRF, or IAM/service role tokens leak in responses, or privilege escalation via parameter manipulation succeeds, reproduced by S2.",
        rule_out_condition="All metadata probes blocked; no IAM tokens found; privilege parameters have no effect.",
        stop_condition=_COMMON_STOP + "; target shows no cloud hosting indicators",
        evidence_requirements=_COMMON_EVIDENCE + "; the cloud provider, the escalation vector, the leaked token or metadata, and the escalated privilege level"),
    "PBB-RBAC": OracleSpec(
        invariant="Role-based access controls must enforce complete separation: no role may access resources or operations belonging to a higher-privilege or different-scope role through parameter manipulation, path traversal, or endpoint enumeration.",
        baseline_state="Two synthetic identities with different role levels (if the brief declares roles) or standard and elevated access.",
        identity_and_tenant="subject S (standard role), E (elevated role if obtainable), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the RBAC escape technique (direct path access to admin endpoints, role parameter manipulation, HTTP method switching on role-gated endpoints, header-based role injection).",
        action_sequence="S accesses E's endpoints directly -> S manipulates role/permission parameters -> S tries HTTP method switching (GET->POST, POST->PUT) on role-gated endpoints -> S injects admin/role headers -> S2 reproduces any successful escalation.",
        expected_outcome="All cross-role access denied; parameter manipulation has no effect; method switching produces same authorization result.",
        p0_condition="S accesses resources or operations belonging to E's role level through any escape technique, reproduced by S2.",
        rule_out_condition="All RBAC escape techniques rejected across all tested endpoints.",
        stop_condition=_COMMON_STOP + "; target shows no multi-role indicators in the brief",
        evidence_requirements=_COMMON_EVIDENCE + "; the escape technique, the source and target roles, the endpoint, and the unauthorized resource accessed"),
    "PBB-BPWPN": OracleSpec(
        invariant="Defensive controls (WAF, input validation, output encoding) must not be bypassable through encoding tricks, protocol-level manipulation, or known bypass patterns.",
        baseline_state="Fresh synthetic identity with a set of known-blocked payloads and their bypass variants.",
        identity_and_tenant="subject S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the bypass technique (double URL encoding, unicode normalization, null-byte injection, HTTP method override, path normalization /.//../, content-type switching, chunked transfer encoding, case variation).",
        action_sequence="S sends a baseline blocked payload -> confirm block -> S sends bypass variants (encoded, normalized, chunked, method-overridden) -> compare responses -> if bypass succeeds, S2 reproduces.",
        expected_outcome="All bypass variants blocked identically to the baseline payload.",
        p0_condition="A bypass variant of a blocked payload passes through defensive controls and is processed by the application, reproduced by S2.",
        rule_out_condition="All bypass variants produce the same block response as the baseline across all tested endpoints.",
        stop_condition=_COMMON_STOP + "; no detectable WAF or input validation (all payloads pass through, indicating no controls to bypass)",
        evidence_requirements=_COMMON_EVIDENCE + "; the baseline blocked payload, the bypass variant that succeeded, the technique, and the differential response"),
    "PBB-REVENG": OracleSpec(
        invariant="Client-side code (JavaScript bundles, WASM modules, API schemas) must not expose hidden endpoints, hardcoded secrets, internal API structures, or undocumented privileged operations.",
        baseline_state="Fresh session downloading all client-side assets (JS bundles, source maps, API schemas).",
        identity_and_tenant="subject S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the analysis target (JavaScript bundles, source maps, WASM binaries, OpenAPI/Swagger schemas, GraphQL introspection, embedded configuration objects).",
        action_sequence="U/S downloads all JS bundles and client assets -> extract endpoints via regex (URL patterns, fetch/axios calls, route definitions) -> extract hardcoded tokens/keys -> identify undocumented admin endpoints -> S2 verifies discovered endpoints are reachable.",
        expected_outcome="No hidden endpoints, hardcoded secrets, or undocumented privileged operations found in client-side code.",
        p0_condition="Client-side code reveals functional hidden endpoints, hardcoded valid credentials, or undocumented operations that bypass normal access controls, confirmed reachable by S2.",
        rule_out_condition="No actionable secrets, hidden endpoints, or privileged operations found in client-side analysis.",
        stop_condition=_COMMON_STOP + "; no JavaScript bundles or client-side assets available",
        evidence_requirements=_COMMON_EVIDENCE + "; the source asset, the extraction method, the discovered endpoint/secret, and confirmation of reachability"),
    "PBB-ZDAY": OracleSpec(
        invariant="Application inputs must be safely parsed and processed: no input mutation strategy (type confusion, boundary values, format strings, oversized payloads, null injection) should cause unexpected behavior, crashes, or information disclosure.",
        baseline_state="Fresh synthetic identity with baseline valid requests establishing normal response patterns.",
        identity_and_tenant="subject S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the mutation strategy (type confusion, boundary values INT_MAX/INT_MIN/0/-1, format strings, null injection, oversized arrays/objects, deeply nested JSON, mixed-encoding payloads).",
        action_sequence="S establishes baseline responses per endpoint -> S sends mutated inputs per strategy -> compare responses to baseline (crashes, stack traces, timing anomalies, memory disclosure) -> S2 reproduces anomalies.",
        expected_outcome="All mutation payloads produce clean error responses consistent with input validation; no crashes or anomalous behavior.",
        p0_condition="A mutation strategy causes a crash (5xx with stack trace), information disclosure, or a response pattern fundamentally different from normal validation errors, reproduced by S2.",
        rule_out_condition="All mutation strategies produce normal validation-error responses with no anomalous behavior.",
        stop_condition=_COMMON_STOP + "; target returns uniform 400 for all mutations (strong input validation)",
        evidence_requirements=_COMMON_EVIDENCE + "; the mutation strategy, the input, the anomalous response, and the baseline comparison"),
    "PBB-XPLOIT": OracleSpec(
        invariant="Individual low-severity findings must not be chainable into a high-severity exploit: the combination of individually minor weaknesses must not produce unauthorized access, data disclosure, or privilege escalation.",
        baseline_state="The set of all findings from prior probes in this run.",
        identity_and_tenant="subject S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the exploit chain: ordered composition of findings from different probes into a multi-step attack path.",
        action_sequence="Collect all non-RULED_OUT findings -> generate candidate exploit chains (credential leak -> IAM escalation -> RBAC escape) -> execute each chain step using actual finding artifacts -> verify escalation -> S2 reproduces.",
        expected_outcome="No exploit chain achieves a higher-severity outcome than the individual findings suggest.",
        p0_condition="A chain of individually minor findings produces unauthorized access or privilege escalation that no single finding achieves alone, reproduced end-to-end by S2.",
        rule_out_condition="No candidate exploit chain achieves escalation beyond individual finding severity.",
        stop_condition=_COMMON_STOP + "; fewer than 2 non-RULED_OUT findings from prior probes (nothing to chain)",
        evidence_requirements=_COMMON_EVIDENCE + "; each chain step with its source finding, the chain order, and the escalated outcome"),
    "PBB-EDRBP": OracleSpec(
        invariant="Security controls (WAF, IDS, rate limiters) must detect and block attack payloads regardless of encoding, timing, fragmentation, or delivery channel variation.",
        baseline_state="Fresh synthetic identity with confirmed-detected baseline payloads and the defensive response pattern.",
        identity_and_tenant="subject S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the evasion technique (payload encoding: base64/hex/unicode/HTML entities; fragmentation: chunked transfer/multipart splitting; timing: slow delivery/request spacing; channel: content-type switching/WebSocket/multipart form).",
        action_sequence="S sends known-detected payload -> confirm detection -> S sends same payload with evasion technique (encoded, fragmented, timed, channel-switched) -> compare detection vs pass-through -> S2 reproduces any evasion.",
        expected_outcome="All evasion variants detected identically to the baseline payload.",
        p0_condition="An evasion technique allows a known-detected payload to pass through security controls undetected, reproduced by S2.",
        rule_out_condition="All evasion variants produce the same detection response as the baseline.",
        stop_condition=_COMMON_STOP + "; no detectable security controls (all payloads pass or all blocked by application-level validation rather than WAF/IDS)",
        evidence_requirements=_COMMON_EVIDENCE + "; the baseline detected payload, the evasion technique, the evaded payload, and the differential detection result"),
    "PBB-EVADE": OracleSpec(
        invariant="Adaptive defenses must maintain detection effectiveness regardless of attacker behavioral adaptation: varying IP indicators, user-agents, request timing, and header patterns must not degrade detection rates.",
        baseline_state="Session-level detection baseline established by prior probes; adaptive evasion parameters initialized.",
        identity_and_tenant="subject S (authenticated synthetic, multiple behavioral profiles), independent S2 for reproduction.",
        controlled_variable="the adaptive evasion dimension (IP indicator rotation via X-Forwarded-For, user-agent variation, request timing jitter, header fingerprint randomization, referrer chain manipulation).",
        action_sequence="S establishes detection baseline from prior probes -> S varies one evasion dimension at a time -> measure detection rate change -> combine most effective dimensions -> S2 reproduces the optimized evasion profile.",
        expected_outcome="Detection rates remain constant regardless of behavioral adaptation.",
        p0_condition="Systematic behavioral adaptation reduces detection rate below 50% of baseline, reproducible by S2.",
        rule_out_condition="Detection rates stable within 10% of baseline across all evasion dimensions.",
        stop_condition=_COMMON_STOP + "; no detection baseline established (prior probes found no active detection)",
        evidence_requirements=_COMMON_EVIDENCE + "; the detection baseline, each evasion dimension, the detection rate change, and the optimized evasion profile"),
    "PBB-E2E": OracleSpec(
        invariant="The complete attack surface must not contain a viable end-to-end path from initial access through lateral movement to crown-jewel data compromise.",
        baseline_state="Complete finding set from all prior probes and experiments in this run.",
        identity_and_tenant="subject S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the end-to-end chain path: ordered composition across domains (credential -> infrastructure -> cloud -> application -> data) with blast-radius measurement.",
        action_sequence="Aggregate all findings -> build attack graph (nodes: findings, edges: exploitability dependencies) -> find paths to crown-jewel indicators -> measure blast radius at each stage -> execute shortest viable path -> S2 reproduces.",
        expected_outcome="No viable end-to-end path exists from initial access to crown-jewel compromise.",
        p0_condition="A complete end-to-end attack chain from initial access through escalation to crown-jewel data access, with measured blast radius, reproduced by S2.",
        rule_out_condition="No candidate path produces escalation beyond starting severity; attack graph has no connected path to crown-jewel indicators.",
        stop_condition=_COMMON_STOP + "; fewer than 3 non-RULED_OUT findings from the entire run (insufficient for chain analysis)",
        evidence_requirements=_COMMON_EVIDENCE + "; the complete chain with each step's source finding, blast radius at each stage, and the crown-jewel indicator reached"),
    "PBB-RRECON": OracleSpec(
        invariant="Recursive modular recon must not discover undeclared attack surface beyond the brief's declared scope: subdomains, vhosts, related services, and orphaned endpoints must be enumerated and tested.",
        baseline_state="Fresh unauthenticated session targeting the root domain from the brief.",
        identity_and_tenant="U (unauthenticated), S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the recon technique (DNS brute-force, certificate transparency logs, Wayback Machine URL mining, link harvesting, robots/sitemap parsing, vhost enumeration, port scanning, service fingerprinting).",
        action_sequence="U harvests subdomains via CT logs and DNS brute-force -> parse robots.txt/sitemap.xml -> mine Wayback Machine for historical URLs -> crawl and extract links recursively -> fingerprint discovered services -> feed results back into module pipeline for further enumeration -> S2 verifies each discovered endpoint.",
        expected_outcome="All discovered surface is within the brief's declared scope; no orphaned or undocumented services found.",
        p0_condition="Recon discovers functional endpoints, services, or subdomains outside the brief's declared surface that accept authenticated requests or expose sensitive functionality, confirmed reachable by S2.",
        rule_out_condition="All discovered surface matches the brief's declarations; no undeclared services found.",
        stop_condition=_COMMON_STOP + "; target is a single-page application with no subdomains or related services",
        evidence_requirements=_COMMON_EVIDENCE + "; the recon technique, each discovered endpoint/subdomain, the module that found it, and reachability confirmation"),
    "PBB-PARAM": OracleSpec(
        invariant="URL parameters discovered through historical mining and active spider must reject all injection payloads from template-based scanning: XSS, SQLi, SSRF, open redirect, and SSTI.",
        baseline_state="Parameter set harvested from Wayback Machine URLs, sitemap, and active crawl of the target.",
        identity_and_tenant="S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the injection template (reflected XSS polyglots, SQL injection probes, SSRF canary URLs, open redirect payloads, SSTI expression payloads) applied to each discovered parameter.",
        action_sequence="Mine parameters from historical URLs and active crawl -> deduplicate and classify by context (query, path, header, body) -> apply injection templates per parameter -> diff responses against clean baseline -> flag reflection, error disclosure, or behavioral changes -> S2 reproduces hits.",
        expected_outcome="All injection templates rejected or neutralized across all discovered parameters.",
        p0_condition="An injection payload is reflected unescaped, triggers SQL error disclosure, causes SSRF callback, or redirects to attacker-controlled domain, reproduced by S2.",
        rule_out_condition="All injection templates produce clean rejection responses across all parameters.",
        stop_condition=_COMMON_STOP + "; no parameterized endpoints found in historical or active crawl",
        evidence_requirements=_COMMON_EVIDENCE + "; the parameter source, the injection template, the vulnerable parameter, and the differential response"),
    "PBB-HIDDEN": OracleSpec(
        invariant="Hidden admin panels, debug endpoints, backup files, and undocumented paths must not be accessible or must require proper authorization.",
        baseline_state="Fresh unauthenticated session with a comprehensive wordlist of common admin/debug/backup paths.",
        identity_and_tenant="U (unauthenticated), S (authenticated with standard role), independent S2 for reproduction.",
        controlled_variable="the path set (admin panels: /admin, /wp-admin, /dashboard, /manage, /cpanel; debug: /debug, /trace, /actuator, /phpinfo; backups: *.bak, *.old, *.sql, *.tar.gz; config: .env, .git, .svn, web.config).",
        action_sequence="U sends HEAD/GET to comprehensive path wordlist -> classify responses (200/301/302/403/401 vs 404) -> S tests accessible paths with standard credentials -> check for information disclosure in non-404 responses -> S2 reproduces accessible paths.",
        expected_outcome="All hidden paths return 404 or require proper admin credentials; no information disclosure.",
        p0_condition="An admin panel, debug endpoint, backup file, or config file is accessible without admin credentials or leaks sensitive information, confirmed by S2.",
        rule_out_condition="All probed paths return 404 or require proper authorization.",
        stop_condition=_COMMON_STOP + "; target returns uniform 404 for all non-existent paths (no path enumeration possible)",
        evidence_requirements=_COMMON_EVIDENCE + "; the discovered path, the response code, the access level, and any disclosed information"),
    "PBB-SWARM": OracleSpec(
        invariant="Coordinated multi-probe validation must not find inconsistencies: findings validated independently by narrow-scope validator agents must confirm the same defenses that broad probes observed.",
        baseline_state="Set of all findings from prior probes, each to be independently re-validated by a fresh narrow-scope agent.",
        identity_and_tenant="V1..Vn (fresh validator sessions, one per finding), S (original finding session) for comparison.",
        controlled_variable="the validation approach per finding (fresh identity, different timing, reversed parameter order, alternate encoding, different HTTP client fingerprint).",
        action_sequence="For each SUSPECTED finding: spawn narrow validator agent with minimal context -> validator independently attempts to reproduce the finding using a fresh identity and different approach -> compare validator result with original -> flag inconsistencies where validator cannot reproduce or finds different severity.",
        expected_outcome="All validators confirm the original finding's verdict and severity within tolerance.",
        p0_condition="A finding claimed as RULED_OUT is reproduced by a validator, or a finding claimed as SUSPECTED cannot be reproduced by any validator (indicating environmental dependency or false positive).",
        rule_out_condition="All validators agree with original findings within declared tolerance.",
        stop_condition=_COMMON_STOP + "; fewer than 2 prior findings to validate",
        evidence_requirements=_COMMON_EVIDENCE + "; each validator's independent reproduction attempt, the original finding, and any divergence between original and validator results"),
    "PBB-BAS": OracleSpec(
        invariant="Security controls must detect and block ATT&CK-mapped breach simulation techniques across initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, and exfiltration tactics.",
        baseline_state="Fresh session with a library of safe, non-destructive ATT&CK technique simulations mapped to the target's surface.",
        identity_and_tenant="S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the ATT&CK technique (T1190 exploit public-facing application, T1059 command injection, T1078 valid accounts abuse, T1548 abuse elevation control, T1562 impair defenses, T1552 unsecured credentials, T1083 file/directory discovery, T1071 application layer protocol abuse).",
        action_sequence="Map target surface to applicable ATT&CK techniques -> execute safe simulation per technique (non-destructive indicators only) -> record detection/block/pass status per technique -> build coverage matrix -> S2 reproduces undetected techniques.",
        expected_outcome="All simulated ATT&CK techniques detected or blocked by security controls.",
        p0_condition="An ATT&CK technique simulation passes undetected through security controls and achieves its simulated objective, reproduced by S2.",
        rule_out_condition="All ATT&CK technique simulations detected or blocked.",
        stop_condition=_COMMON_STOP + "; target has no detectable security controls (WAF, IDS) to test against",
        evidence_requirements=_COMMON_EVIDENCE + "; the ATT&CK technique ID, the simulation payload, the detection/block status, and the coverage matrix"),
    "PBB-AGRAPH": OracleSpec(
        invariant="No viable attack graph path should exist from initial access through intermediate steps to crown-jewel assets: each step in the graph must be independently blocked.",
        baseline_state="Graph of all findings, endpoints, and access levels discovered across all prior probes.",
        identity_and_tenant="Analysis phase (no new sessions); graph built from prior probes' S and U sessions.",
        controlled_variable="the graph traversal strategy (shortest path, all paths, choke-point analysis, privilege escalation chains, lateral movement paths).",
        action_sequence="Build attack graph from all prior findings -> nodes are endpoints/resources, edges are findings/access paths -> compute shortest paths from initial access to crown jewels -> identify choke points where a single fix blocks multiple paths -> compute privilege escalation chains -> report all viable paths with blast radius.",
        expected_outcome="No complete attack graph path from initial access to crown-jewel assets exists.",
        p0_condition="A complete attack graph path from initial unauthenticated access through privilege escalation to crown-jewel data/functionality is identified, with each step validated by prior findings.",
        rule_out_condition="No complete paths exist; all graph traversals terminate at blocked nodes.",
        stop_condition=_COMMON_STOP + "; fewer than 3 findings to build a meaningful graph",
        evidence_requirements=_COMMON_EVIDENCE + "; the complete graph, each path with step-by-step findings, choke points, and blast radius per path"),
    "PBB-SUPPLY": OracleSpec(
        invariant="No exposed secrets, leaked credentials, vulnerable dependencies, or supply chain weaknesses should be detectable through the application's public surface or client-side assets.",
        baseline_state="Fresh session analyzing client-side assets, response headers, and error messages for supply chain indicators.",
        identity_and_tenant="U (unauthenticated), S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the supply chain signal (dependency version disclosure in headers/responses, secret patterns in JS bundles, known-vulnerable library fingerprints, package manifest exposure, CI/CD artifact leaks).",
        action_sequence="Scan response headers for server/framework version disclosure -> analyze JS bundles for dependency versions and known CVEs -> search for exposed package manifests (package.json, requirements.txt, Gemfile.lock) -> scan all responses for high-entropy secret patterns (API keys, tokens, private keys) -> S2 reproduces.",
        expected_outcome="No secrets, vulnerable dependencies, or supply chain weaknesses detectable from the public surface.",
        p0_condition="A valid secret (API key, token, private key) is found in client assets or responses, or a dependency with a known critical CVE is identified and confirmed exploitable, reproduced by S2.",
        rule_out_condition="No secrets or exploitable dependency information found in public surface analysis.",
        stop_condition=_COMMON_STOP + "; target serves no JavaScript or client-side assets",
        evidence_requirements=_COMMON_EVIDENCE + "; the signal type, the source asset, the secret or CVE, and the exploitability assessment"),
    "PBB-CFUZZ": OracleSpec(
        invariant="Application inputs must safely handle coverage-guided mutation strategies that maximize code path exploration without crashes, hangs, or information disclosure.",
        baseline_state="Fresh synthetic identity with baseline valid requests establishing normal response patterns per endpoint.",
        identity_and_tenant="S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the fuzzing strategy (grammar-based mutation, coverage-guided generation, structure-aware field mutation, length/depth escalation, cross-field dependency breaking, semantic type confusion).",
        action_sequence="Establish baseline per endpoint -> apply grammar-based mutations to structured inputs -> escalate field lengths and nesting depths -> break cross-field dependencies (valid field A + invalid field B) -> monitor for crashes (5xx), hangs (timeout increase > 5x), memory disclosure (response size anomaly) -> S2 reproduces anomalies.",
        expected_outcome="All fuzzing strategies produce clean error responses with consistent timing and size.",
        p0_condition="A fuzzing strategy causes a crash (5xx with stack trace), a hang (response time > 5x baseline), or memory disclosure (response size anomaly with internal data), reproduced by S2.",
        rule_out_condition="All fuzzing strategies produce normal error responses within timing and size tolerance.",
        stop_condition=_COMMON_STOP + "; target returns uniform 400 for all mutations within the first generation",
        evidence_requirements=_COMMON_EVIDENCE + "; the fuzzing strategy, the input that triggered the anomaly, the baseline comparison, and the anomaly type"),
    "PBB-POCVAL": OracleSpec(
        invariant="Every finding above UNKNOWN must have a validated, independently reproducible proof-of-concept: no finding may be reported without confirmed reproduction by a fresh session.",
        baseline_state="Set of all findings from prior probes with verdict above UNKNOWN.",
        identity_and_tenant="V (fresh validator session per finding), independent of original finding session.",
        controlled_variable="the reproduction fidelity (exact replay, minimal reproduction, alternate-path reproduction).",
        action_sequence="For each finding with verdict >= SUSPECTED: create minimal reproduction steps -> spawn fresh validator session V -> V executes reproduction steps from scratch -> compare V's result with original finding -> downgrade findings V cannot reproduce -> upgrade findings V reproduces with stronger evidence.",
        expected_outcome="All SUSPECTED and above findings successfully reproduced by fresh validator sessions.",
        p0_condition="A previously SUSPECTED finding is promoted to higher confidence after independent reproduction confirms exploitability with stronger evidence.",
        rule_out_condition="All findings at SUSPECTED or above are confirmed reproducible by independent validation.",
        stop_condition=_COMMON_STOP + "; no findings above UNKNOWN to validate",
        evidence_requirements=_COMMON_EVIDENCE + "; the original finding, the reproduction steps, the validator's independent result, and any verdict adjustment"),
    "PBB-MORPH": OracleSpec(
        invariant="Security controls must detect payload variants regardless of encoding, obfuscation, or polymorphic transformation: morphed payloads must not bypass controls that block the original.",
        baseline_state="Set of known-blocked payloads from prior probes (PBB-BPWPN baseline) plus an adaptive morphing engine.",
        identity_and_tenant="S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the morphing technique (case randomization, comment insertion, whitespace manipulation, Unicode homoglyph substitution, charset encoding chains, semantic-preserving rewrites, payload fragmentation across parameters).",
        action_sequence="Take each blocked payload from PBB-BPWPN -> apply N morphing techniques per payload -> send morphed variants -> diff responses against blocked baseline -> iterate: use response feedback to guide next morphing round (coverage-guided) -> S2 reproduces any bypasses.",
        expected_outcome="All morphed variants blocked identically to the original payload.",
        p0_condition="A morphed payload variant bypasses controls that block the original, achieving the same effect through transformation, reproduced by S2.",
        rule_out_condition="All morphing techniques and their combinations produce the same block response.",
        stop_condition=_COMMON_STOP + "; no blocked payloads from PBB-BPWPN to morph (no baseline controls detected)",
        evidence_requirements=_COMMON_EVIDENCE + "; the original blocked payload, the morphing technique, the successful variant, and the differential response"),
    "PBB-PLAY": OracleSpec(
        invariant="Pre-built attack playbooks targeting common vulnerability patterns must not succeed: each playbook step must be independently blocked.",
        baseline_state="Library of pre-built attack playbooks mapped to the target's technology stack and surface.",
        identity_and_tenant="S (authenticated synthetic), U (unauthenticated), independent S2 for reproduction.",
        controlled_variable="the playbook (OWASP WSTG test cases, technology-specific exploit sequences, known CVE reproduction patterns, authentication bypass playbooks, payment bypass playbooks, privilege escalation playbooks).",
        action_sequence="Fingerprint target technology stack -> select applicable playbooks -> execute each playbook's steps sequentially -> record pass/block at each step -> if any playbook reaches its final step, S2 reproduces the full sequence -> build playbook coverage matrix.",
        expected_outcome="All playbook sequences blocked at or before the exploitation step.",
        p0_condition="A complete attack playbook succeeds from initial step through exploitation, reaching its defined objective, reproduced by S2.",
        rule_out_condition="All playbooks blocked; no playbook reaches its exploitation step.",
        stop_condition=_COMMON_STOP + "; target technology stack not recognized by any available playbook",
        evidence_requirements=_COMMON_EVIDENCE + "; the playbook name, each step's result, the technology match, and the exploitation outcome"),
    "PBB-SCHEMA": OracleSpec(
        invariant="API endpoints must reject all schema-violating requests: type mismatches, missing required fields, extra unknown fields, boundary violations, and constraint breaks must produce consistent error responses.",
        baseline_state="API schema extracted from OpenAPI/Swagger, GraphQL introspection, or response-shape inference.",
        identity_and_tenant="S (authenticated synthetic), independent S2 for reproduction.",
        controlled_variable="the schema violation type (wrong type, missing required, extra field, boundary value, constraint violation, null where non-nullable, array where object expected, nested depth exceeding limit).",
        action_sequence="Extract or infer API schema -> generate violation request per field per violation type -> send violations -> compare response to valid-request baseline -> flag endpoints that process schema-violating requests instead of rejecting them -> S2 reproduces processing of invalid requests.",
        expected_outcome="All schema violations rejected with appropriate error responses; no processing of invalid input.",
        p0_condition="A schema-violating request is processed as valid (state change, data returned, side effect triggered) instead of rejected, reproduced by S2.",
        rule_out_condition="All schema violations produce consistent rejection responses.",
        stop_condition=_COMMON_STOP + "; no API schema discoverable and no endpoints accept structured input",
        evidence_requirements=_COMMON_EVIDENCE + "; the schema source, the violation type, the field, the request, and the processing evidence"),
    "PBB-BROWSE": OracleSpec(
        invariant="Browser-automated interaction must not reveal client-side vulnerabilities invisible to API-only testing: DOM-based XSS, client-side logic flaws, JavaScript-driven state manipulation, and SPA routing bypasses.",
        baseline_state="Headless browser session navigating the target application's UI flows.",
        identity_and_tenant="B (browser session with authenticated synthetic identity), U (unauthenticated browser session), independent B2 for reproduction.",
        controlled_variable="the browser-specific test (DOM-based XSS via URL fragments, postMessage handler exploitation, client-side storage manipulation, SPA route forcing, JavaScript prototype pollution, WebSocket message injection, service worker interception).",
        action_sequence="B navigates full UI flow -> inject XSS payloads via URL fragments and postMessage -> manipulate localStorage/sessionStorage -> force direct SPA routes -> test JavaScript prototype pollution vectors -> intercept WebSocket messages -> B2 reproduces findings.",
        expected_outcome="No client-side vulnerabilities found; all browser-specific vectors produce safe behavior.",
        p0_condition="A DOM-based XSS executes, or client-side logic manipulation achieves unauthorized state change, or SPA route forcing bypasses client-side access controls, reproduced by B2.",
        rule_out_condition="All browser-specific tests produce safe, expected behavior.",
        stop_condition=_COMMON_STOP + "; target is a pure API with no browser-facing UI",
        evidence_requirements=_COMMON_EVIDENCE + "; the browser test, the injection point, the DOM state, and screenshot/HAR evidence"),
    "PBB-MORCH": OracleSpec(
        invariant="Multi-agent coordinated attack sequences must not bypass defenses that block individual probes: no combination of simultaneous or sequenced multi-agent actions may achieve what single-agent probes could not.",
        baseline_state="Multiple independent agent sessions targeting different aspects of the same application simultaneously.",
        identity_and_tenant="A1..An (independent agent sessions with different synthetic identities), coordinator C (orchestration session).",
        controlled_variable="the coordination strategy (simultaneous multi-endpoint probing, sequenced handoff between agents, shared state exploitation, timing-coordinated actions, role-differentiated agents targeting different layers).",
        action_sequence="C assigns specialized tasks to A1..An (recon agent, exploit agent, validation agent, exfiltration agent) -> agents execute in coordinated phases -> share findings through coordinator -> attempt coordinated exploits that combine each agent's access -> test for defenses that fail under concurrent load.",
        expected_outcome="Coordinated multi-agent sequences blocked as effectively as individual agent probes.",
        p0_condition="A coordinated multi-agent attack succeeds where individual probes failed, exploiting timing windows, shared state, or defense saturation, reproduced with fresh agents.",
        rule_out_condition="All coordination strategies blocked; no multi-agent combination achieves more than individual probes.",
        stop_condition=_COMMON_STOP + "; target has a single endpoint with no multi-surface attack possibility",
        evidence_requirements=_COMMON_EVIDENCE + "; each agent's role, the coordination strategy, the combined exploit path, and evidence that individual probes were blocked"),
    "PBB-DTEST": OracleSpec(
        invariant="Parallel distributed testing must not reveal timing-dependent or load-sensitive vulnerabilities: race conditions, resource exhaustion, and defense degradation under parallel load must not be exploitable.",
        baseline_state="Multiple parallel sessions targeting the same endpoints simultaneously from distributed vantage points.",
        identity_and_tenant="D1..Dn (distributed parallel sessions with independent synthetic identities).",
        controlled_variable="the distributed strategy (parallel identical requests for race conditions, progressive load escalation, distributed credential stuffing patterns, geographically-varied timing, staggered session establishment).",
        action_sequence="D1..Dn establish parallel sessions -> send identical requests simultaneously to race-condition-sensitive endpoints -> progressively increase parallel load -> monitor for state inconsistencies between sessions -> check for defense degradation under load -> test for resource exhaustion indicators.",
        expected_outcome="All parallel sessions see consistent state; defenses maintain effectiveness under distributed load.",
        p0_condition="Parallel testing reveals a race condition (inconsistent state), defense degradation under load (payloads pass that are blocked under normal load), or resource exhaustion (service degradation), reproduced.",
        rule_out_condition="All distributed tests show consistent state and defense effectiveness.",
        stop_condition=_COMMON_STOP + "; target rate-limits all distributed sessions to single-session throughput",
        evidence_requirements=_COMMON_EVIDENCE + "; the distributed strategy, the number of parallel sessions, the timing, and the state inconsistency or defense degradation evidence"),
    "PBB-WHOOK": OracleSpec(
        invariant="Webhook endpoints must reject forged, unsigned, and empty-secret-signed events: no crafted event payload may grant entitlement without a valid provider signature.",
        baseline_state="Webhook endpoint reachable, signing secret configured, legitimate events are processed.",
        identity_and_tenant="W1 (webhook forger with no signing secret or empty secret), W2 (webhook forger with crafted HMAC).",
        controlled_variable="the webhook signature (absent, empty-key HMAC, default-key HMAC, algorithm-downgraded, timestamp-replayed, event-type-confused).",
        action_sequence="W1 sends checkout.session.completed with no signature header -> W1 sends with HMAC(empty key) -> W2 sends with known default keys -> test event confusion (invoice.paid vs checkout.session.completed) -> test idempotency bypass (duplicate event IDs) -> verify entitlement state after each.",
        expected_outcome="All forged events rejected; entitlement unchanged.",
        p0_condition="A forged webhook event (unsigned or signed with empty/default key) is processed and grants entitlement, reproduced with a fresh identity.",
        rule_out_condition="All signature variations rejected with 400/401/403.",
        stop_condition=_COMMON_STOP + "; no webhook endpoint discovered in the target's surface",
        evidence_requirements=_COMMON_EVIDENCE + "; the forged event payload, the signature method used, the HTTP response, and the entitlement state before/after"),
    "PBB-BFLOW": OracleSpec(
        invariant="Browser-driven payment flows must not grant entitlement on deferred or failed payments: navigating the checkout return URL after a declined or incomplete payment must not unlock paid features.",
        baseline_state="Checkout flow reachable via browser, return URL known, feature-use oracle operational.",
        identity_and_tenant="B1 (browser-driven identity that starts but does not complete payment).",
        controlled_variable="the payment completion state (deferred method selected, payment_status=unpaid on return, return URL navigated before payment confirmation, success URL accessed directly without checkout).",
        action_sequence="B1 initiates Stripe Checkout -> selects SEPA/Boleto/OXXO (deferred) -> returns to success_url with payment_status=unpaid -> attempts to use paid feature -> B1 navigates directly to success_url without checkout -> attempts feature -> B1 manipulates client-side payment state -> attempts feature.",
        expected_outcome="Paid feature denied in all deferred/incomplete payment scenarios.",
        p0_condition="Paid feature usable after deferred payment method selection without actual payment completion, reproduced with fresh browser session.",
        rule_out_condition="All deferred/incomplete payment paths correctly deny feature access.",
        stop_condition=_COMMON_STOP + "; target uses no browser-based checkout flow",
        evidence_requirements=_COMMON_EVIDENCE + "; browser HAR/screenshot, the payment method selected, the return URL parameters, and the feature-use attempt result"),
    "PBB-GQL": OracleSpec(
        invariant="GraphQL endpoints must enforce per-operation rate limits: alias-batched queries must not bypass rate limiting.",
        baseline_state="GraphQL endpoint reachable, rate limits enforce N operations per time window.",
        identity_and_tenant="G1 (single identity sending aliased batch queries).",
        controlled_variable="the number of aliased operations per request (1, 10, 50, 100+).",
        action_sequence="G1 sends single query -> G1 sends 10 aliased queries in 1 request -> G1 sends 100 aliased login mutations in 1 request -> compare rate limit response.",
        expected_outcome="Rate limit enforced per operation count, not per HTTP request.",
        p0_condition="100+ operations execute in a single request bypassing per-request rate limits, enabling brute-force.",
        rule_out_condition="Per-operation limits enforced; batch returns 429 when cumulative operations exceed threshold.",
        stop_condition=_COMMON_STOP + "; target has no GraphQL endpoint",
        evidence_requirements=_COMMON_EVIDENCE + "; the aliased query, the number of operations, the rate limit response"),
    "PBB-JWTF": OracleSpec(
        invariant="JWT validation must reject algorithm:none and algorithm confusion attacks.",
        baseline_state="JWT-authenticated endpoints operational, RS256 key pair in use.",
        identity_and_tenant="J1 (identity with valid JWT), J2 (forged JWT with alg:none or HS256 confusion).",
        controlled_variable="the JWT algorithm header (none, HS256 with public key as secret, empty signature).",
        action_sequence="J1 authenticates normally -> J2 sends JWT with alg:none and no signature -> J2 sends JWT with alg:HS256 signed with the RS256 public key -> J2 sends JWT with kid pointing to injected key -> verify access.",
        expected_outcome="All algorithm-confused JWTs rejected.",
        p0_condition="Forged JWT accepted and grants access to protected resources.",
        rule_out_condition="All algorithm confusion attempts rejected.",
        stop_condition=_COMMON_STOP + "; target does not use JWTs",
        evidence_requirements=_COMMON_EVIDENCE + "; the forged JWT, the algorithm used, the response status/body"),
    "PBB-SMUG": OracleSpec(
        invariant="HTTP frontend/backend must agree on request boundaries.",
        baseline_state="Application served through reverse proxy/CDN, both frontend and backend reachable.",
        identity_and_tenant="S1 (identity sending ambiguous requests).",
        controlled_variable="the Content-Length/Transfer-Encoding combination (CL.TE, TE.CL, TE.TE with obfuscation, 0.CL).",
        action_sequence="S1 sends CL.TE ambiguous request -> S1 sends TE.CL ambiguous request -> S1 sends TE.TE with obfuscated chunked header -> observe if second request is smuggled.",
        expected_outcome="All ambiguous requests normalized or rejected; no request smuggling.",
        p0_condition="A smuggled request reaches a different backend handler than intended, demonstrated by differential response.",
        rule_out_condition="All ambiguous requests produce consistent responses.",
        stop_condition=_COMMON_STOP + "; target serves directly without a reverse proxy",
        evidence_requirements=_COMMON_EVIDENCE + "; the ambiguous request, both CL and TE values, the smuggled response"),
    "PBB-PPOLL": OracleSpec(
        invariant="Server must reject __proto__ and constructor.prototype in JSON input.",
        baseline_state="JSON-accepting endpoints operational.",
        identity_and_tenant="P1 (identity sending polluted JSON payloads).",
        controlled_variable="the pollution key (__proto__, constructor.prototype, __proto__.isAdmin, constructor.prototype.role).",
        action_sequence="P1 sends JSON with __proto__.isAdmin=true -> P1 sends constructor.prototype.role=admin -> P1 sends nested pollution in array elements -> verify server state.",
        expected_outcome="All pollution keys stripped or rejected.",
        p0_condition="Prototype pollution accepted and affects server behavior (e.g., grants admin access).",
        rule_out_condition="All pollution payloads rejected or sanitized.",
        stop_condition=_COMMON_STOP + "; target is not a Node.js/JavaScript application",
        evidence_requirements=_COMMON_EVIDENCE + "; the polluted payload, the server response, the behavioral change"),
    "PBB-CACHE": OracleSpec(
        invariant="Cache keys must include all security-relevant headers.",
        baseline_state="CDN/cache layer operational, cache headers visible in responses.",
        identity_and_tenant="C1 (attacker identity poisoning cache), C2 (victim identity receiving poisoned content).",
        controlled_variable="the unkeyed header (X-Forwarded-Host, X-Original-URL, Accept-Language with injection).",
        action_sequence="C1 sends request with X-Forwarded-Host:evil.com -> observe if response cached -> C2 requests same URL normally -> check if C2 receives poisoned response.",
        expected_outcome="Security-relevant headers included in cache key; poisoning impossible.",
        p0_condition="Poisoned cache response served to victim identity.",
        rule_out_condition="All unkeyed header variations produce separate cache entries or are stripped.",
        stop_condition=_COMMON_STOP + "; target has no CDN/cache layer",
        evidence_requirements=_COMMON_EVIDENCE + "; the poisoning request, the cache-status headers, the victim's response"),
    "PBB-WAFB": OracleSpec(
        invariant="Security controls must inspect full request body regardless of size.",
        baseline_state="WAF operational, known payloads blocked at normal sizes.",
        identity_and_tenant="W1 (identity sending size-varied payloads).",
        controlled_variable="the request body size (normal, at WAF limit, 1 byte over limit, 2x limit) with identical payload.",
        action_sequence="W1 sends known-blocked payload at normal size -> verify blocked -> W1 pads payload to WAF inspection limit (8KB/128KB) -> W1 sends same payload beyond limit -> observe if bypass occurs.",
        expected_outcome="Payload blocked regardless of body size.",
        p0_condition="Payload that is blocked at normal size passes inspection when padded beyond WAF body limit.",
        rule_out_condition="All payload sizes inspected and blocked consistently.",
        stop_condition=_COMMON_STOP + "; no WAF detected in target infrastructure",
        evidence_requirements=_COMMON_EVIDENCE + "; the payload, both sizes, the WAF response at each size"),
    "PBB-RACE": OracleSpec(
        invariant="Concurrent requests to payment/subscription endpoints must not cause double-grant via TOCTOU.",
        baseline_state="Subscription endpoint grants entitlement exactly once per confirmed payment.",
        identity_and_tenant="R1 (identity submitting concurrent requests with same payment context).",
        controlled_variable="the number of concurrent identical requests (1 vs 5 simultaneous).",
        action_sequence="R1 sends 5 concurrent POST requests to subscription/checkout endpoint with same payment context -> count how many grant entitlement -> verify if more than one entitlement was created.",
        expected_outcome="Exactly one entitlement grant regardless of concurrent request count.",
        p0_condition="Two or more concurrent requests each independently grant entitlement from a single payment.",
        rule_out_condition="All concurrent requests correctly serialize; at most one grants entitlement.",
        stop_condition=_COMMON_STOP + "; no payment/subscription endpoints discovered",
        evidence_requirements=_COMMON_EVIDENCE + "; the concurrent request count, number of success responses, number of entitlement grants"),
    "PBB-SAML": OracleSpec(
        invariant="SAML/SSO endpoints must reject unsigned, assertion-wrapped, replayed, and subject-manipulated responses.",
        baseline_state="SAML ACS endpoint validates XML signatures, assertion integrity, and replay protection.",
        identity_and_tenant="S1 (identity submitting forged SAML responses).",
        controlled_variable="the SAML response integrity (valid signature vs unsigned vs replayed vs forged NameID).",
        action_sequence="S1 submits unsigned SAML response with forged admin NameID -> observe acceptance -> S1 replays same assertion -> observe if accepted again.",
        expected_outcome="All forged/unsigned/replayed SAML responses rejected.",
        p0_condition="Unsigned SAML assertion with forged NameID is accepted and creates an authenticated session.",
        rule_out_condition="All SAML manipulation variants rejected with appropriate error responses.",
        stop_condition=_COMMON_STOP + "; no SAML/SSO endpoints discovered",
        evidence_requirements=_COMMON_EVIDENCE + "; the forged SAML response, the endpoint, the HTTP status and response body"),
    "PBB-APIVER": OracleSpec(
        invariant="Deprecated API versions must enforce the same auth and rate-limit controls as the current version.",
        baseline_state="Current API version (e.g. v2/v3) enforces authentication and rate limits.",
        identity_and_tenant="A1 (unauthenticated identity testing version-downgraded paths).",
        controlled_variable="the API version prefix (current vs deprecated) on the same logical endpoint.",
        action_sequence="A1 requests current-version endpoint -> verify auth required (401/403) -> A1 requests same endpoint with version decremented to v1 -> observe if auth bypassed.",
        expected_outcome="Deprecated API versions enforce identical auth controls as current version.",
        p0_condition="Deprecated API version serves protected resource without authentication while current version requires it.",
        rule_out_condition="All API versions enforce consistent authentication and authorization.",
        stop_condition=_COMMON_STOP + "; no versioned API paths discovered",
        evidence_requirements=_COMMON_EVIDENCE + "; the current and deprecated paths, HTTP status codes for each, response body differences"),
}

EXPERIMENT_CLASSES: dict[str, str] = {
    "PBB-U": "unconfirmed_payment_grants_access", "PBB-F": "plan_or_price_binding", "PBB-H": "currency_binding", "PBB-C": "duplicate_value_via_return_flow_repetition",
    "PBB-G": "cross_tenant_binding", "PBB-X": "cross_identity_binding", "PBB-R": "retention_after_refund", "PBB-E": "ui_vs_server_divergence", "PBB-OPEN": "paid_feature_open_to_unpaid", "PBB-LEAK": "entitlement_leak_to_unrelated_identity",
    "PBB-D": "cross_subject_object_access",
    "PBB-SIG": "signature_bypass", "PBB-AUTH": "auth_bypass", "PBB-RATE": "ratelimit_bypass", "PBB-IDOR": "id_guessing",
    "PBB-TWIN": "digital_twin_profiling", "PBB-CRED": "credential_harvesting", "PBB-ADPATH": "ad_attack_path", "PBB-C2": "c2_channel_viability",
    "PBB-IAM": "cloud_iam_escalation", "PBB-RBAC": "rbac_escape", "PBB-BPWPN": "bypass_weaponization", "PBB-REVENG": "reverse_engineering",
    "PBB-ZDAY": "zero_day_discovery", "PBB-XPLOIT": "exploit_synthesis", "PBB-EDRBP": "edr_av_bypass", "PBB-EVADE": "dynamic_evasion", "PBB-E2E": "e2e_attack_chain",
    "PBB-RRECON": "recursive_recon_pipeline", "PBB-PARAM": "parameter_discovery_scanning", "PBB-HIDDEN": "hidden_path_discovery",
    "PBB-SWARM": "swarm_agent_coordination", "PBB-BAS": "breach_attack_simulation", "PBB-AGRAPH": "attack_graph_analysis",
    "PBB-SUPPLY": "supply_chain_scanning", "PBB-CFUZZ": "coverage_guided_fuzzing", "PBB-POCVAL": "poc_validation_reproduction",
    "PBB-MORPH": "payload_morphing", "PBB-PLAY": "attack_playbook_execution", "PBB-SCHEMA": "schema_api_testing",
    "PBB-BROWSE": "browser_automation_probing", "PBB-MORCH": "multi_agent_orchestration", "PBB-DTEST": "distributed_parallel_testing",
    "PBB-WHOOK": "webhook_signature_forgery", "PBB-BFLOW": "browser_payment_flow_bypass",
    "PBB-GQL": "graphql_alias_batching", "PBB-JWTF": "jwt_algorithm_confusion",
    "PBB-SMUG": "http_request_smuggling", "PBB-PPOLL": "prototype_pollution",
    "PBB-CACHE": "cache_key_poisoning", "PBB-WAFB": "waf_body_limit_bypass",
    "PBB-RACE": "payment_race_condition", "PBB-SAML": "saml_sso_bypass", "PBB-APIVER": "api_version_downgrade",
}

# ZR-006: the identity/tenant SCOPE each experiment probes. The smallest
# reasonable, documented categorization (parallel to EXPERIMENT_CLASSES); used
# only for coverage reporting (coverage.py), never for any verdict.
SCOPE_BY_HYPOTHESIS: dict[str, str] = {
    "PBB-U": "single_identity", "PBB-F": "single_identity", "PBB-H": "single_identity", "PBB-C": "single_identity", "PBB-R": "single_identity",
    "PBB-G": "cross_tenant", "PBB-X": "cross_identity", "PBB-LEAK": "unrelated_identity", "PBB-E": "view_consistency", "PBB-OPEN": "open_access",
    "PBB-D": "cross_subject",
    "PBB-SIG": "signature_bypass", "PBB-AUTH": "auth_bypass", "PBB-RATE": "ratelimit_bypass", "PBB-IDOR": "id_guessing",
    "PBB-TWIN": "environment_profiling", "PBB-CRED": "credential_exposure", "PBB-ADPATH": "infrastructure_attack", "PBB-C2": "channel_establishment",
    "PBB-IAM": "cloud_escalation", "PBB-RBAC": "role_escape", "PBB-BPWPN": "defensive_bypass", "PBB-REVENG": "client_analysis",
    "PBB-ZDAY": "input_fuzzing", "PBB-XPLOIT": "chain_synthesis", "PBB-EDRBP": "detection_evasion", "PBB-EVADE": "adaptive_evasion", "PBB-E2E": "full_kill_chain",
    "PBB-RRECON": "full_regression", "PBB-PARAM": "full_regression", "PBB-HIDDEN": "full_regression",
    "PBB-SWARM": "full_regression", "PBB-BAS": "full_regression", "PBB-AGRAPH": "full_regression",
    "PBB-SUPPLY": "full_regression", "PBB-CFUZZ": "full_regression", "PBB-POCVAL": "full_regression",
    "PBB-MORPH": "full_regression", "PBB-PLAY": "full_regression", "PBB-SCHEMA": "full_regression",
    "PBB-BROWSE": "full_regression", "PBB-MORCH": "full_regression", "PBB-DTEST": "full_regression",
    "PBB-WHOOK": "webhook_forgery", "PBB-BFLOW": "browser_payment_flow",
    "PBB-GQL": "graphql_abuse", "PBB-JWTF": "auth_bypass",
    "PBB-SMUG": "infrastructure_attack", "PBB-PPOLL": "input_fuzzing",
    "PBB-CACHE": "infrastructure_attack", "PBB-WAFB": "defensive_bypass",
    "PBB-RACE": "payment_race", "PBB-SAML": "auth_bypass", "PBB-APIVER": "api_version_bypass",
}


@dataclass
class Finding:
    hypothesis_id: str
    p0_class: str
    title: str
    verdict: Verdict
    confidence: str
    summary: str
    spec: OracleSpec
    artifact_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    divergences: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    token: Any = field(default=None, repr=False, compare=False)  # a ConfirmationToken issued by the confirmation gate (Control Adapter); answers covers()

    # ZR-019 (full schema, section 15.2) -- fields added beyond the original set.
    # Populated uniformly for every finding (see engine.py's _finding()):
    timestamp: str | None = None
    priority: str | None = None  # derived from verdict -- see engine.py's _PRIORITY_BY_VERDICT
    reproduction_status: str | None = None  # derived from verdict+token -- see engine.py's _finding()
    impact: str | None = None  # populated for CONFIRMED_P0 only, where it's a true structural statement of what the verdict means
    recommended_fix: str | None = None  # per-hypothesis-class remediation guidance, see engine.py's RECOMMENDED_FIX
    # Populated per-experiment where the local context exists (PBB-U demonstrates the pattern; not yet threaded through every experiment -- see engine.py):
    identity_tenant_dimension: str | None = None
    commercial_context: str | None = None
    expected_state: str | None = None
    actual_state: str | None = None
    payment_state: str | None = None
    entitlement_state: str | None = None
    server_side_oracle: str | None = None
    affected_flow: str | None = None  # flow FAMILY (fsm_compiler.FLOW_TYPES) the hypothesis exercises -- see engine.py's FLOW_BY_HYPOTHESIS; not yet a reference to a specific compiled FSM segment
    target_label: str | None = None  # "cold_domain" or "digital_twin" -- which target this finding was produced against
    # Structurally present, deliberately None until the capability they depend on exists:
    reproduction_steps: str | None = None  # needs B20 (replay bundles)
    regression_test_reference: str | None = None  # ZR-023: set by regression.attach_regression_references in engine.run() (was benchmark-only)
    precondition: dict[str, Any] | None = None  # needs B32 (Phase 4)
    effect: dict[str, Any] | None = None  # needs B32 (Phase 4)

    def __post_init__(self) -> None:
        if self.verdict == Verdict.CONFIRMED_P0 and (self.token is None or not self.token.covers(self.hypothesis_id)):
            raise ConfirmationRefused("confirmed_p0_without_oracle_token", f"{self.hypothesis_id}: CONFIRMED_P0 requires a ConfirmationToken issued by ConfirmationGate (external Protected-Feature Oracle chain)")
        if self.confidence not in ("high", "medium", "low"):
            raise ValueError("confidence must be high|medium|low")
        if self.timestamp is None:
            self.timestamp = now_iso()

    def schema_completeness(self) -> float:
        """ZR-019's acceptance criterion / Section 19's hard gate: fraction of
        the full ZR-019 schema (section 15.2) that's actually populated, not
        merely present as a field. Mirrors OracleSpec.completeness() --
        counts non-empty strings and non-empty/non-None values generally,
        excluding fields that are structural bookkeeping rather than part of
        the schema itself (hypothesis_id/spec/token/artifact_ids -- the
        latter two are specifically covered by the 'server-side oracle' and
        'evidence references' schema items via server_side_oracle and
        artifact_ids respectively, so double-counting them here would be
        misleading, not more accurate)."""
        schema_fields = (
            "title", "priority", "verdict", "affected_flow", "identity_tenant_dimension", "commercial_context",
            "expected_state", "actual_state", "payment_state", "entitlement_state", "server_side_oracle",
            "artifact_ids", "reproduction_steps", "impact", "confidence", "limitations", "summary",
            "recommended_fix", "regression_test_reference", "reproduction_status", "timestamp",
            "precondition", "effect",
        )
        populated = 0
        for name in schema_fields:
            v = getattr(self, name)
            if v is None:
                continue
            if isinstance(v, str) and not v.strip():
                continue
            if isinstance(v, (list, dict)) and not v:
                continue
            populated += 1
        return populated / len(schema_fields)

    @property
    def truth_label(self) -> TruthLabel:
        return {Verdict.CONFIRMED_P0: TruthLabel.EXTERNALLY_REPRODUCED, Verdict.UNKNOWN: TruthLabel.UNKNOWN, Verdict.BLOCKED: TruthLabel.BLOCKED}.get(self.verdict, TruthLabel.EXTERNALLY_OBSERVED)

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "p0_class": self.p0_class, "title": self.title, "verdict": self.verdict.value, "confidence": self.confidence,
                "truth_label": self.truth_label.value, "summary": self.summary, "artifact_ids": list(self.artifact_ids), "reasons": list(self.reasons),
                "divergences": list(self.divergences), "limitations": list(self.limitations), "metrics": dict(self.metrics),
                "oracle_spec": dict(self.spec.__dict__), "confirmed_via_oracle_gate": self.token is not None,
                "internal_cause": "UNKNOWN (not externally observable; deliberately not inferred)"}


@dataclass
class EngineResult:
    findings: list[Finding]
    controls: dict[str, Any]
    ledger_summary: dict[str, Any]
    stats: dict[str, Any]
    brief_fingerprint: str
    engine_version: str = ENGINE_VERSION
    started_at: str = ""
    finished_at: str = ""
    replay_bundles: dict[str, Any] = field(default_factory=dict)  # ZR-015/B20: per-finding replay bundles (hypothesis_id -> ReplayBundle.to_dict())

    def by_id(self) -> dict[str, Finding]:
        return {f.hypothesis_id: f for f in self.findings}

    def verdicts(self) -> dict[str, str]:
        return {f.hypothesis_id: f.verdict.value for f in self.findings}

    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict == Verdict.CONFIRMED_P0]

    def to_dict(self) -> dict[str, Any]:
        return {"engine_version": self.engine_version, "brief_fingerprint": self.brief_fingerprint, "started_at": self.started_at, "finished_at": self.finished_at,
                "controls": self.controls, "stats": self.stats, "evidence": self.ledger_summary, "replay_bundles": self.replay_bundles,
                "findings": [f.to_dict() for f in self.findings]}
