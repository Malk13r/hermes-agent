# Temporary local lifecycle carry (HX-65)

Local compatibility carry from published PR #84874 head
`1c6c9d46980db38a95ffab6353f31eeaad86c0dd`, previously adapted in
`a0ad159db1a08c9767ace83506e3c36493471aea` for v2026.9.11. This adaptation
is refreshed onto upstream `351e644b8373da53197d3c3008cf3a0410cb618e`
(Agent 0.21.5), retaining the upstream multiplex restart machinery.
It is not the future community lifecycle redesign.

The existing key stays unchanged. Example (synthetic IDs):

```yaml
slack:
  gateway_restart_channel:
    platform: slack
    chat_id: C-OPERATIONS
    name: Operations
    # Optional: thread_id, user_id, scope_id
```

For this key, root `slack:` wins over `platforms.slack`, which wins over
`gateway.platforms.slack`. Explicit null clears a lower-precedence override.
Malformed values warn without exposing target/provenance values and fall back
to the platform's existing home-channel path. The target must name the same
platform and use nonblank string/integer IDs (not booleans or containers).
Optional IDs are preserved explicitly, never inherited from home. The field is
appended to `PlatformConfig` to preserve existing positional construction and
bridged as a typed field, not an adapter `extra`. Unlike the earlier release,
this upstream base has `PlatformConfig._TYPED_KEYS`; the override is registered
there, and the shared bridge remains in `gateway/config_loader.py`.

Only planned-startup and platform-level shutdown broadcasts are redirected.
Active-session notices stay with their conversation. In-chat `/restart`
requester delivery, quiet-drain suppression, DB warnings, cron and ordinary
home routing keep their upstream behaviour. `gateway_restart_notification: false`
still suppresses lifecycle notices even with an override. No home is required
for an explicit override, and configuring a target does not enable an adapter.

For explicit overrides only, enabled native platforms require a connected
native adapter; they must not silently switch to Relay after native failure.
An intentionally disabled logical platform can use an existing connected Relay
transport that explicitly fronts it. The configured target's thread and explicit
`user_id`/`scope_id` are sent on that transport; home provenance is not borrowed.
This adds no Relay protocol, enrollment, capture command or inheritance feature.

## Preserved newer retry, deduplication and profile behaviour

The newer upstream restart replay machinery is retained, not replaced with the
older carry's startup flow. Planned-restart owed targets use the same validated
override-or-home destination as delivery, even when its adapter is unavailable.
A failed or unavailable send remains pending; an override without a home is not
forgotten, and a superseded home does not keep the marker alive. Only successful
sends are recorded in the marker's `delivered_targets`. Partial delivery survives
runner replacement and skips already delivered targets on retry; the marker is
removed when all currently owed targets are delivered. Opt-outs and removed
targets retain upstream completion semantics.

Deduplication and explicit skip targets remain keyed by logical platform, chat
and thread. Shutdown overrides deduplicate against active-session notices at the
same exact target without redirecting those active notices. Adapter iteration
remains snapshotted so fatal sends can remove a live adapter safely. Shutdown
override sends use upstream `present_notification` warning policy; startup online
notices retain their separate policy. Profile-scoped configuration and warning
suppression remain isolated under the upstream multiplex runtime scope.

## Deliberately retained upstream ambiguity

Without a valid override, startup home broadcasts can use Relay even when an
enabled native adapter is absent, whereas shutdown home broadcasts iterate
native adapters only. That asymmetry is pre-existing in this upstream base and
is retained rather than expanding the scope of this local carry. Invalid/null
configuration takes the same home fallback; it does not opt into the explicit
transport policy. Resolving that asymmetry belongs to a separately approved
change. Generic home-target validation and existing shutdown-home metadata are
also intentionally untouched.

## Validation and deployment boundary

Validation uses synthetic configuration, real loader/runner methods and fake
outbound adapters in the isolated candidate venv (managed Python 3.11.15), via
`scripts/run_tests.sh -j 4 --file-timeout 180`. The enclosing macOS sandbox denies
network access and access to live `.hermes` state; a probe verified both denials.

The focused suite includes configuration precedence, native/Relay delivery,
per-profile replay accounting, unavailable secondary bots, and shared-chat/thread
deduplication. Adjacent suites exercise configuration, shutdown, restart replay,
drain, and ordinary delivery. Stock-red runs use a separate disposable source
tree, never in-place production-file replacement in the candidate.

Private HX-65 carry receipts contain exact commands, source hashes, outcomes,
and platform skips. No live switch is part of this change. Parent review and
separate live-switch approval remain required.
