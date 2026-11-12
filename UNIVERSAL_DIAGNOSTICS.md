# Universal diagnostics — implementation status

Feature branch, **not production-ready**. No Home Assistant files have been changed.

## Implemented
- Allowlisted adapter registry (HTTP/REST, MQTT, Zigbee and HA-state sources).
- Explicit resource access; no user-supplied URL or credential access.
- Bounded HA state snapshots, adapter-to-entity comparison, two-snapshot diff.
- Initial unit tests for allowlists, output filtering, snapshots and diff.

## Integration work still required
1. Add Home Assistant LLM Tool wrappers to the *current installed* llm.py, not
   blindly overwrite it with the older GitHub version.
2. Register an authenticated Bosch adapter using Bosch HomeCom's existing client.
   Confirm the real resource mapping for flame indication and HC1 pump status;
   never guess URLs or fetch arbitrary LAN hosts.
3. Add MQTT/ZHA/Zigbee2MQTT adapters using supported HA integration interfaces
   (not direct broker credentials or arbitrary topic subscriptions).
4. Provide bounded sampling for monitoring (explicit duration, interval, stop,
   maximum samples) with safe lifecycle handling.
5. Test under the installed HA version and integration versions, then obtain
   approval for deployment/restart. Compare GitHub and installed llm.py hashes.

## Important
A changed entity state is not proof of flame or pump operation. Never present
a heuristic as a direct hardware signal. The API must return 'unsupported'
when a reliable authenticated adapter cannot be registered.
