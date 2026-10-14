# Scaling pressured to large clusters

Status: proposed, 2026-10-14. Long-term goal; not scheduled yet.

pressured should run on clusters with thousands of nodes and tens of thousands of pods with API-server load,
memory and poll latency that do not grow with cluster size the way they do today.

## Where it breaks today

Every poll cycle in cluster (kubelet) mode, `kubelet_collect` in `src/kubelet.c`:

- lists all nodes (`kubelet_refresh_nodes`) and **all pods twice** (`kubelet_refresh_pod_limits` and
  `collect_oom_from_pod_status`), parsing each response whole;
- fetches each node's `/stats/summary` through the API server proxy, **one node at a time**
  (`collect_from_node`);
- lists OOMKilling events (`collect_oom_events`).

Consequences as the cluster grows:

- **API load** is proportional to cluster size on every cycle, not to the rate of change.
- **Memory**: the pod list is held and parsed whole, so peak heap grows linearly with pod count and can reach
  pressured's own container memory limit.
- **Cycle time**: sequential per-node requests make a cycle longer than the poll interval on large node counts.
- **Silent caps**: `MAX_TRACKED_CONTAINERS` (`src/event_generator.c`), `MAX_PODS` and `MAX_NODES`
  (`src/kubelet.c`) drop containers or nodes past fixed limits, with no alert.
- **Linear lookups**: `lookup_pod_info` and `find_or_create_state` scan whole tables per sample.
- **Synchronous dispatch**: Lua handlers run inside the poll loop, so a slow handler (a memory dump can take
  up to `lua.timeoutMs`) delays the next collection.

## Goals

- API-server load proportional to the rate of change, not to cluster size.
- Memory bounded by what is monitored, kept as compact per-container records rather than raw JSON.
- Poll cycle time independent of node count.
- No silent caps: tables grow, and any limit that remains is reported.
- One binary, two deployment modes: a central Deployment for small and medium clusters, a per-node DaemonSet for
  large ones.

## Design

1. **List and watch instead of re-listing.** Pods (and nodes) are listed once in pages (`limit` + `continue`),
   then followed with a watch (`watch=1`, `allowWatchBookmarks=true`), resuming from the last `resourceVersion`
   and relisting on `410 Gone`. Each pod becomes a compact record: namespace, name, UID, node, pod IP, per-container
   name and memory limit, and annotations (with an optional key-prefix filter, since scripts read annotations but
   large clusters carry many unrelated ones). OOM kills are detected from pod status changes in watch events
   (`lastState.terminated.reason == OOMKilled` with a new restart count) as they happen, with the existing
   UID + container + restart-count dedupe and the startup age window.
2. **One event loop, no new threads.** Watch streams and stats requests run on a curl multi handle; the main loop
   waits in `curl_multi_poll` with the poll interval as its timeout and parses newline-delimited watch events as
   they arrive.
3. **Parallel stats in central mode.** Node stats are fetched concurrently with a bounded number of in-flight
   requests, optionally straight from each kubelet (`https://<node-ip>:10250/stats/summary`, RBAC `nodes/stats`)
   instead of through the API-server proxy.
4. **Node mode (DaemonSet).** Each instance learns its node from the downward API, watches only its node's pods
   (`fieldSelector=spec.nodeName=<node>`) and reads only its own kubelet's stats. Work and memory per instance stay
   constant as the cluster grows, and each kill is reported exactly once.
5. **Data structures.** Hash tables keyed by namespace/pod/container (the vendored `cwisstable.h`) replace the linear
   scans; per-container state and sample arrays grow without fixed caps.
6. **Dispatch.** First measure: log when a cycle overruns the poll interval. If overruns occur in practice, move
   action dispatch to one worker thread behind a bounded queue whose events own their data, so collection stays on
   schedule.
7. **Helm chart.** `mode: cluster | node`, a DaemonSet template, RBAC per mode, and resource defaults per mode.
8. **Scale harness.** A mock API server that serves paginated lists, watch streams and per-node stats for a
   configurable cluster size. A CI job runs pressured against a large simulated cluster and fails on regressions in
   API bytes per steady-state cycle, peak RSS and cycle time.

## Milestones

1. Scale harness, hash-table lookups and removal of the fixed caps.
2. Pod and node list-and-watch caches (central mode), OOM detection from watch events, fetching the pod list once.
3. Parallel stats fetching.
4. Node mode and chart support.
5. Dispatch decoupling, if the overrun measurements call for it.

## Open questions

- Should node mode drop the Events-API OOM path entirely, given that pod status covers OOM kills?
- Which annotation filter default keeps memory small without breaking existing scripts that read annotations?
- Is leader election needed for the central mode (more than one replica), or do we keep a single replica with the
  Recreate strategy?
