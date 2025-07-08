## Patch Description

memcg: fix data-race KCSAN bug in rstats

A data-race issue in memcg rstat occurs when two distinct code paths
access the same 4-byte region concurrently.  KCSAN detection triggers the
following BUG as a result.

	BUG: KCSAN: data-race in __count_memcg_events / mem_cgroup_css_rstat_flush

	write to 0xffffe8ffff98e300 of 4 bytes by task 5274 on cpu 17:
	mem_cgroup_css_rstat_flush (mm/memcontrol.c:5850)
	cgroup_rstat_flush_locked (kernel/cgroup/rstat.c:243 (discriminator 7))
	cgroup_rstat_flush (./include/linux/spinlock.h:401 kernel/cgroup/rstat.c:278)
	mem_cgroup_flush_stats.part.0 (mm/memcontrol.c:767)
	memory_numa_stat_show (mm/memcontrol.c:6911)
<snip>

	read to 0xffffe8ffff98e300 of 4 bytes by task 410848 on cpu 27:
	__count_memcg_events (mm/memcontrol.c:725 mm/memcontrol.c:962)
	count_memcg_event_mm.part.0 (./include/linux/memcontrol.h:1097 ./include/linux/memcontrol.h:1120)
	handle_mm_fault (mm/memory.c:5483 mm/memory.c:5622)
<snip>

	value changed: 0x00000029 -> 0x00000000

The race occurs because two code paths access the same "stats_updates"
location.  Although "stats_updates" is a per-CPU variable, it is remotely
accessed by another CPU at
cgroup_rstat_flush_locked()->mem_cgroup_css_rstat_flush(), leading to the
data race mentioned.

Considering that memcg_rstat_updated() is in the hot code path, adding a
lock to protect it may not be desirable, especially since this variable
pertains solely to statistics.

Therefore, annotating accesses to stats_updates with READ/WRITE_ONCE() can
prevent KCSAN splats and potential partial reads/writes.

Link: https://lkml.kernel.org/r/20240424125940.2410718-1-leitao@debian.org
Fixes: 9cee7e8ef3e3 ("mm: memcg: optimize parent iteration in memcg_rstat_updated()")
Signed-off-by: Breno Leitao <leitao@debian.org>
Suggested-by: Shakeel Butt <shakeel.butt@linux.dev>
Acked-by: Johannes Weiner <hannes@cmpxchg.org>
Acked-by: Shakeel Butt <shakeel.butt@linux.dev>
Reviewed-by: Yosry Ahmed <yosryahmed@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Muchun Song <songmuchun@bytedance.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>

## Buggy Code

```c
// mm/memcontrol.c
static inline void memcg_rstat_updated(struct mem_cgroup *memcg, int val)
{
	struct memcg_vmstats_percpu *statc;
	int cpu = smp_processor_id();

	if (!val)
		return;

	cgroup_rstat_updated(memcg->css.cgroup, cpu);
	statc = this_cpu_ptr(memcg->vmstats_percpu);
	for (; statc; statc = statc->parent) {
		statc->stats_updates += abs(val);
		if (statc->stats_updates < MEMCG_CHARGE_BATCH)
			continue;

		/*
		 * If @memcg is already flush-able, increasing stats_updates is
		 * redundant. Avoid the overhead of the atomic update.
		 */
		if (!memcg_vmstats_needs_flush(statc->vmstats))
			atomic64_add(statc->stats_updates,
				     &statc->vmstats->stats_updates);
		statc->stats_updates = 0;
	}
}
```
```c
// mm/memcontrol.c
static void mem_cgroup_css_rstat_flush(struct cgroup_subsys_state *css, int cpu)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	struct mem_cgroup *parent = parent_mem_cgroup(memcg);
	struct memcg_vmstats_percpu *statc;
	long delta, delta_cpu, v;
	int i, nid;

	statc = per_cpu_ptr(memcg->vmstats_percpu, cpu);

	for (i = 0; i < MEMCG_NR_STAT; i++) {
		/*
		 * Collect the aggregated propagation counts of groups
		 * below us. We're in a per-cpu loop here and this is
		 * a global counter, so the first cycle will get them.
		 */
		delta = memcg->vmstats->state_pending[i];
		if (delta)
			memcg->vmstats->state_pending[i] = 0;

		/* Add CPU changes on this level since the last flush */
		delta_cpu = 0;
		v = READ_ONCE(statc->state[i]);
		if (v != statc->state_prev[i]) {
			delta_cpu = v - statc->state_prev[i];
			delta += delta_cpu;
			statc->state_prev[i] = v;
		}

		/* Aggregate counts on this level and propagate upwards */
		if (delta_cpu)
			memcg->vmstats->state_local[i] += delta_cpu;

		if (delta) {
			memcg->vmstats->state[i] += delta;
			if (parent)
				parent->vmstats->state_pending[i] += delta;
		}
	}

	for (i = 0; i < NR_MEMCG_EVENTS; i++) {
		delta = memcg->vmstats->events_pending[i];
		if (delta)
			memcg->vmstats->events_pending[i] = 0;

		delta_cpu = 0;
		v = READ_ONCE(statc->events[i]);
		if (v != statc->events_prev[i]) {
			delta_cpu = v - statc->events_prev[i];
			delta += delta_cpu;
			statc->events_prev[i] = v;
		}

		if (delta_cpu)
			memcg->vmstats->events_local[i] += delta_cpu;

		if (delta) {
			memcg->vmstats->events[i] += delta;
			if (parent)
				parent->vmstats->events_pending[i] += delta;
		}
	}

	for_each_node_state(nid, N_MEMORY) {
		struct mem_cgroup_per_node *pn = memcg->nodeinfo[nid];
		struct mem_cgroup_per_node *ppn = NULL;
		struct lruvec_stats_percpu *lstatc;

		if (parent)
			ppn = parent->nodeinfo[nid];

		lstatc = per_cpu_ptr(pn->lruvec_stats_percpu, cpu);

		for (i = 0; i < NR_VM_NODE_STAT_ITEMS; i++) {
			delta = pn->lruvec_stats.state_pending[i];
			if (delta)
				pn->lruvec_stats.state_pending[i] = 0;

			delta_cpu = 0;
			v = READ_ONCE(lstatc->state[i]);
			if (v != lstatc->state_prev[i]) {
				delta_cpu = v - lstatc->state_prev[i];
				delta += delta_cpu;
				lstatc->state_prev[i] = v;
			}

			if (delta_cpu)
				pn->lruvec_stats.state_local[i] += delta_cpu;

			if (delta) {
				pn->lruvec_stats.state[i] += delta;
				if (ppn)
					ppn->lruvec_stats.state_pending[i] += delta;
			}
		}
	}
	statc->stats_updates = 0;
	/* We are in a per-cpu loop here, only do the atomic write once */
	if (atomic64_read(&memcg->vmstats->stats_updates))
		atomic64_set(&memcg->vmstats->stats_updates, 0);
}
```

## Bug Fix Patch

```diff
diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 9095ab05d47a..a111e0d981ba 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -715,6 +715,7 @@ static inline void memcg_rstat_updated(struct mem_cgroup *memcg, int val)
 {
 	struct memcg_vmstats_percpu *statc;
 	int cpu = smp_processor_id();
+	unsigned int stats_updates;
 
 	if (!val)
 		return;
@@ -722,8 +723,9 @@ static inline void memcg_rstat_updated(struct mem_cgroup *memcg, int val)
 	cgroup_rstat_updated(memcg->css.cgroup, cpu);
 	statc = this_cpu_ptr(memcg->vmstats_percpu);
 	for (; statc; statc = statc->parent) {
-		statc->stats_updates += abs(val);
-		if (statc->stats_updates < MEMCG_CHARGE_BATCH)
+		stats_updates = READ_ONCE(statc->stats_updates) + abs(val);
+		WRITE_ONCE(statc->stats_updates, stats_updates);
+		if (stats_updates < MEMCG_CHARGE_BATCH)
 			continue;
 
 		/*
@@ -731,9 +733,9 @@ static inline void memcg_rstat_updated(struct mem_cgroup *memcg, int val)
 		 * redundant. Avoid the overhead of the atomic update.
 		 */
 		if (!memcg_vmstats_needs_flush(statc->vmstats))
-			atomic64_add(statc->stats_updates,
+			atomic64_add(stats_updates,
 				     &statc->vmstats->stats_updates);
-		statc->stats_updates = 0;
+		WRITE_ONCE(statc->stats_updates, 0);
 	}
 }
 
@@ -5887,7 +5889,7 @@ static void mem_cgroup_css_rstat_flush(struct cgroup_subsys_state *css, int cpu)
 			}
 		}
 	}
-	statc->stats_updates = 0;
+	WRITE_ONCE(statc->stats_updates, 0);
 	/* We are in a per-cpu loop here, only do the atomic write once */
 	if (atomic64_read(&memcg->vmstats->stats_updates))
 		atomic64_set(&memcg->vmstats->stats_updates, 0);
```

