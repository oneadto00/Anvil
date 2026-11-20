//! Dependency DAG construction, deterministic cycle detection, and event-driven scheduling.

use crate::config::AnvilConfig;
use crate::error::{ConfigValidationError, CoreError};
use crate::state::ServiceId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub use crate::error::DagCycleError;

/// Directed acyclic dependency graph built from [`AnvilConfig::services`].
///
/// Uses `BTreeMap` and `BTreeSet` internally so topological waves and downstream
/// traversals are completely deterministic across runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyGraph {
    /// Reverse adjacency map: `service -> sorted set of upstream dependencies`.
    dependencies: BTreeMap<ServiceId, BTreeSet<ServiceId>>,
    /// Forward adjacency map: `upstream -> sorted list of downstream dependents`.
    dependents: BTreeMap<ServiceId, Vec<ServiceId>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitColor {
    White,
    Gray,
    Black,
}

impl DependencyGraph {
    /// Builds and validates a [`DependencyGraph`] from [`AnvilConfig`].
    ///
    /// Returns [`CoreError::ValidationErrors`] if any `depends_on` references an
    /// undefined service ID, or [`CoreError::DagCycle`] with the exact closed cycle
    /// path if a circular dependency exists.
    pub fn from_config(config: &AnvilConfig) -> Result<Self, CoreError> {
        let mut dependencies: BTreeMap<ServiceId, BTreeSet<ServiceId>> = BTreeMap::new();
        let mut dependents_sets: BTreeMap<ServiceId, BTreeSet<ServiceId>> = BTreeMap::new();
        let mut missing_errors = Vec::new();

        for service_id in config.services.keys() {
            dependencies.insert(service_id.clone(), BTreeSet::new());
            dependents_sets.insert(service_id.clone(), BTreeSet::new());
        }

        for (service_id, svc) in &config.services {
            for dep in &svc.depends_on {
                if !config.services.contains_key(dep) {
                    missing_errors.push(ConfigValidationError::UndefinedDependency {
                        service: service_id.clone(),
                        missing_dep: dep.clone(),
                    });
                    continue;
                }

                if let Some(deps) = dependencies.get_mut(service_id) {
                    deps.insert(dep.clone());
                }
                if let Some(children) = dependents_sets.get_mut(dep) {
                    children.insert(service_id.clone());
                }
            }
        }

        if !missing_errors.is_empty() {
            return Err(CoreError::ValidationErrors(missing_errors));
        }

        detect_cycles(&dependencies)?;

        let dependents = dependents_sets
            .into_iter()
            .map(|(id, children)| (id, children.into_iter().collect()))
            .collect();

        Ok(Self {
            dependencies,
            dependents,
        })
    }

    /// Computes topological startup waves using Kahn's algorithm.
    ///
    /// Services inside each wave are sorted lexicographically and have all of their
    /// upstream dependencies satisfied in earlier waves.
    pub fn execution_layers(&self) -> Vec<Vec<ServiceId>> {
        let mut in_degree: BTreeMap<ServiceId, usize> = self
            .dependencies
            .iter()
            .map(|(id, deps)| (id.clone(), deps.len()))
            .collect();

        let mut current_wave: Vec<ServiceId> = in_degree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(id, _)| id.clone())
            .collect();

        let mut layers = Vec::new();

        while !current_wave.is_empty() {
            let mut next_wave = BTreeSet::new();

            for service_id in &current_wave {
                if let Some(children) = self.dependents.get(service_id) {
                    for child in children {
                        if let Some(deg) = in_degree.get_mut(child) {
                            *deg = deg.saturating_sub(1);
                            if *deg == 0 {
                                next_wave.insert(child.clone());
                            }
                        }
                    }
                }
            }

            layers.push(current_wave);
            current_wave = next_wave.into_iter().collect();
        }

        layers
    }

    /// Computes reverse topological shutdown waves for safe cascading teardown.
    pub fn shutdown_layers(&self) -> Vec<Vec<ServiceId>> {
        let mut layers = self.execution_layers();
        layers.reverse();
        layers
    }

    /// Returns the reverse adjacency map (`service -> upstream dependencies`).
    pub fn dependencies(&self) -> &BTreeMap<ServiceId, BTreeSet<ServiceId>> {
        &self.dependencies
    }

    /// Returns the forward adjacency map (`upstream -> downstream dependents`).
    pub fn dependents(&self) -> &BTreeMap<ServiceId, Vec<ServiceId>> {
        &self.dependents
    }

    /// Returns the direct upstream dependencies of `id`, if `id` exists in the graph.
    pub fn dependencies_of(&self, id: &str) -> Option<&BTreeSet<ServiceId>> {
        self.dependencies.get(id)
    }

    /// Returns the direct downstream dependents of `id`, if `id` exists in the graph.
    pub fn dependents_of(&self, id: &str) -> Option<&[ServiceId]> {
        self.dependents.get(id).map(Vec::as_slice)
    }

    /// Creates a fresh event-driven runtime scheduler state from this graph.
    pub fn scheduler_state(&self) -> DagSchedulerState {
        DagSchedulerState::new(self)
    }
}

/// Event-driven runtime scheduling tracker for a validated [`DependencyGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagSchedulerState {
    dependencies: BTreeMap<ServiceId, BTreeSet<ServiceId>>,
    dependents: BTreeMap<ServiceId, Vec<ServiceId>>,
    healthy: BTreeSet<ServiceId>,
    unlocked: BTreeSet<ServiceId>,
}

impl DagSchedulerState {
    /// Initializes scheduler state with all root services (in-degree `0`) marked unlocked.
    pub fn new(graph: &DependencyGraph) -> Self {
        let unlocked = root_services_iter(&graph.dependencies).collect();

        Self {
            dependencies: graph.dependencies.clone(),
            dependents: graph.dependents.clone(),
            healthy: BTreeSet::new(),
            unlocked,
        }
    }

    /// Returns all services with zero upstream dependencies in deterministic order.
    pub fn initial_ready_services(&self) -> Vec<ServiceId> {
        root_services_iter(&self.dependencies).collect()
    }

    /// Direct dependents whose waiting snapshot changes when this service changes health.
    pub(crate) fn dependents_of(&self, id: &str) -> &[ServiceId] {
        self.dependents.get(id).map(Vec::as_slice).unwrap_or_default()
    }

    /// Rearm dependency checks after one instance exits. Running descendants
    /// retain their own health until their own lifecycle event arrives.
    pub(crate) fn mark_exited(&mut self, id: &str) {
        self.healthy.remove(id);
        self.unlocked.remove(id);
        if let Some(children) = self.dependents.get(id) {
            for child in children {
                if !self.healthy.contains(child) {
                    self.unlocked.remove(child);
                }
            }
        }
    }

    /// Marks `id` as healthy and returns only the downstream services whose remaining
    /// unsatisfied upstream dependencies just dropped to `0`.
    ///
    /// Calling this multiple times for the same healthy service or for an unknown
    /// service returns an empty `Vec` and never duplicates unlocked services.
    pub fn mark_healthy(&mut self, id: &str) -> Vec<ServiceId> {
        if !self.dependencies.contains_key(id) {
            return Vec::new();
        }
        if !self.healthy.insert(id.to_owned()) {
            return Vec::new();
        }
        self.unlocked.insert(id.to_owned());

        let mut newly_unlocked = Vec::new();
        if let Some(children) = self.dependents.get(id) {
            for child in children {
                if !self.unlocked.contains(child)
                    && self
                        .dependencies
                        .get(child)
                        .is_some_and(|deps| deps.iter().all(|dep| self.healthy.contains(dep)))
                {
                    self.unlocked.insert(child.clone());
                    newly_unlocked.push(child.clone());
                }
            }
        }

        newly_unlocked
    }

    /// Resets `id` and all transitive downstream dependents for restart tracking.
    ///
    /// Clears healthy and unlocked tracking for the entire affected subgraph and returns
    /// the sorted list of affected service IDs (empty if `id` is unknown).
    pub fn reset_subtree(&mut self, id: &str) -> Vec<ServiceId> {
        if !self.dependencies.contains_key(id) {
            return Vec::new();
        }

        let mut affected = BTreeSet::new();
        let mut queue = VecDeque::new();

        let root = id.to_owned();
        affected.insert(root.clone());
        queue.push_back(root);

        while let Some(current) = queue.pop_front() {
            if let Some(children) = self.dependents.get(&current) {
                for child in children {
                    if affected.insert(child.clone()) {
                        queue.push_back(child.clone());
                    }
                }
            }
        }

        for svc in &affected {
            self.healthy.remove(svc);
            self.unlocked.remove(svc);
        }

        affected.into_iter().collect()
    }

    /// Returns the sorted list of upstream dependencies for `id` not yet marked healthy.
    pub fn pending_dependencies(&self, id: &str) -> Vec<ServiceId> {
        self.dependencies
            .get(id)
            .map(|deps| {
                deps.iter()
                    .filter(|dep| !self.healthy.contains(*dep))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns `true` if `id` is currently recorded as healthy.
    pub fn is_healthy(&self, id: &str) -> bool {
        self.healthy.contains(id)
    }

    /// Returns `true` if `id` exists in the graph and all of its upstream dependencies are healthy.
    pub fn is_ready(&self, id: &str) -> bool {
        self.dependencies
            .get(id)
            .is_some_and(|deps| deps.iter().all(|dep| self.healthy.contains(dep)))
    }
}

fn root_services_iter(
    dependencies: &BTreeMap<ServiceId, BTreeSet<ServiceId>>,
) -> impl Iterator<Item = ServiceId> + '_ {
    dependencies
        .iter()
        .filter(|&(_, deps)| deps.is_empty())
        .map(|(id, _)| id.clone())
}

fn detect_cycles(
    dependencies: &BTreeMap<ServiceId, BTreeSet<ServiceId>>,
) -> Result<(), DagCycleError> {
    let mut colors: BTreeMap<ServiceId, VisitColor> = dependencies
        .keys()
        .map(|id| (id.clone(), VisitColor::White))
        .collect();
    let mut stack = Vec::new();
    let mut pos_map = BTreeMap::new();

    for service_id in dependencies.keys() {
        if colors.get(service_id).copied() == Some(VisitColor::White) {
            detect_cycle_dfs(
                service_id,
                dependencies,
                &mut colors,
                &mut stack,
                &mut pos_map,
            )?;
        }
    }

    Ok(())
}

fn detect_cycle_dfs(
    node: &ServiceId,
    dependencies: &BTreeMap<ServiceId, BTreeSet<ServiceId>>,
    colors: &mut BTreeMap<ServiceId, VisitColor>,
    stack: &mut Vec<ServiceId>,
    pos_map: &mut BTreeMap<ServiceId, usize>,
) -> Result<(), DagCycleError> {
    colors.insert(node.clone(), VisitColor::Gray);
    let pos = stack.len();
    stack.push(node.clone());
    pos_map.insert(node.clone(), pos);

    if let Some(deps) = dependencies.get(node) {
        for dep in deps {
            match colors.get(dep).copied().unwrap_or(VisitColor::White) {
                VisitColor::Gray => {
                    let start_idx = pos_map.get(dep).copied().unwrap_or(0);
                    let mut cycle = stack[start_idx..].to_vec();
                    if let Some((min_idx, _)) =
                        cycle.iter().enumerate().min_by(|(_, a), (_, b)| a.cmp(b))
                    {
                        cycle.rotate_left(min_idx);
                    }
                    if let Some(first) = cycle.first().cloned() {
                        cycle.push(first);
                    }
                    return Err(DagCycleError { cycle_path: cycle });
                }
                VisitColor::White => {
                    detect_cycle_dfs(dep, dependencies, colors, stack, pos_map)?;
                }
                VisitColor::Black => {}
            }
        }
    }

    stack.pop();
    pos_map.remove(node);
    colors.insert(node.clone(), VisitColor::Black);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProjectMetadata, RuntimeConfig, ServiceConfig};

    fn make_config(edges: &[(&str, &[&str])]) -> AnvilConfig {
        let services = edges
            .iter()
            .map(|(name, deps)| {
                let svc = ServiceConfig {
                    runtime: RuntimeConfig::Native {
                        cmd: format!("echo {name}"),
                        cwd: None,
                        grace_period_ms: 3_000,
                    },
                    port: None,
                    depends_on: deps.iter().map(|d| (*d).to_owned()).collect(),
                    env: BTreeMap::new(),
                    readiness_probe: None,
                    restart_policy: Default::default(),
                };
                ((*name).to_owned(), svc)
            })
            .collect();

        AnvilConfig {
            version: "1".to_owned(),
            project: ProjectMetadata {
                name: "dag-test".to_owned(),
                description: None,
            },
            env: BTreeMap::new(),
            secrets: Vec::new(),
            services,
        }
    }

    #[test]
    fn diamond_dag_layers_and_step_by_step_unlocking() {
        // db -> [auth, billing] -> gateway
        let cfg = make_config(&[
            ("db", &[]),
            ("auth", &["db"]),
            ("billing", &["db"]),
            ("gateway", &["auth", "billing"]),
        ]);

        let graph = DependencyGraph::from_config(&cfg).unwrap();

        assert_eq!(
            graph.execution_layers(),
            vec![
                vec!["db".to_owned()],
                vec!["auth".to_owned(), "billing".to_owned()],
                vec!["gateway".to_owned()],
            ]
        );
        assert_eq!(
            graph.shutdown_layers(),
            vec![
                vec!["gateway".to_owned()],
                vec!["auth".to_owned(), "billing".to_owned()],
                vec!["db".to_owned()],
            ]
        );

        let mut scheduler = graph.scheduler_state();
        assert_eq!(scheduler.initial_ready_services(), vec!["db".to_owned()]);
        assert!(scheduler.is_ready("db"));
        assert!(!scheduler.is_ready("auth"));
        assert_eq!(
            scheduler.pending_dependencies("gateway"),
            vec!["auth".to_owned(), "billing".to_owned()]
        );

        assert_eq!(
            scheduler.mark_healthy("db"),
            vec!["auth".to_owned(), "billing".to_owned()]
        );
        assert!(scheduler.is_healthy("db"));
        assert!(scheduler.is_ready("auth"));
        assert!(scheduler.is_ready("billing"));
        assert!(!scheduler.is_ready("gateway"));

        assert!(scheduler.mark_healthy("db").is_empty());

        assert!(scheduler.mark_healthy("auth").is_empty());
        assert!(!scheduler.is_ready("gateway"));
        assert_eq!(
            scheduler.pending_dependencies("gateway"),
            vec!["billing".to_owned()]
        );

        assert_eq!(
            scheduler.mark_healthy("billing"),
            vec!["gateway".to_owned()]
        );
        assert!(scheduler.is_ready("gateway"));
        assert!(scheduler.pending_dependencies("gateway").is_empty());

        assert!(scheduler.mark_healthy("gateway").is_empty());
        assert!(scheduler.is_healthy("gateway"));
    }

    #[test]
    fn reset_subtree_rearms_downstream_unlocking() {
        let cfg = make_config(&[
            ("db", &[]),
            ("auth", &["db"]),
            ("billing", &["db"]),
            ("gateway", &["auth", "billing"]),
        ]);
        let graph = DependencyGraph::from_config(&cfg).unwrap();
        let mut scheduler = graph.scheduler_state();

        scheduler.mark_healthy("db");
        scheduler.mark_healthy("auth");
        scheduler.mark_healthy("billing");
        scheduler.mark_healthy("gateway");

        // Restarting auth invalidates auth and gateway, while db and billing stay healthy.
        let affected = scheduler.reset_subtree("auth");
        assert_eq!(affected, vec!["auth".to_owned(), "gateway".to_owned()]);
        assert!(scheduler.is_healthy("db"));
        assert!(scheduler.is_healthy("billing"));
        assert!(!scheduler.is_healthy("auth"));
        assert!(!scheduler.is_healthy("gateway"));
        assert!(scheduler.is_ready("auth"));
        assert!(!scheduler.is_ready("gateway"));

        // When auth recovers, gateway is unlocked again because billing is still healthy.
        assert_eq!(scheduler.mark_healthy("auth"), vec!["gateway".to_owned()]);
        assert!(scheduler.is_ready("gateway"));

        assert!(scheduler.reset_subtree("nonexistent").is_empty());
        assert!(scheduler.mark_healthy("nonexistent").is_empty());
    }

    #[test]
    fn detects_two_node_cycle_with_closed_path() {
        let cfg = make_config(&[("a", &["b"]), ("b", &["a"])]);
        let err = DependencyGraph::from_config(&cfg).unwrap_err();

        match err {
            CoreError::DagCycle(cycle_err) => {
                assert_eq!(
                    cycle_err.cycle_path,
                    vec!["a".to_owned(), "b".to_owned(), "a".to_owned()]
                );
                assert_eq!(cycle_err.to_string(), "dependency cycle detected: a -> b -> a");
            }
            other => panic!("expected DagCycle error, got: {other:?}"),
        }
    }

    #[test]
    fn detects_three_node_cycle_embedded_in_larger_valid_graph() {
        // Non-cycle prefixes/suffixes (aaa-edge, db, metrics, zzz-ui) surround the cycle:
        // api -> worker -> cache -> api
        let cfg = make_config(&[
            ("aaa-edge", &["api"]),
            ("db", &[]),
            ("api", &["db", "worker"]),
            ("worker", &["cache"]),
            ("cache", &["api"]),
            ("metrics", &["cache"]),
            ("zzz-ui", &["db"]),
        ]);

        let err = DependencyGraph::from_config(&cfg).unwrap_err();
        match err {
            CoreError::DagCycle(cycle_err) => {
                assert_eq!(
                    cycle_err.cycle_path,
                    vec![
                        "api".to_owned(),
                        "worker".to_owned(),
                        "cache".to_owned(),
                        "api".to_owned(),
                    ]
                );
                assert_eq!(cycle_err.cycle_path.first(), cycle_err.cycle_path.last());
                assert_eq!(
                    cycle_err.to_string(),
                    "dependency cycle detected: api -> worker -> cache -> api"
                );
            }
            other => panic!("expected DagCycle error, got: {other:?}"),
        }
    }

    #[test]
    fn handles_disconnected_multi_root_graphs() {
        let cfg = make_config(&[
            ("postgres", &[]),
            ("redis", &[]),
            ("docs", &[]),
            ("api", &["postgres"]),
            ("worker", &["redis"]),
            ("web", &["api", "worker"]),
        ]);

        let graph = DependencyGraph::from_config(&cfg).unwrap();

        assert_eq!(
            graph.execution_layers(),
            vec![
                vec!["docs".to_owned(), "postgres".to_owned(), "redis".to_owned()],
                vec!["api".to_owned(), "worker".to_owned()],
                vec!["web".to_owned()],
            ]
        );
        assert_eq!(
            graph.shutdown_layers(),
            vec![
                vec!["web".to_owned()],
                vec!["api".to_owned(), "worker".to_owned()],
                vec!["docs".to_owned(), "postgres".to_owned(), "redis".to_owned()],
            ]
        );

        let mut scheduler = graph.scheduler_state();
        assert_eq!(
            scheduler.initial_ready_services(),
            vec!["docs".to_owned(), "postgres".to_owned(), "redis".to_owned()]
        );

        assert_eq!(scheduler.mark_healthy("docs"), Vec::<ServiceId>::new());
        assert_eq!(scheduler.mark_healthy("postgres"), vec!["api".to_owned()]);
        assert_eq!(scheduler.mark_healthy("redis"), vec!["worker".to_owned()]);
        assert!(scheduler.mark_healthy("api").is_empty());
        assert_eq!(scheduler.mark_healthy("worker"), vec!["web".to_owned()]);
    }

    #[test]
    fn rejects_undefined_dependency_when_called_on_unvalidated_config() {
        let cfg = make_config(&[("api", &["missing-db"])]);
        let err = DependencyGraph::from_config(&cfg).unwrap_err();
        assert!(matches!(err, CoreError::ValidationErrors(_)));
    }
}
