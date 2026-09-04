//! Dependency resolution over one repository index.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::error::{ArcError, Result};
use crate::metadata::Metadata;
use crate::repository::{RepositoryIndex, RepositoryPackage};
use crate::version::Requirement;

const MAX_SEARCH_STEPS: u64 = 100_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedPackage {
    pub package: RepositoryPackage,
    pub explicit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    /// Packages in dependency-first installation order.
    pub packages: Vec<PlannedPackage>,
}

#[derive(Clone, Debug, Default)]
struct State {
    /// Package name to repository-index position.
    selected: BTreeMap<String, usize>,
}

pub fn resolve(index: &RepositoryIndex, architecture: &str, requests: &[String]) -> Result<Plan> {
    index.validate()?;
    if requests.is_empty() {
        return Err(ArcError::Resolution("no packages were requested".into()));
    }

    let requirements = requests
        .iter()
        .map(|request| Requirement::parse(request))
        .collect::<Result<Vec<_>>>()?;
    let mut steps = 0;
    let state = search(
        index,
        architecture,
        requirements.clone(),
        State::default(),
        &mut steps,
    )?
    .ok_or_else(|| {
        ArcError::Resolution(format!(
            "no valid package set satisfies {}",
            requests.join(", ")
        ))
    })?;

    let explicit = requirements
        .iter()
        .filter_map(|requirement| selected_provider(index, &state, requirement))
        .map(|position| index.packages[position].metadata.name.clone())
        .collect::<BTreeSet<_>>();
    let order = installation_order(index, &state)?;
    Ok(Plan {
        packages: order
            .into_iter()
            .map(|position| {
                let package = index.packages[position].clone();
                let explicit = explicit.contains(&package.metadata.name);
                PlannedPackage { package, explicit }
            })
            .collect(),
    })
}

fn search(
    index: &RepositoryIndex,
    architecture: &str,
    mut pending: Vec<Requirement>,
    state: State,
    steps: &mut u64,
) -> Result<Option<State>> {
    *steps += 1;
    if *steps > MAX_SEARCH_STEPS {
        return Err(ArcError::Resolution(format!(
            "solver exceeded {MAX_SEARCH_STEPS} decisions"
        )));
    }
    if pending.is_empty() {
        return Ok(Some(state));
    }

    let requirement = pending.remove(0);
    if selected_provider(index, &state, &requirement).is_some() {
        return search(index, architecture, pending, state, steps);
    }

    for position in matching_candidates(index, architecture, &requirement) {
        let candidate = &index.packages[position];
        if state
            .selected
            .get(&candidate.metadata.name)
            .is_some_and(|selected| *selected != position)
        {
            continue;
        }

        let mut next = state.clone();
        next.selected
            .insert(candidate.metadata.name.clone(), position);
        if !compatible(index, &next) {
            continue;
        }

        let mut next_pending = pending.clone();
        for dependency in &candidate.metadata.depends {
            next_pending.push(Requirement::parse(dependency)?);
        }
        if let Some(solution) = search(index, architecture, next_pending, next, steps)? {
            return Ok(Some(solution));
        }
    }
    Ok(None)
}

fn matching_candidates(
    index: &RepositoryIndex,
    architecture: &str,
    requirement: &Requirement,
) -> Vec<usize> {
    let mut candidates = index
        .packages
        .iter()
        .enumerate()
        .filter(|(_, package)| {
            (package.metadata.arch == architecture || package.metadata.arch == "any")
                && package_satisfies(&package.metadata, requirement)
        })
        .map(|(position, _)| position)
        .collect::<Vec<_>>();

    candidates.sort_by(|first, second| {
        let first = &index.packages[*first];
        let second = &index.packages[*second];
        let first_direct = first.metadata.name == requirement.name;
        let second_direct = second.metadata.name == requirement.name;
        second_direct
            .cmp(&first_direct)
            .then_with(|| {
                let first_version = first.metadata.version().expect("validated index");
                let second_version = second.metadata.version().expect("validated index");
                second_version.cmp(&first_version)
            })
            .then_with(|| first.metadata.name.cmp(&second.metadata.name))
            .then_with(|| first.filename.cmp(&second.filename))
    });
    candidates
}

pub(crate) fn package_satisfies(metadata: &Metadata, requirement: &Requirement) -> bool {
    if metadata.name == requirement.name {
        return metadata
            .version()
            .is_ok_and(|version| requirement.matches(&version));
    }

    metadata.provides.iter().any(|provided| {
        let Ok(provided) = Requirement::parse(provided) else {
            return false;
        };
        if provided.name != requirement.name {
            return false;
        }
        match (&requirement.version, &provided.version) {
            (None, _) => true,
            (Some(_), Some(version)) => requirement.matches(version),
            (Some(_), None) => false,
        }
    })
}

fn selected_provider(
    index: &RepositoryIndex,
    state: &State,
    requirement: &Requirement,
) -> Option<usize> {
    state
        .selected
        .values()
        .copied()
        .find(|position| package_satisfies(&index.packages[*position].metadata, requirement))
}

fn compatible(index: &RepositoryIndex, state: &State) -> bool {
    let positions = state.selected.values().copied().collect::<Vec<_>>();
    for (offset, first) in positions.iter().enumerate() {
        for second in positions.iter().skip(offset + 1) {
            let first = &index.packages[*first].metadata;
            let second = &index.packages[*second].metadata;
            if conflicts(first, second) || conflicts(second, first) {
                return false;
            }
        }
    }
    true
}

fn conflicts(first: &Metadata, second: &Metadata) -> bool {
    first.conflicts.iter().any(|conflict| {
        Requirement::parse(conflict).is_ok_and(|conflict| package_satisfies(second, &conflict))
    })
}

fn installation_order(index: &RepositoryIndex, state: &State) -> Result<Vec<usize>> {
    fn visit(
        position: usize,
        index: &RepositoryIndex,
        state: &State,
        temporary: &mut HashSet<usize>,
        permanent: &mut HashSet<usize>,
        output: &mut Vec<usize>,
    ) -> Result<()> {
        if permanent.contains(&position) {
            return Ok(());
        }
        if !temporary.insert(position) {
            // Dependency cycles are valid because an Arc transaction extracts
            // every payload before it runs any post-install hook.
            return Ok(());
        }

        for dependency in &index.packages[position].metadata.depends {
            let dependency = Requirement::parse(dependency)?;
            let provider = selected_provider(index, state, &dependency).ok_or_else(|| {
                ArcError::Resolution(format!(
                    "internal solver error: {} has no selected provider for {dependency:?}",
                    index.packages[position].metadata.name
                ))
            })?;
            visit(provider, index, state, temporary, permanent, output)?;
        }
        temporary.remove(&position);
        permanent.insert(position);
        output.push(position);
        Ok(())
    }

    let mut temporary = HashSet::new();
    let mut permanent = HashSet::new();
    let mut output = Vec::new();
    for position in state.selected.values().copied() {
        visit(
            position,
            index,
            state,
            &mut temporary,
            &mut permanent,
            &mut output,
        )?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn package(name: &str, version: &str, depends: &[&str]) -> RepositoryPackage {
        RepositoryPackage {
            metadata: Metadata {
                format: 1,
                name: name.into(),
                version: version.into(),
                arch: "x86_64".into(),
                description: String::new(),
                license: String::new(),
                url: String::new(),
                self_contained: false,
                bundled: vec![],
                depends: depends.iter().map(|value| (*value).into()).collect(),
                optdepends: vec![],
                package_groups: vec![],
                provides: vec![],
                conflicts: vec![],
                replaces: vec![],
                backup: vec![],
                triggers: vec![],
                groups: vec![],
                users: vec![],
            },
            filename: format!("packages/{name}-{version}.arc"),
            sha256: HASH.into(),
            size: 1,
            signature: String::new(),
            files: vec![],
            source: String::new(),
        }
    }

    fn index(packages: Vec<RepositoryPackage>) -> RepositoryIndex {
        RepositoryIndex {
            format: 1,
            generated: 1,
            packages,
        }
    }

    #[test]
    fn dependencies_are_first_and_newest_versions_win() {
        let index = index(vec![
            package("app", "1", &["lib>=2"]),
            package("lib", "1", &[]),
            package("lib", "2", &[]),
        ]);
        let plan = resolve(&index, "x86_64", &["app".into()]).unwrap();
        let names = plan
            .packages
            .iter()
            .map(|item| {
                (
                    &*item.package.metadata.name,
                    &*item.package.metadata.version,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(names, [("lib", "2"), ("app", "1")]);
    }

    #[test]
    fn solver_backtracks_when_newest_candidate_is_impossible() {
        let index = index(vec![
            package("app", "2", &["missing"]),
            package("app", "1", &[]),
        ]);
        let plan = resolve(&index, "x86_64", &["app".into()]).unwrap();
        assert_eq!(plan.packages[0].package.metadata.version, "1");
    }

    #[test]
    fn virtual_providers_satisfy_dependencies() {
        let mut shell = package("dash", "1", &[]);
        shell.metadata.provides.push("sh=1".into());
        let index = index(vec![package("script", "1", &["sh"]), shell]);
        let plan = resolve(&index, "x86_64", &["script".into()]).unwrap();
        assert_eq!(plan.packages[0].package.metadata.name, "dash");
    }

    #[test]
    fn conflicts_make_a_request_unsatisfiable() {
        let mut first = package("first", "1", &[]);
        first.metadata.conflicts.push("second".into());
        let index = index(vec![first, package("second", "1", &[])]);
        assert!(resolve(&index, "x86_64", &["first".into(), "second".into()]).is_err());
    }

    #[test]
    fn dependency_cycles_terminate() {
        let index = index(vec![
            package("first", "1", &["second"]),
            package("second", "1", &["first"]),
        ]);
        let plan = resolve(&index, "x86_64", &["first".into()]).unwrap();
        assert_eq!(plan.packages.len(), 2);
    }
}
