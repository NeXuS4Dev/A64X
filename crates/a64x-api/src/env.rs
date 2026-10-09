//! Process environment block (case-insensitive names, as on Windows).

/// Environment variables of the guest process.
pub(crate) struct Env {
    vars: Vec<(String, String)>,
    /// Bumped on every change; cached guest copies are rebuilt when it moves.
    pub(crate) version: u64,
}

impl Env {
    /// Snapshot of the host environment at process start.
    pub(crate) fn from_host() -> Env {
        let vars = std::env::vars_os()
            .filter_map(|(k, v)| {
                let k = k.to_string_lossy().into_owned();
                if k.is_empty() || k.starts_with('=') {
                    None
                } else {
                    Some((k, v.to_string_lossy().into_owned()))
                }
            })
            .collect();
        Env { vars, version: 1 }
    }

    /// Value of `name` (case-insensitive).
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Set (`Some`) or delete (`None`) a variable.
    pub(crate) fn set(&mut self, name: &str, value: Option<&str>) {
        let idx = self
            .vars
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case(name));
        match (idx, value) {
            (Some(i), Some(v)) => self.vars[i].1 = v.to_string(),
            (Some(i), None) => {
                self.vars.remove(i);
            }
            (None, Some(v)) => self.vars.push((name.to_string(), v.to_string())),
            (None, None) => {}
        }
        self.version += 1;
    }

    /// `NAME=value` entries in insertion order.
    pub(crate) fn entries(&self) -> Vec<String> {
        self.vars.iter().map(|(k, v)| format!("{k}={v}")).collect()
    }
}
