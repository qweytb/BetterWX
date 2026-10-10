use std::{collections::BTreeSet, ops::Range};

use crate::{Result, progress::Progress, uia};

pub struct Feature {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub scan: fn(&[u8], &Progress) -> Result<Vec<Edit>>,
}

pub struct Edit {
    pub range: Range<usize>,
    pub bytes: Vec<u8>,
}

pub struct Prepared {
    pub feature: &'static Feature,
    pub edits: std::result::Result<Vec<Edit>, String>,
}

pub const FEATURES: &[Feature] = &[uia::FEATURE];

pub fn find(id: &str) -> Result<&'static Feature> {
    FEATURES
        .iter()
        .find(|feature| feature.id == id)
        .ok_or_else(|| format!("未知功能：{id}").into())
}

pub fn scan(original: &[u8], progress: &Progress) -> Result<Vec<Prepared>> {
    let mut prepared = Vec::new();
    for feature in FEATURES {
        progress.check()?;
        let edits = (feature.scan)(original, progress).map_err(|error| error.to_string());
        progress.check()?;
        prepared.push(Prepared { feature, edits });
    }
    Ok(prepared)
}

pub fn inspect(
    original: &[u8],
    current: &[u8],
    prepared: &[Prepared],
    progress: &Progress,
) -> Result<(BTreeSet<String>, Option<String>)> {
    let step = progress.activity("识别当前补丁");
    let mut enabled = BTreeSet::new();
    for patch in prepared {
        progress.check()?;
        let Ok(edits) = &patch.edits else {
            continue;
        };
        let applied = !edits.is_empty()
            && edits.iter().all(|edit| {
                current.get(edit.range.start..edit.range.start + edit.bytes.len())
                    == Some(edit.bytes.as_slice())
            });
        if applied {
            enabled.insert(patch.feature.id.to_owned());
        }
    }
    let expected = generate(original, &enabled, prepared)?;
    let difference = expected
        .iter()
        .zip(current)
        .position(|(left, right)| left != right)
        .or_else(|| (expected.len() != current.len()).then_some(expected.len().min(current.len())));
    let issue = difference.map(|offset| format!("文件位置 {offset:#x} 存在未识别的改动"));
    step.finish(if let Some(issue) = &issue {
        issue.clone()
    } else if enabled.is_empty() {
        "原始状态".to_owned()
    } else {
        enabled.iter().cloned().collect::<Vec<_>>().join("、")
    });
    Ok((enabled, issue))
}

pub fn generate(
    original: &[u8],
    enabled: &BTreeSet<String>,
    prepared: &[Prepared],
) -> Result<Vec<u8>> {
    let mut edits = Vec::new();
    for id in enabled {
        let patch = prepared
            .iter()
            .find(|patch| patch.feature.id == id)
            .ok_or_else(|| format!("未知功能：{id}"))?;
        let changes = patch
            .edits
            .as_ref()
            .map_err(|error| format!("{}：{error}", patch.feature.name))?;
        edits.extend(changes);
    }
    edits.sort_by_key(|edit| edit.range.start);
    for pair in edits.windows(2) {
        if pair[0].range.end > pair[1].range.start {
            return Err("所选功能的修改位置重叠".into());
        }
    }
    let mut output = original.to_vec();
    for edit in edits.into_iter().rev() {
        output.splice(edit.range.clone(), edit.bytes.iter().copied());
    }
    Ok(output)
}
