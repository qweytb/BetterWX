use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use iced_x86::{Code, Register};

use crate::{Result, feature::Resources, image::Image, progress::Progress};

pub fn find(image: &Image<'_>, root: &str, progress: &Progress) -> Result<Vec<u64>> {
    let encoded: Vec<_> = root.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let sections = image.sections()?;
    let mut names = BTreeSet::new();
    for address in image.find(root, &encoded, progress)? {
        let Some(header) = address.checked_sub(6) else {
            continue;
        };
        let Some((base, data, offset)) = sections.iter().find_map(|(base, data)| {
            let offset = usize::try_from(header.checked_sub(*base)?).ok()?;
            (offset + 6 + encoded.len() <= data.len()).then_some((*base, *data, offset))
        }) else {
            continue;
        };
        if data[offset..offset + 2] != (encoded.len() as u16 / 2).to_be_bytes() {
            continue;
        }
        let mut pending = vec![offset];
        while let Some(end) = pending.pop() {
            progress.check()?;
            if !names.insert(base + end as u64) {
                continue;
            }
            let first = end.saturating_sub(usize::from(u16::MAX) * 2 + 6);
            let first = first + (end - first) % 2;
            for start in (first..end.saturating_sub(6)).step_by(2) {
                let length = u16::from_be_bytes(data[start..start + 2].try_into()?) as usize;
                if length == 0 || start + 6 + length * 2 != end {
                    continue;
                }
                let hash =
                    data[start + 6..end]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .fold(0u32, |hash, pair| {
                            let hash =
                                (hash << 4).wrapping_add(u32::from(u16::from_be_bytes(*pair)));
                            (hash ^ ((hash & 0xf000_0000) >> 23)) & 0x0fff_ffff
                        });
                if hash == u32::from_be_bytes(data[start + 2..start + 6].try_into()?) {
                    pending.push(start);
                }
            }
        }
    }
    if names.is_empty() {
        return Err("找不到 Qt 资源名称表".into());
    }
    Ok(names.into_iter().collect())
}

pub struct Scan {
    names: Vec<u64>,
    paths: BTreeMap<String, String>,
    tables: BTreeSet<u64>,
    pub resources: Resources,
}

impl Scan {
    pub fn new(names: Vec<u64>, paths: BTreeMap<String, String>) -> Self {
        Self {
            names,
            paths,
            tables: BTreeSet::new(),
            resources: Resources::new(),
        }
    }

    pub fn visit(
        &mut self,
        image: &Image<'_>,
        function: &Range<u64>,
        progress: &Progress,
    ) -> Result<()> {
        let mut arguments = BTreeMap::new();
        for instruction in image.instructions(function)? {
            if instruction.code() == Code::Lea_r64_m && instruction.is_ip_rel_memory_operand() {
                arguments.insert(
                    instruction.op0_register(),
                    instruction.ip_rel_memory_address(),
                );
            } else if instruction.code() == Code::Mov_r32_imm32 {
                arguments.insert(
                    instruction.op0_register(),
                    u64::from(instruction.immediate32()),
                );
            } else if instruction.code() == Code::Call_rel32_64 {
                let (Some(&version), Some(&tree), Some(&names), Some(&data)) = (
                    arguments.get(&Register::ECX),
                    arguments.get(&Register::RDX),
                    arguments.get(&Register::R8),
                    arguments.get(&Register::R9),
                ) else {
                    arguments.clear();
                    continue;
                };
                if self.names.contains(&names) && self.tables.insert(tree) {
                    if version != 3 {
                        return Err("无法识别 Qt 资源目录格式".into());
                    }
                    for (name, range) in self.read(image, tree, names, data, progress)? {
                        if self
                            .resources
                            .insert(name.clone(), range.clone())
                            .is_some_and(|previous| previous != range)
                        {
                            return Err(format!("资源 {name} 存在不同副本").into());
                        }
                    }
                }
                arguments.clear();
            }
        }
        Ok(())
    }

    fn read(
        &self,
        image: &Image<'_>,
        tree: u64,
        names: u64,
        data: u64,
        progress: &Progress,
    ) -> Result<Resources> {
        let mut resources = Resources::new();
        let mut pending = vec![(0u32, String::new())];
        let mut visited = BTreeSet::new();
        while let Some((index, parent)) = pending.pop() {
            progress.check()?;
            if !visited.insert(index) {
                return Err("Qt 资源目录存在重复节点".into());
            }
            let node = image.data(tree + u64::from(index) * 22, 22)?;
            let offset = u32::from_be_bytes(node[..4].try_into()?);
            let flags = u16::from_be_bytes(node[4..6].try_into()?);
            let path = if index == 0 {
                parent
            } else {
                let name = names + u64::from(offset);
                let length = u16::from_be_bytes(image.data(name, 2)?.try_into()?) as usize;
                let encoded: Vec<_> = image
                    .data(name + 6, length * 2)?
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_be_bytes(*pair))
                    .collect();
                format!("{parent}/{}", String::from_utf16(&encoded)?)
            };
            if flags & 2 != 0 {
                let count = u32::from_be_bytes(node[6..10].try_into()?);
                let first = u32::from_be_bytes(node[10..14].try_into()?);
                let end = first.checked_add(count).ok_or("Qt 资源索引溢出")?;
                image.data(tree + u64::from(first) * 22, count as usize * 22)?;
                pending.extend((first..end).map(|child| (child, path.clone())));
            } else if let Some(name) = self.paths.get(&path) {
                if flags != 0 {
                    return Err(format!("资源 {path} 使用了压缩数据").into());
                }
                let offset = u32::from_be_bytes(node[10..14].try_into()?);
                let address = data + u64::from(offset);
                let size = u32::from_be_bytes(image.data(address, 4)?.try_into()?) as usize;
                image.data(address + 4, size)?;
                let offset = image.offset(address + 4)?;
                resources.insert(name.clone(), offset..offset + size);
            }
        }
        Ok(resources)
    }
}
