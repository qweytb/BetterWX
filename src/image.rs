use std::{cell::OnceCell, collections::BTreeMap, ffi::CStr, ops::Range};

use iced_x86::{
    Decoder, DecoderOptions, FastFormatter, Instruction, OpKind, code_asm::CodeAssembler,
};
use object::endian::LittleEndian as LE;
use object::pe;
use object::read::pe::PeFile64;
use object::read::{ExportTarget, NameOrOrdinal, Object, ObjectSection};

use crate::{Result, feature::Edit, progress::Progress, xlog::Records};

pub type Symbols = BTreeMap<String, Vec<u64>>;

pub fn assembly(bytes: &[u8], address: u64) -> String {
    let mut formatter = FastFormatter::new();
    Decoder::with_ip(64, bytes, address, DecoderOptions::NONE)
        .into_iter()
        .map(|instruction| {
            let mut text = String::new();
            formatter.format(&instruction, &mut text);
            text
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub struct References {
    functions: Vec<Range<u64>>,
    entries: Vec<(u64, usize)>,
}

impl References {
    pub fn get(&self, address: u64) -> Option<impl Iterator<Item = &Range<u64>>> {
        let start = self.entries.partition_point(|entry| entry.0 < address);
        let end = start + self.entries[start..].partition_point(|entry| entry.0 == address);
        (start != end).then(|| {
            self.entries[start..end]
                .iter()
                .map(|entry| &self.functions[entry.1])
        })
    }
}

pub fn functions(
    name: &str,
    symbols: &Symbols,
    references: &References,
) -> BTreeMap<u64, Range<u64>> {
    symbols[name]
        .iter()
        .filter_map(|address| references.get(*address))
        .flatten()
        .map(|function| (function.start, function.clone()))
        .collect()
}

pub struct Image<'a> {
    file: PeFile64<'a>,
    pub logs: OnceCell<std::result::Result<Records, String>>,
}

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let file = PeFile64::parse(data)?;
        if file.architecture() != object::Architecture::X86_64 {
            return Err("需要 Windows x64 PE 文件".into());
        }
        Ok(Self {
            file,
            logs: OnceCell::new(),
        })
    }

    pub fn base(&self) -> u64 {
        self.file.relative_address_base()
    }

    pub fn sections(&self) -> Result<Vec<(u64, &'a [u8])>> {
        self.file
            .sections()
            .map(|section| Ok((section.address(), section.data()?)))
            .collect()
    }

    pub fn data(&self, address: u64, size: usize) -> Result<&'a [u8]> {
        for section in self.file.sections() {
            if let Some(offset) = address.checked_sub(section.address()) {
                let data = section.data()?;
                if let Some(end) = (offset as usize).checked_add(size)
                    && let Some(bytes) = data.get(offset as usize..end)
                {
                    return Ok(bytes);
                }
            }
        }
        Err(format!("地址 {address:#x} 的数据不在文件中").into())
    }

    pub fn offset(&self, address: u64) -> Result<usize> {
        for section in self.file.sections() {
            if let Some(offset) = address.checked_sub(section.address())
                && let Some((start, size)) = section.file_range()
                && offset < size
            {
                return Ok((start + offset) as usize);
            }
        }
        Err(format!("地址 {address:#x} 没有对应的文件位置").into())
    }

    pub fn instructions(&self, function: &Range<u64>) -> Result<Vec<Instruction>> {
        let bytes = self.data(function.start, (function.end - function.start) as usize)?;
        Ok(
            Decoder::with_ip(64, bytes, function.start, DecoderOptions::NONE)
                .into_iter()
                .collect(),
        )
    }

    pub fn unwind_info(&self, address: u64) -> Result<u64> {
        let entry = self
            .unwind()?
            .iter()
            .find(|entry| {
                self.base()
                    + u32::from_le_bytes(entry[..4].try_into().expect("function RVA")) as u64
                    == address
            })
            .ok_or("找不到函数展开记录")?;
        Ok(self.base() + u32::from_le_bytes(entry[8..].try_into()?) as u64)
    }

    pub fn replace_function(
        &self,
        function: &Range<u64>,
        code: &mut CodeAssembler,
        unwind: &[u8],
    ) -> Result<Vec<Edit>> {
        let mut bytes = code.assemble(function.start)?;
        let size = usize::try_from(function.end - function.start)?;
        if bytes.len() > size {
            return Err("原函数的指令空间不足".into());
        }
        bytes.resize(size, 0xcc);
        let offset = self.offset(function.start)?;
        let mut edits = vec![Edit {
            range: offset..offset + size,
            bytes,
        }];
        let address = self.unwind_info(function.start)?;
        if self.data(address, unwind.len())? != unwind {
            let header = self.data(address, 4)?;
            let size = (4 + usize::from(header[2]) * 2).next_multiple_of(4);
            let shared = self
                .unwind()?
                .iter()
                .filter(|entry| {
                    u32::from_le_bytes(entry[8..].try_into().expect("unwind RVA")) as u64
                        == address - self.base()
                })
                .count();
            if header[0] >> 3 != 0 || shared != 1 || unwind.len() > size {
                return Err("原函数的展开信息无法原位改写".into());
            }
            let offset = self.offset(address)?;
            let mut bytes = unwind.to_vec();
            bytes.resize(size, 0);
            edits.push(Edit {
                range: offset..offset + size,
                bytes,
            });
        }
        Ok(edits)
    }

    pub fn find(&self, value: &[u8], progress: &Progress) -> Result<Vec<u64>> {
        let sections = self.sections()?;
        let step = progress.activity("查找配置字符串");
        let target = String::from_utf8_lossy(value.strip_suffix(&[0]).unwrap_or(value));
        step.detail(target.to_string());
        let mut addresses = Vec::new();
        for (address, data) in sections {
            progress.check()?;
            step.detail(format!("{target}\n搜索 RVA {:#x}", address - self.base()));
            addresses.extend(
                memchr::memmem::find_iter(data, value).map(|offset| address + offset as u64),
            );
        }
        step.finish(if addresses.is_empty() {
            format!("{target}：未找到")
        } else {
            format!(
                "{target} → {}",
                addresses
                    .iter()
                    .map(|address| format!("RVA {:#x}", address - self.base()))
                    .collect::<Vec<_>>()
                    .join("、")
            )
        });
        Ok(addresses)
    }

    pub fn references(
        &self,
        name: &str,
        labels: BTreeMap<u64, String>,
        progress: &Progress,
    ) -> Result<References> {
        let mut exports = BTreeMap::new();
        for export in self.file.exports()? {
            let export = export?;
            if let (NameOrOrdinal::Name(name), ExportTarget::Address { address }) =
                (export.name(), export.target())
            {
                exports.insert(address, String::from_utf8_lossy(name).into_owned());
            }
        }
        let functions = self.functions()?;
        let mut entries = Vec::new();
        let step = progress.start("分析代码引用", functions.len() as u64, "函数");
        step.detail(name);
        for (index, function) in functions.iter().enumerate() {
            progress.check()?;
            let bytes = self.data(function.start, (function.end - function.start) as usize)?;
            let mut decoder = Decoder::with_ip(64, bytes, function.start, DecoderOptions::NONE);
            let mut instruction = Instruction::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);
                let target = if instruction.is_ip_rel_memory_operand() {
                    instruction.ip_rel_memory_address()
                } else if instruction.op0_kind() == OpKind::NearBranch64 {
                    instruction.near_branch_target()
                } else {
                    continue;
                };
                entries.push((target, index));
                let symbol = labels.get(&target);
                let sampled = step.sample();
                if sampled || symbol.is_some() {
                    let bytes = self.data(instruction.ip(), instruction.len())?;
                    let label = exports.get(&function.start).or(symbol);
                    let mut detail = name.to_owned();
                    if let Some(symbol) = label {
                        detail.push_str(&format!("；{symbol}"));
                    }
                    detail.push_str(&format!(
                        "；RVA 0x{:08X}；{} → {}",
                        instruction.ip() - self.base(),
                        bytes
                            .iter()
                            .map(|byte| format!("{byte:02X}"))
                            .collect::<Vec<_>>()
                            .join(" "),
                        assembly(bytes, instruction.ip()),
                    ));
                    if let Some(symbol) = symbol.or_else(|| exports.get(&target)) {
                        if Some(symbol) != label {
                            detail.push_str(&format!("；{symbol}"));
                        }
                    } else if let Some(value) = self.string(target) {
                        detail.push_str(&format!("；{value:?}"));
                    }
                    step.detail(detail);
                }
            }
            step.set(index as u64 + 1);
        }
        step.finish(format!(
            "{name}；{} 函数；{} 引用",
            functions.len(),
            entries.len()
        ));
        let step = progress.activity("排序引用索引");
        let mut comparisons = 0_u64;
        entries.sort_unstable_by(|left, right| {
            comparisons += 1;
            let order = left.cmp(right);
            if step.sample() {
                step.detail(format!(
                    "{name}；{comparisons} 次比较\n\
                     (0x{:X}, {}) {} (0x{:X}, {})",
                    left.0,
                    left.1,
                    match order {
                        std::cmp::Ordering::Less => "<",
                        std::cmp::Ordering::Equal => "=",
                        std::cmp::Ordering::Greater => ">",
                    },
                    right.0,
                    right.1,
                ));
            }
            order
        });
        progress.check()?;
        step.finish(format!(
            "{name}；{comparisons} 次比较；{} 引用",
            entries.len()
        ));
        let total = entries.len();
        let step = progress.start("合并重复引用", total as u64, "引用");
        let mut processed = usize::from(total != 0);
        let mut duplicates = 0;
        let mut targets = processed;
        entries.dedup_by(|left, right| {
            processed += 1;
            targets += usize::from(left.0 != right.0);
            let equal = left == right;
            duplicates += usize::from(equal);
            if step.sample() {
                step.set(processed as u64);
                step.detail(format!(
                    "{name}；(0x{:X}, {})；重复 {duplicates}；目标 {targets}",
                    left.0, left.1,
                ));
            }
            equal
        });
        step.finish(format!(
            "{name}；{} → {} 引用；{targets} 目标",
            total,
            entries.len()
        ));
        Ok(References { functions, entries })
    }

    fn string(&self, address: u64) -> Option<&str> {
        for section in self.file.sections() {
            let Some(offset) = address.checked_sub(section.address()) else {
                continue;
            };
            let Some(data) = section.data().ok()?.get(offset as usize..) else {
                continue;
            };
            let text = CStr::from_bytes_until_nul(data).ok()?.to_str().ok()?;
            if text.chars().count() > 1 && text.chars().all(|character| !character.is_control()) {
                return Some(text);
            }
        }
        None
    }

    fn unwind(&self) -> Result<&'a [[u8; 12]]> {
        let directory = self
            .file
            .data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            .ok_or("找不到异常展开目录")?;
        Ok(self
            .data(
                self.base() + u64::from(directory.virtual_address.get(LE)),
                directory.size.get(LE) as usize,
            )?
            .as_chunks::<12>()
            .0)
    }

    pub fn function(&self, address: u64) -> Result<Option<Range<u64>>> {
        let entries = self.unwind()?;
        let index = entries.partition_point(|entry| {
            let start = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            self.base() + start as u64 <= address
        });
        let Some(entry) = index.checked_sub(1).and_then(|index| entries.get(index)) else {
            return Ok(None);
        };
        let start = self.base() + u32::from_le_bytes(entry[..4].try_into()?) as u64;
        let end = self.base() + u32::from_le_bytes(entry[4..8].try_into()?) as u64;
        let function = start..end;
        Ok(function.contains(&address).then_some(function))
    }

    fn functions(&self) -> Result<Vec<Range<u64>>> {
        let mut functions = Vec::new();
        for entry in self.unwind()? {
            let start = u32::from_le_bytes(entry[..4].try_into()?) as u64;
            let end = u32::from_le_bytes(entry[4..8].try_into()?) as u64;
            if start < end {
                functions.push(self.base() + start..self.base() + end);
            }
        }
        Ok(functions)
    }
}
