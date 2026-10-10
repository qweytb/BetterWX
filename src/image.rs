use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    time::Instant,
};

use iced_x86::{Decoder, DecoderOptions, FastFormatter, Instruction};
use object::read::pe::PeFile64;
use object::read::{Object, ObjectSection};

use crate::{
    Result,
    progress::{FRAME, Progress},
};

pub type Symbols = BTreeMap<String, Vec<u64>>;
pub type References = BTreeMap<u64, Vec<Range<u64>>>;

pub struct Image<'a> {
    file: PeFile64<'a>,
}

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let file = PeFile64::parse(data)?;
        if file.architecture() != object::Architecture::X86_64 {
            return Err("需要 Windows x64 PE 文件".into());
        }
        Ok(Self { file })
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
        addresses: &[u64],
        name: &str,
        progress: &Progress,
    ) -> Result<References> {
        let mut references = References::new();
        if addresses.is_empty() {
            return Ok(references);
        }
        let functions = self.functions()?;
        let targets: BTreeSet<_> = addresses.iter().copied().collect();
        let step = progress.start(
            format!("分析代码引用：{name}"),
            functions.len() as u64,
            "个函数",
        );
        let mut sample = Instant::now();
        let mut formatter = FastFormatter::new();
        for (index, function) in functions.into_iter().enumerate() {
            progress.check()?;
            let bytes = self.data(function.start, (function.end - function.start) as usize)?;
            let mut decoder = Decoder::with_ip(64, bytes, function.start, DecoderOptions::NONE);
            let mut instruction = Instruction::default();
            if sample.elapsed() >= FRAME {
                let first = decoder.decode();
                let mut text = String::new();
                formatter.format(&first, &mut text);
                step.detail(format!(
                    "函数 RVA {:#x}\n{text}",
                    function.start - self.base()
                ));
                decoder.set_position(0)?;
                decoder.set_ip(function.start);
                sample = Instant::now();
            }
            let mut found = BTreeSet::new();
            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);
                if instruction.is_ip_rel_memory_operand() {
                    let address = instruction.ip_rel_memory_address();
                    if targets.contains(&address) {
                        found.insert(address);
                    }
                }
            }
            for address in found {
                references
                    .entry(address)
                    .or_default()
                    .push(function.clone());
            }
            step.set(index as u64 + 1);
        }
        step.finish(format!("找到 {} 个目标的引用", references.len()));
        Ok(references)
    }

    fn functions(&self) -> Result<Vec<Range<u64>>> {
        let section = self
            .file
            .section_by_name(".pdata")
            .ok_or("找不到异常展开表")?;
        let data = section.data()?;
        let entries = data.as_chunks::<12>().0;
        let mut functions = Vec::new();
        for entry in entries {
            let start = u32::from_le_bytes(entry[..4].try_into()?) as u64;
            let end = u32::from_le_bytes(entry[4..8].try_into()?) as u64;
            if start < end {
                functions.push(self.base() + start..self.base() + end);
            }
        }
        Ok(functions)
    }
}
