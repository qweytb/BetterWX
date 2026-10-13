use std::{
    cell::OnceCell,
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    time::Instant,
};

use iced_x86::{
    Decoder, DecoderOptions, FastFormatter, Instruction, OpKind, code_asm::CodeAssembler,
};
use object::endian::LittleEndian as LE;
use object::pe;
use object::read::pe::PeFile64;
use object::read::{Object, ObjectSection};

use crate::{
    Result,
    feature::Edit,
    progress::{FRAME, Progress},
    xlog::Records,
};

pub type Symbols = BTreeMap<String, Vec<u64>>;
pub type References = BTreeMap<u64, Vec<Range<u64>>>;

pub fn functions(
    name: &str,
    symbols: &Symbols,
    references: &References,
) -> BTreeMap<u64, Range<u64>> {
    symbols[name]
        .iter()
        .filter_map(|address| references.get(address))
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
                if instruction.op0_kind() == OpKind::NearBranch64 {
                    let address = instruction.near_branch_target();
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
