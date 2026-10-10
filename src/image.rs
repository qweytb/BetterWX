use std::ops::Range;

use object::read::pe::PeFile64;
use object::read::{Object, ObjectSection};

use crate::{Result, progress::Progress};

pub struct Image<'a> {
    file: PeFile64<'a>,
}

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8], progress: &Progress) -> Result<Self> {
        let step = progress.activity("解析 PE 映像");
        let file = PeFile64::parse(data)?;
        if file.architecture() != object::Architecture::X86_64 {
            return Err("需要 Windows x64 PE 文件".into());
        }
        let mut names = Vec::new();
        for section in file.sections() {
            names.push(section.name()?);
        }
        step.finish(format!(
            "AMD64 / PE32+，{} 个节：{}",
            names.len(),
            names.join("、")
        ));
        Ok(Self { file })
    }

    pub fn base(&self) -> u64 {
        self.file.relative_address_base()
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
        let mut sections = Vec::new();
        for section in self.file.sections() {
            sections.push((section.address(), section.data()?));
        }
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

    pub fn functions(&self, progress: &Progress) -> Result<Vec<Range<u64>>> {
        let section = self
            .file
            .section_by_name(".pdata")
            .ok_or("找不到异常展开表")?;
        let data = section.data()?;
        let entries = data.as_chunks::<12>().0;
        let step = progress.start("解析异常展开表", entries.len() as u64, "条");
        let mut functions = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            progress.check()?;
            let start = u32::from_le_bytes(entry[..4].try_into()?) as u64;
            let end = u32::from_le_bytes(entry[4..8].try_into()?) as u64;
            if start < end {
                functions.push(self.base() + start..self.base() + end);
            }
            step.set(index as u64 + 1);
        }
        step.finish(format!("取得 {} 个函数范围", functions.len()));
        Ok(functions)
    }
}
