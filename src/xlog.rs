use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Result,
    image::{Image, Symbols},
    progress::Progress,
};

pub type Records = BTreeMap<Vec<u8>, Vec<u64>>;

fn decode(data: &[u8]) -> Option<Vec<u8>> {
    data.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            Some((high * 16 + low) as u8)
        })
        .collect()
}

fn parse(image: &Image<'_>, progress: &Progress) -> Result<Records> {
    let sections = image.sections()?;
    let total = sections.iter().map(|(_, data)| data.len() as u64).sum();
    let step = progress.start("解析日志字符串", total, "字节");
    let mut records = Records::new();
    let mut completed = 0;
    for (address, data) in sections {
        progress.check()?;
        step.detail(format!("搜索 RVA {:#x}", address - image.base()));
        for start in memchr::memchr_iter(0xa1, data) {
            let Some(header) = data.get(start..start + 6) else {
                continue;
            };
            if header[5] != 0xb1 {
                continue;
            }
            let Some(length) = decode(&header[1..5]) else {
                continue;
            };
            let length = u16::from_le_bytes([length[0], length[1]]) as usize;
            let end = start + 6 + length * 2;
            if data.get(end) != Some(&0xc1) {
                continue;
            }
            if let Some(ciphertext) = decode(&data[start + 6..end]) {
                records
                    .entry(ciphertext)
                    .or_default()
                    .push(address + start as u64);
            }
        }
        completed += data.len() as u64;
        step.set(completed);
    }
    step.finish(format!("取得 {} 条日志字符串", records.len()));
    Ok(records)
}

pub fn find(image: &Image<'_>, names: &[&str], progress: &Progress) -> Result<Symbols> {
    let records = image
        .logs
        .get_or_init(|| parse(image, progress).map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| error.clone())?;
    if names.is_empty() {
        return Err("缺少日志符号名称".into());
    }
    let step = progress.activity("恢复日志符号");
    step.detail(names.join("\n"));
    let mut streams = BTreeSet::new();
    let mut best = 0;
    for anchor in names {
        for ciphertext in records.keys().filter(|value| value.len() == anchor.len()) {
            progress.check()?;
            let stream: Vec<_> = ciphertext
                .iter()
                .zip(anchor.bytes())
                .map(|(left, right)| left ^ right)
                .collect();
            let matched = names
                .iter()
                .filter(|name| {
                    if name.len() > stream.len() {
                        return false;
                    }
                    let encoded: Vec<_> = name
                        .bytes()
                        .zip(&stream)
                        .map(|(left, right)| left ^ right)
                        .collect();
                    records.contains_key(&encoded)
                })
                .count();
            if matched > best {
                best = matched;
                streams.clear();
            }
            if matched == best {
                streams.insert(stream);
            }
        }
    }
    let [stream] = &streams.into_iter().collect::<Vec<_>>()[..] else {
        return Err("无法唯一恢复日志符号的解码参数".into());
    };
    let addresses = names
        .iter()
        .map(|name| {
            if name.len() > stream.len() {
                return Err(format!("日志符号无法完整解码：{name}").into());
            }
            let encoded: Vec<_> = name
                .bytes()
                .zip(stream)
                .map(|(left, right)| left ^ right)
                .collect();
            let addresses = records
                .get(&encoded)
                .ok_or_else(|| format!("找不到日志符号：{name}"))?;
            Ok(((*name).to_owned(), addresses.clone()))
        })
        .collect::<Result<_>>()?;
    step.finish(format!("找到 {} 个日志符号", names.len()));
    Ok(addresses)
}
