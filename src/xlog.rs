use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Result,
    image::{Image, Symbols},
    progress::Progress,
};

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

pub fn find(image: &Image<'_>, names: &[&str], progress: &Progress) -> Result<Symbols> {
    let sections = image.sections()?;
    let total = sections.iter().map(|(_, data)| data.len() as u64).sum();
    let step = progress.start("解析日志字符串", total, "字节");
    let mut records: BTreeMap<Vec<u8>, Vec<u64>> = BTreeMap::new();
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

    let anchor = names
        .iter()
        .max_by_key(|name| name.len())
        .ok_or("缺少日志符号名称")?;
    let step = progress.activity("恢复日志符号");
    step.detail(names.join("\n"));
    let mut streams = BTreeSet::new();
    for ciphertext in records.keys().filter(|value| value.len() == anchor.len()) {
        progress.check()?;
        let stream: Vec<_> = ciphertext
            .iter()
            .zip(anchor.bytes())
            .map(|(left, right)| left ^ right)
            .collect();
        if names.iter().all(|name| {
            let encoded: Vec<_> = name
                .bytes()
                .zip(&stream)
                .map(|(left, right)| left ^ right)
                .collect();
            records.contains_key(&encoded)
        }) {
            streams.insert(stream);
        }
    }
    let [stream] = &streams.into_iter().collect::<Vec<_>>()[..] else {
        return Err("无法唯一恢复日志符号的解码参数".into());
    };
    let addresses = names
        .iter()
        .map(|name| {
            let encoded: Vec<_> = name
                .bytes()
                .zip(stream)
                .map(|(left, right)| left ^ right)
                .collect();
            ((*name).to_owned(), records[&encoded].clone())
        })
        .collect();
    step.finish(format!("找到 {} 个日志符号", names.len()));
    Ok(addresses)
}
