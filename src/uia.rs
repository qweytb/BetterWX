use std::collections::BTreeSet;
use std::time::Instant;

use iced_x86::{Code, Decoder, DecoderOptions, FastFormatter, Instruction, Register};

use crate::{
    Result,
    feature::{Edit, Feature},
    image::Image,
    progress::{FRAME, Progress},
};

pub const FEATURE: Feature = Feature {
    id: "uia",
    name: "UI 自动化",
    description: "开放微信的原生无障碍控件查询",
    scan,
};

fn scan(data: &[u8], progress: &Progress) -> Result<Vec<Edit>> {
    let image = Image::parse(data, progress)?;
    let offset = locate(&image, progress)?;
    let step = progress.activity("准备 UI 自动化补丁");
    let edits = vec![Edit {
        range: offset..offset + 1,
        bytes: vec![0xc3],
    }];
    step.finish(format!("文件位置 {offset:#x}：{:02X} → C3", data[offset]));
    Ok(edits)
}

fn locate(image: &Image<'_>, progress: &Progress) -> Result<usize> {
    let keys = image.find(b"accessibility_enable_scheme\0", progress)?;
    if keys.is_empty() {
        return Err("找不到无障碍配置键".into());
    }

    let functions = image.functions(progress)?;
    let step = progress.start("解码 x64 指令与配置引用", functions.len() as u64, "个函数");
    let mut setters = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut sample = Instant::now();
    let mut formatter = FastFormatter::new();
    for (index, function) in functions.iter().enumerate() {
        progress.check()?;
        let bytes = image.data(function.start, (function.end - function.start) as usize)?;
        let mut decoder = Decoder::with_ip(64, bytes, function.start, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        if sample.elapsed() >= FRAME {
            let first = decoder.decode();
            let mut text = String::new();
            formatter.format(&first, &mut text);
            step.detail(format!(
                "函数 RVA {:#x}\n{text}",
                function.start - image.base()
            ));
            decoder.set_position(0)?;
            decoder.set_ip(function.start);
            sample = Instant::now();
        }
        let mut targets = BTreeSet::new();
        let mut references_key = false;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            references_key |= instruction.is_ip_rel_memory_operand()
                && keys.contains(&instruction.ip_rel_memory_address());
            if matches!(
                instruction.code(),
                Code::Call_rel32_64 | Code::Jmp_rel32_64 | Code::Jmp_rel8_64
            ) {
                targets.insert(instruction.near_branch_target());
            }
        }
        if references_key {
            calls.extend(targets);
        }
        step.set(index as u64 + 1);
    }
    step.finish(format!("找到 {} 个待分析的目标函数", calls.len()));
    let step = progress.activity("定位无障碍开关");
    for target in calls {
        progress.check()?;
        let bytes = image.data(target, 16)?;
        let mut decoder = Decoder::with_ip(64, bytes, target, DecoderOptions::NONE);
        let store = decoder.decode();
        let ret = decoder.decode();
        step.detail(format!("目标函数 RVA {:#x}", target - image.base()));
        if store.code() == Code::Mov_rm8_r8
            && store.op1_register() == Register::CL
            && store.is_ip_rel_memory_operand()
            && ret.code() == Code::Retnq
        {
            setters.insert((target, store.ip_rel_memory_address()));
        }
    }
    let [(setter, flag)] = setters.into_iter().collect::<Vec<_>>()[..] else {
        return Err("无法唯一定位无障碍开关写入函数".into());
    };
    if image.data(flag, 1)? != [1] {
        return Err("无障碍开关的初始值与预期不同".into());
    }
    step.finish(format!(
        "写入函数 RVA {:#x}，开关 RVA {:#x}",
        setter - image.base(),
        flag - image.base()
    ));
    image.offset(setter)
}
