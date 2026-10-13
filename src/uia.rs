use std::collections::BTreeSet;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Register};

use crate::{
    Result,
    feature::{Edit, Feature, Target},
    image::{Image, References, Symbols, assembly},
    progress::Progress,
};

const KEY: &str = "accessibility_enable_scheme\0";

pub const FEATURE: Feature = Feature {
    id: "uia",
    name: "开放无障碍访问",
    description: "开放微信的原生无障碍控件查询",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let keys = image.find(KEY.as_bytes(), progress)?;
    if keys.is_empty() {
        return Err("找不到无障碍配置键".into());
    }
    Ok(Symbols::from([(KEY.to_owned(), keys)]))
}

fn scan(
    image: &Image<'_>,
    symbols: &Symbols,
    references: &References,
    progress: &Progress,
) -> Result<Vec<Edit>> {
    let address = locate(image, symbols, references, progress)?;
    let offset = image.offset(address)?;
    let step = progress.activity("准备补丁");
    let edits = vec![Edit {
        range: offset..offset + 1,
        bytes: vec![0xc3],
    }];
    let instruction =
        Decoder::with_ip(64, image.data(address, 16)?, address, DecoderOptions::NONE).decode();
    step.finish(format!(
        "RVA 0x{:08X}；{:02X} → C3；{} → ret",
        address - image.base(),
        image.data(address, 1)?[0],
        assembly(image.data(address, instruction.len())?, address),
    ));
    Ok(edits)
}

fn locate(
    image: &Image<'_>,
    symbols: &Symbols,
    references: &References,
    progress: &Progress,
) -> Result<u64> {
    let mut setters = BTreeSet::new();
    let mut calls = BTreeSet::new();
    for function in symbols[KEY]
        .iter()
        .filter_map(|address| references.get(*address))
        .flatten()
    {
        progress.check()?;
        let bytes = image.data(function.start, (function.end - function.start) as usize)?;
        let mut decoder = Decoder::with_ip(64, bytes, function.start, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if matches!(
                instruction.code(),
                Code::Call_rel32_64 | Code::Jmp_rel32_64 | Code::Jmp_rel8_64
            ) {
                calls.insert(instruction.near_branch_target());
            }
        }
    }
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
        "RVA 0x{:08X} → byte [RVA 0x{:08X}]；初值 01",
        setter - image.base(),
        flag - image.base()
    ));
    Ok(setter)
}
