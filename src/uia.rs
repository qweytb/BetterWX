use std::collections::BTreeSet;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Register};

use crate::{
    Result,
    feature::{Edit, Edits, Feature},
    image::Image,
    progress::Progress,
    store::Store,
};

pub const FEATURE: Feature = Feature {
    id: "uia",
    name: "开放无障碍访问",
    description: "开放微信的原生无障碍控件查询",
    files: &[],
    scan,
};

fn scan(store: &mut Store, progress: &Progress) -> Result<Edits> {
    let target = store.target.clone();
    let file = store.load(&target, progress)?;
    let image = Image::parse(&file.original, progress)?;
    let offset = locate(&image, progress)?;
    let step = progress.activity(format!("准备补丁：{}", FEATURE.name));
    let edits = vec![Edit {
        range: offset..offset + 1,
        bytes: vec![0xc3],
    }];
    step.finish(format!(
        "文件位置 {offset:#x}：{:02X} → C3",
        file.original[offset]
    ));
    Ok(Edits::from([(target, edits)]))
}

fn locate(image: &Image<'_>, progress: &Progress) -> Result<usize> {
    let keys = image.find(b"accessibility_enable_scheme\0", progress)?;
    if keys.is_empty() {
        return Err("找不到无障碍配置键".into());
    }

    let references = image.references(&keys, progress)?;
    let mut setters = BTreeSet::new();
    let mut calls = BTreeSet::new();
    for function in references.values().flatten() {
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
        "写入函数 RVA {:#x}，开关 RVA {:#x}",
        setter - image.base(),
        flag - image.base()
    ));
    image.offset(setter)
}
