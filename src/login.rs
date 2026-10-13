use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Code, Instruction, OpKind, Register};

use crate::{
    Result,
    feature::{Edit, Feature, Target},
    image::{Image, References, Symbols, functions},
    progress::Progress,
    xlog,
};

const INIT: &str = "mmui::LoginViewModel::Init()::(lambda)::operator()";
const BUTTON: &str = "mmui::LoginWindow::initActions()::(lambda)::operator()";
const REQUEST: &str = "kernel::service::LoginService::PushLoginURL";

pub const FEATURE: Feature = Feature {
    id: "login",
    name: "自动点击登录",
    description: "取得已有账号信息后自动触发登录",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    xlog::find(image, &[INIT, BUTTON, REQUEST], progress)
}

fn calls(instructions: &[Instruction]) -> BTreeMap<u64, Vec<u64>> {
    let mut calls: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for pair in instructions.windows(2) {
        if matches!(pair[0].code(), Code::Mov_r64_rm64 | Code::Mov_rm64_r64)
            && pair[0].op0_register() == Register::RCX
            && pair[0].op1_kind() == OpKind::Register
            && matches!(
                pair[0].op1_register(),
                Register::RBX
                    | Register::RBP
                    | Register::RSI
                    | Register::RDI
                    | Register::R12
                    | Register::R13
                    | Register::R14
                    | Register::R15
            )
            && pair[1].code() == Code::Call_rel32_64
        {
            calls
                .entry(pair[1].near_branch_target())
                .or_default()
                .push(pair[1].ip());
        }
    }
    calls
}

fn scan(
    image: &Image<'_>,
    symbols: &Symbols,
    references: &References,
    progress: &Progress,
) -> Result<Vec<Edit>> {
    let step = progress.activity("定位登录流程");
    let [init] = &functions(INIT, symbols, references)
        .into_values()
        .collect::<Vec<_>>()[..]
    else {
        return Err("无法唯一定位账号信息初始化回调".into());
    };
    let [request] = &functions(REQUEST, symbols, references)
        .into_values()
        .collect::<Vec<_>>()[..]
    else {
        return Err("无法唯一定位登录请求函数".into());
    };
    let mut targets = BTreeSet::new();
    for function in functions(BUTTON, symbols, references).into_values() {
        progress.check()?;
        for instruction in image.instructions(&function)? {
            if matches!(instruction.code(), Code::Jmp_rel32_64 | Code::Jmp_rel8_64)
                && !function.contains(&instruction.near_branch_target())
            {
                targets.insert(instruction.near_branch_target());
            }
        }
    }
    let mut handlers = BTreeMap::new();
    for target in targets {
        progress.check()?;
        let Some(function) = image.function(target)? else {
            continue;
        };
        if function.start == target
            && image.instructions(&function)?.iter().any(|instruction| {
                instruction.code() == Code::Call_rel32_64
                    && instruction.near_branch_target() == request.start
            })
        {
            handlers.insert(target, function);
        }
    }
    let [handler] = &handlers.into_values().collect::<Vec<_>>()[..] else {
        return Err("无法唯一定位登录按钮处理函数".into());
    };
    let initialized = calls(&image.instructions(init)?);
    let login = calls(&image.instructions(handler)?);
    let sites: Vec<_> = initialized
        .iter()
        .filter(|(target, _)| login.contains_key(target))
        .flat_map(|(target, sites)| sites.iter().map(move |site| (*site, *target)))
        .collect();
    let [(site, notify)] = sites[..] else {
        return Err("无法唯一定位初始化完成后的界面通知".into());
    };
    step.finish(format!(
        "初始化 RVA {:#x}，登录处理 RVA {:#x}",
        init.start - image.base(),
        handler.start - image.base(),
    ));
    let step = progress.activity("准备补丁");
    // The login handler already publishes the new view state.
    let displacement = i32::try_from(handler.start as i64 - (site + 5) as i64)?;
    let offset = image.offset(site + 1)?;
    step.finish(format!(
        "调用 RVA {:#x}：{:#x} → {:#x}",
        site - image.base(),
        notify - image.base(),
        handler.start - image.base(),
    ));
    Ok(vec![Edit {
        range: offset..offset + 4,
        bytes: displacement.to_le_bytes().to_vec(),
    }])
}
