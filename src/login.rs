use std::{
    collections::{BTreeMap, btree_map::Entry},
    ops::Range,
};

use iced_x86::{Code, Instruction, OpKind, Register};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Target},
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

struct Scan {
    symbols: Symbols,
    handlers: BTreeMap<u64, Vec<Instruction>>,
    emitted: bool,
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan {
        symbols,
        handlers: BTreeMap::new(),
        emitted: false,
    })
}

impl Analysis for Scan {
    fn visit(
        &mut self,
        image: &Image<'_>,
        function: &Range<u64>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Edit>> {
        if functions(BUTTON, &self.symbols, references).contains_key(&function.start) {
            for instruction in image.instructions(function)? {
                if !matches!(instruction.code(), Code::Jmp_rel32_64 | Code::Jmp_rel8_64)
                    || function.contains(&instruction.near_branch_target())
                {
                    continue;
                }
                let target = instruction.near_branch_target();
                if let Entry::Vacant(entry) = self.handlers.entry(target)
                    && let Some(function) = image.function(target)?
                    && function.start == target
                {
                    entry.insert(image.instructions(&function)?);
                }
            }
        }
        let init = functions(INIT, &self.symbols, references);
        let request = functions(REQUEST, &self.symbols, references);
        if init.len() > 1 {
            return Err("无法唯一定位账号信息初始化回调".into());
        }
        if request.len() > 1 {
            return Err("无法唯一定位登录请求函数".into());
        }
        let (Some(init), Some(request)) = (init.first_key_value(), request.first_key_value())
        else {
            return Ok(Vec::new());
        };
        let handlers: Vec<_> = self
            .handlers
            .iter()
            .filter(|(_, instructions)| {
                instructions.iter().any(|instruction| {
                    instruction.code() == Code::Call_rel32_64
                        && instruction.near_branch_target() == request.1.start
                })
            })
            .collect();
        if handlers.len() > 1 {
            return Err("无法唯一定位登录按钮处理函数".into());
        }
        let Some(&(handler, instructions)) = handlers.first() else {
            return Ok(Vec::new());
        };
        if self.emitted {
            return Ok(Vec::new());
        }
        let initialized = calls(&image.instructions(init.1)?);
        let login = calls(instructions);
        let sites: Vec<_> = initialized
            .iter()
            .filter(|(target, _)| login.contains_key(target))
            .flat_map(|(target, sites)| sites.iter().map(move |site| (*site, *target)))
            .collect();
        let [(site, notify)] = sites[..] else {
            return Err("无法唯一定位初始化完成后的界面通知".into());
        };
        let step = progress.activity("准备补丁");
        // The login handler already publishes the new view state.
        let displacement = i32::try_from(*handler as i64 - (site + 5) as i64)?;
        let offset = image.offset(site + 1)?;
        step.finish(format!(
            "RVA 0x{:08X}；call 0x{:08X} → call 0x{:08X}",
            site - image.base(),
            notify - image.base(),
            handler - image.base(),
        ));
        self.emitted = true;
        Ok(vec![Edit {
            range: offset..offset + 4,
            bytes: displacement.to_le_bytes().to_vec(),
        }])
    }

    fn finish(
        self: Box<Self>,
        _image: &Image<'_>,
        references: &References,
        _progress: &Progress,
    ) -> Result<Vec<Edit>> {
        if functions(INIT, &self.symbols, references).len() != 1 {
            return Err("无法唯一定位账号信息初始化回调".into());
        }
        if functions(REQUEST, &self.symbols, references).len() != 1 {
            return Err("无法唯一定位登录请求函数".into());
        }
        if !self.emitted {
            return Err("无法唯一定位登录按钮处理函数".into());
        }
        Ok(Vec::new())
    }
}
