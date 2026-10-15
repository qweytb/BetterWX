use std::{collections::BTreeSet, ops::Range};

use iced_x86::{Code, Decoder, DecoderOptions, Register};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
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
    let keys = image.find(KEY, KEY.as_bytes(), progress)?;
    if keys.is_empty() {
        return Err("找不到无障碍配置键".into());
    }
    Ok(Symbols::from([(KEY.to_owned(), keys)]))
}

struct Scan {
    calls: BTreeSet<u64>,
    setters: BTreeSet<(u64, u64)>,
    emitted: bool,
}

fn scan(_symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan {
        calls: BTreeSet::new(),
        setters: BTreeSet::new(),
        emitted: false,
    })
}

impl Analysis for Scan {
    fn visit(
        &mut self,
        image: &Image<'_>,
        function: &Range<u64>,
        _references: &References,
        progress: &Progress,
    ) -> Result<Vec<Edit>> {
        for instruction in image.instructions(function)? {
            if !matches!(
                instruction.code(),
                Code::Call_rel32_64 | Code::Jmp_rel32_64 | Code::Jmp_rel8_64
            ) {
                continue;
            }
            let target = instruction.near_branch_target();
            if !self.calls.insert(target) {
                continue;
            }
            progress.check()?;
            let bytes = image.data(target, 16)?;
            let mut decoder = Decoder::with_ip(64, bytes, target, DecoderOptions::NONE);
            let store = decoder.decode();
            let ret = decoder.decode();
            if store.code() == Code::Mov_rm8_r8
                && store.op1_register() == Register::CL
                && store.is_ip_rel_memory_operand()
                && ret.code() == Code::Retnq
            {
                self.setters.insert((target, store.ip_rel_memory_address()));
            }
        }
        if self.setters.len() > 1 {
            return Err("无法唯一定位无障碍开关写入函数".into());
        }
        let Some(&(address, flag)) = self.setters.first() else {
            return Ok(Vec::new());
        };
        if self.emitted {
            return Ok(Vec::new());
        }
        if image.data(flag, 1)? != [1] {
            return Err("无障碍开关的初始值与预期不同".into());
        }
        let step = progress.activity("准备补丁");
        let offset = image.offset(address)?;
        let instruction =
            Decoder::with_ip(64, image.data(address, 16)?, address, DecoderOptions::NONE).decode();
        step.finish(format!(
            "RVA 0x{:08X}；{:02X} → C3；{} → ret",
            address - image.base(),
            image.data(address, 1)?[0],
            assembly(image.data(address, instruction.len())?, address),
        ));
        self.emitted = true;
        Ok(vec![Edit {
            range: offset..offset + 1,
            bytes: vec![0xc3],
        }])
    }

    fn finish(
        self: Box<Self>,
        _image: &Image<'_>,
        _references: &References,
        _progress: &Progress,
    ) -> Result<Vec<Mode>> {
        if !self.emitted {
            return Err("无法唯一定位无障碍开关写入函数".into());
        }
        Ok(vec![Mode::enabled(Vec::new())])
    }
}
