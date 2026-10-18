use std::ops::Range;

use iced_x86::{Code, Instruction, OpKind, Register, code_asm::CodeAssembler};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, assembly, functions},
    progress::Progress,
    xlog,
};

const CHECK: &str = "kernel::multiprocess::IsMultiProcessSupported";
const LIMIT: &str = "kernel::multiprocess::CheckMultiProcessOverLimit";

pub const FEATURE: Feature = Feature {
    id: "single-instance",
    name: "单实例启动",
    description: "重复打开同一入口时唤起已有窗口",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

struct Scan {
    symbols: Symbols,
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    xlog::find(image, &[CHECK, LIMIT], progress)
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan { symbols })
}

impl Analysis for Scan {
    fn visit(
        &mut self,
        _image: &Image<'_>,
        _function: &Range<u64>,
        _references: &References,
        _progress: &Progress,
    ) -> Result<Vec<Edit>> {
        Ok(Vec::new())
    }

    fn finish(
        self: Box<Self>,
        image: &Image<'_>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Mode>> {
        let found = functions(CHECK, &self.symbols, references)
            .into_values()
            .collect::<Vec<_>>();
        let [function] = &found[..] else {
            return Err("无法唯一定位原生多进程判断".into());
        };
        let body = image.instructions(function)?;
        let copies = body
            .iter()
            .filter(|instruction| {
                matches!(instruction.code(), Code::Mov_r32_rm32 | Code::Mov_rm32_r32)
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op1_register() == Register::EAX
                    && body.iter().any(|result| {
                        matches!(result.code(), Code::Mov_r32_rm32 | Code::Mov_rm32_r32)
                            && result.op0_register() == Register::EAX
                            && result.op1_kind() == OpKind::Register
                            && result.op1_register() == instruction.op0_register()
                    })
            })
            .collect::<Vec<_>>();
        let [copy] = copies[..] else {
            return Err("无法唯一定位原生多进程判断结果".into());
        };
        let step = progress.activity("准备补丁");
        let mut code = CodeAssembler::new(64)?;
        code.add_instruction(Instruction::with2(
            Code::Xor_rm32_r32,
            copy.op0_register(),
            copy.op0_register(),
        )?)?;
        let bytes = code.assemble(copy.ip())?;
        if bytes.len() != copy.len() {
            return Err("无法原位替换原生多进程判断结果".into());
        }
        let offset = image.offset(copy.ip())?;
        step.finish(format!(
            "RVA 0x{:08X}；{} → {}",
            copy.ip() - image.base(),
            assembly(image.data(copy.ip(), copy.len())?, copy.ip()),
            assembly(&bytes, copy.ip()),
        ));
        Ok(vec![Mode::enabled(vec![Edit {
            range: offset..offset + bytes.len(),
            bytes,
        }])])
    }
}
