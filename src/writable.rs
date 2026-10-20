use std::ops::Range;

use iced_x86::{Code, Encoder};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, assembly, functions},
    progress::Progress,
    xlog,
};

const SET: &str = "kernel::fileutil::SetFileReadOnly";
const PREPARE: &str = "kernel::fileutil::PrepareWriteableFile";

pub const FEATURE: Feature = Feature {
    id: "writable",
    name: "解除文件只读",
    description: "保存文件时取消只读属性",
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
    xlog::find(image, &[SET, PREPARE], progress)
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
        let found = functions(SET, &self.symbols, references)
            .into_values()
            .collect::<Vec<_>>();
        let [function] = &found[..] else {
            return Err("无法唯一定位文件只读设置函数".into());
        };
        let masks = image
            .instructions(function)?
            .into_iter()
            .filter(|instruction| {
                instruction.code() == Code::Or_rm32_imm8 && instruction.immediate8() == 1
            })
            .collect::<Vec<_>>();
        let [original] = masks[..] else {
            return Err("无法唯一定位只读属性设置".into());
        };
        let step = progress.activity("准备文件属性补丁");
        let mut mask = original;
        mask.set_code(Code::And_rm32_imm8);
        mask.set_immediate8(!mask.immediate8());
        let mut encoder = Encoder::new(64);
        encoder.encode(&mask, original.ip())?;
        let bytes = encoder.take_buffer();
        if bytes.len() != original.len() {
            return Err("无法原位替换只读属性设置".into());
        }
        let offset = image.offset(original.ip())?;
        step.finish(format!(
            "RVA 0x{:08X}；{} → {}",
            original.ip() - image.base(),
            assembly(image.data(original.ip(), original.len())?, original.ip()),
            assembly(&bytes, original.ip()),
        ));
        Ok(vec![Mode::enabled(vec![Edit {
            range: offset..offset + bytes.len(),
            bytes,
        }])])
    }
}
