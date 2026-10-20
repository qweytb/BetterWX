use std::ops::Range;

use iced_x86::code_asm::{CodeAssembler, eax};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, functions},
    progress::Progress,
    xlog,
};

const INIT: &str = "kernel::service::XWebService::Init";
const LAUNCH: &str = "kernel::service::XWebService::LaunchXWeb";

pub const FEATURE: Feature = Feature {
    id: "no-appex",
    name: "关闭内置浏览器",
    description: "禁用 WeChatAppEx，将不再能够浏览内置网页和小程序等",
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
    xlog::find(image, &[INIT, LAUNCH], progress)
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
        let found = functions(LAUNCH, &self.symbols, references)
            .into_values()
            .collect::<Vec<_>>();
        let [function] = &found[..] else {
            return Err("无法唯一定位扩展组件启动函数".into());
        };
        let step = progress.activity("准备扩展组件补丁");
        let mut code = CodeAssembler::new(64)?;
        // Init returns 3 when XWeb startup is deferred.
        code.mov(eax, 3)?;
        code.ret()?;
        let edits = image.replace_function(function, &mut code, &[1, 0, 0, 0])?;
        step.finish(format!(
            "{LAUNCH}；RVA 0x{:08X}；返回 3",
            function.start - image.base(),
        ));
        Ok(vec![Mode::enabled(edits)])
    }
}
