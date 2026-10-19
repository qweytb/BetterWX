use std::{collections::BTreeMap, ops::Range};

use iced_x86::{
    Register,
    code_asm::{CodeAssembler, eax},
};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, calls, functions, literal},
    progress::Progress,
    xlog,
};

const SET: &str = "kernel::service::MultiTabService::SetIfUseSysBrowser";
const WRITE: &str = "kernel::foundation::LoginConfigKV::AddOrUpdate";
const READ: &str = "kernel::foundation::LoginConfigKV::GetBoolValueByKey";

pub const FEATURE: Feature = Feature {
    id: "browser",
    name: "系统浏览器",
    description: "使用系统默认浏览器打开网页",
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
    xlog::find(image, &[SET, WRITE, READ], progress)
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
        let setters = functions(SET, &self.symbols, references);
        let [setter]: [_; 1] = setters
            .into_values()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "无法唯一定位系统浏览器设置函数")?;
        let body = image.instructions(&setter)?;
        let writers = functions(WRITE, &self.symbols, references);
        let keys = calls(&body)
            .filter(|(_, target)| writers.contains_key(target))
            .map(|(index, _)| literal(&body, index, Register::RDX))
            .collect::<Result<Vec<_>>>()?;
        let [key] = keys[..] else {
            return Err("无法唯一定位系统浏览器配置键".into());
        };
        let readers = functions(READ, &self.symbols, references);
        let mut getters = BTreeMap::new();
        for function in references.get(key).into_iter().flatten() {
            let body = image.instructions(function)?;
            if calls(&body).any(|(index, target)| {
                readers.contains_key(&target)
                    && literal(&body, index, Register::RDX).ok() == Some(key)
            }) {
                getters.insert(function.start, function.clone());
            }
        }
        let [getter]: [_; 1] = getters
            .into_values()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "无法唯一定位系统浏览器偏好读取函数")?;
        let step = progress.activity("准备浏览器补丁");
        let mut code = CodeAssembler::new(64)?;
        code.mov(eax, 1)?;
        code.ret()?;
        let edits = image.replace_function(&getter, &mut code, &[1, 0, 0, 0])?;
        step.finish(format!(
            "系统浏览器偏好；RVA 0x{:08X}；返回开启",
            getter.start - image.base(),
        ));
        Ok(vec![Mode::enabled(edits)])
    }
}
