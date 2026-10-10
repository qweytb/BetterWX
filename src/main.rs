mod feature;
mod install;
#[cfg(windows)]
mod process;
mod progress;
mod store;
mod tui;

use std::{collections::BTreeSet, env, error::Error, path::PathBuf, process::ExitCode};

use progress::Progress;
use store::Store;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

const HELP: &str = "\
BetterWX

用法：
  betterwx
  betterwx status [Weixin.dll]
  betterwx enable <功能> [Weixin.dll]
  betterwx disable <功能> [Weixin.dll]
  betterwx restore [Weixin.dll]

无参数启动时进入交互界面。
省略路径时，读取微信安装目录中的最新版本。
restore：恢复保存的原始文件。";

fn run() -> Result<()> {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        return tui::run();
    };
    if command == "--help" || command == "-h" {
        println!("{HELP}");
        for feature in feature::FEATURES {
            println!("{}：{}", feature.id, feature.description);
        }
        return Ok(());
    }
    if command == "--version" {
        println!("BetterWX {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let command = command.to_str().ok_or("命令必须为文字")?;
    let feature = match command {
        "enable" | "disable" => {
            let argument = arguments.next().ok_or("需要指定功能名称")?;
            Some(feature::find(
                argument.to_str().ok_or("功能名称必须为文字")?,
            )?)
        }
        "status" | "restore" => None,
        _ => return Err(format!("未知命令：{command}").into()),
    };
    let path = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() {
        return Err("参数数量过多".into());
    }
    let path = match path {
        Some(path) => path,
        None => install::scan()?
            .into_iter()
            .next()
            .ok_or("安装目录中找不到微信版本")?,
    };
    let progress = Progress::default();
    let mut store = Store::open(&path, &progress)?;
    let mut prepared = Vec::new();
    let mut issue = None;
    if command != "restore" {
        prepared = feature::scan(&store.original, &progress)?;
        (store.enabled, issue) =
            feature::inspect(&store.original, &store.current, &prepared, &progress)?;
    }
    println!("目标：{}", path.display());
    match command {
        "status" => {
            for patch in &prepared {
                println!(
                    "{}：{}",
                    patch.feature.name,
                    if let Some(error) = patch.edits.as_ref().err().or(issue.as_ref()) {
                        error.as_str()
                    } else if store.enabled.contains(patch.feature.id) {
                        "开启"
                    } else {
                        "关闭"
                    },
                );
            }
        }
        "enable" | "disable" => {
            if let Some(issue) = issue {
                return Err(issue.into());
            }
            let mut enabled = store.enabled.clone();
            let feature = feature.ok_or("缺少功能名称")?;
            if command == "enable" {
                enabled.insert(feature.id.to_owned());
            } else {
                enabled.remove(feature.id);
            }
            if enabled == store.enabled {
                println!("当前状态已符合请求");
                return Ok(());
            }
            let output = feature::generate(&store.original, &enabled, &prepared)?;
            store.save(output, enabled, &progress)?;
            println!(
                "{}：{}",
                feature.name,
                if command == "enable" {
                    "已启用"
                } else {
                    "已关闭"
                }
            );
        }
        "restore" => {
            if store.current == store.original {
                println!("文件处于原始状态");
                return Ok(());
            }
            store.save(store.original.as_ref().clone(), BTreeSet::new(), &progress)?;
            println!("已恢复原始文件");
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
