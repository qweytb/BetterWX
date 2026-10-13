mod feature;
mod image;
mod install;
mod login;
#[cfg(windows)]
mod process;
mod progress;
mod revoke;
mod store;
mod tui;
mod uia;
mod updates;
mod xlog;

use std::{env, error::Error, path::PathBuf, process::ExitCode};

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
            println!("{}：{}", feature.id, feature.name);
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
    if command != "restore" {
        prepared = feature::scan(&mut store, &progress)?;
        feature::inspect(&mut store, &prepared, &progress)?;
    } else {
        store.load_backups(&feature::targets(&store.target)?, &progress)?;
    }
    println!("目标：{}", store::display(&path));
    match command {
        "status" => {
            for patch in &prepared {
                println!(
                    "{}：{}",
                    patch.feature.name,
                    if let Some(error) = patch.issue(&store) {
                        error.as_str()
                    } else {
                        patch.state(&store).label()
                    },
                );
            }
        }
        "enable" | "disable" => {
            let feature = feature.ok_or("缺少功能名称")?;
            let patch = prepared
                .iter()
                .find(|patch| patch.feature.id == feature.id)
                .ok_or("找不到功能分析结果")?;
            if let Some(issue) = patch.issue(&store) {
                return Err(issue.clone().into());
            }
            let enable = command == "enable";
            let requested = if enable {
                feature::State::Enabled
            } else {
                feature::State::Disabled
            };
            if patch.state(&store) == requested {
                println!("当前状态已符合请求");
                return Ok(());
            }
            let contents = feature::change(&store, patch, enable, &prepared)?;
            store.save(contents, &progress)?;
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
            if store.changed().is_empty() {
                println!("文件处于原始状态");
                return Ok(());
            }
            store.save(store.originals(), &progress)?;
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
