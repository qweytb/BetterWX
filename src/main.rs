mod coexist;
mod credentials;
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
  betterwx coexist <create|remove> <字母> [Weixin.dll]
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
    let mut entry = None;
    let mut remove = false;
    let feature = match command {
        "enable" | "disable" => {
            let argument = arguments.next().ok_or("需要指定功能名称")?;
            Some(feature::find(
                argument.to_str().ok_or("功能名称必须为文字")?,
            )?)
        }
        "coexist" => {
            let operation = arguments.next().ok_or("需要指定 create 或 remove")?;
            remove = match operation.to_str().ok_or("操作名称必须为文字")? {
                "create" => false,
                "remove" => true,
                operation => return Err(format!("未知共存操作：{operation}").into()),
            };
            let name = arguments.next().ok_or("需要指定入口字母")?;
            entry = Some(coexist::letter(name.to_str().ok_or("入口名称必须为文字")?)?);
            Some(feature::find(coexist::FEATURE.id)?)
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
    if remove {
        let directory = coexist::directory(&path.canonicalize()?)?;
        let entry = directory.join(entry.ok_or("缺少入口字母")?.to_string());
        coexist::remove(&entry, &progress)?;
        println!("已删除入口：{}", store::display(&entry));
        return Ok(());
    }
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
        "enable" | "disable" | "coexist" => {
            let feature = feature.ok_or("缺少功能名称")?;
            let patch = prepared
                .iter()
                .find(|patch| patch.feature.id == feature.id)
                .ok_or("找不到功能分析结果")?;
            if let Some(issue) = patch.issue(&store) {
                return Err(issue.clone().into());
            }
            if let Some(letter) = entry {
                if patch.state(&store) != feature::State::Enabled {
                    return Err("启用所选版本的共存支持后可创建入口".into());
                }
                let path = coexist::directory(&store.target)?.join(letter.to_string());
                if coexist::exists(&path)? {
                    return Err(format!("{} 已存在", store::display(&path)).into());
                }
                coexist::create(&path, &progress)?;
                println!("入口：{}", store::display(&path.join("Weixin.exe")));
                return Ok(());
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
                if enable { "已启用" } else { "已关闭" }
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
