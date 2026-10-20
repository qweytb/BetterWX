mod appex;
mod browser;
mod coexist;
mod credentials;
mod emoticon;
mod feature;
mod icon;
mod image;
mod install;
mod instance;
mod login;
mod notify;
#[cfg(windows)]
mod process;
mod progress;
mod qrc;
mod remote;
mod resources;
mod revoke;
mod sound;
mod store;
mod tray;
mod tui;
mod uia;
mod updates;
mod writable;
mod xlog;

use std::{env, error::Error, path::PathBuf, process::ExitCode};

use progress::Progress;
use store::Store;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

const HELP: &str = "\
BetterWX

用法：
  betterwx
  betterwx status [文件]
  betterwx enable <功能> [--mode <模式>] [文件]
  betterwx disable <功能> [文件]
  betterwx coexist <create|remove> <字母> [文件]
  betterwx sound import <提示音> <音频文件> [文件]
  betterwx sound restore <提示音> [文件]
  betterwx icon import <图片文件> [文件]
  betterwx icon restore [文件]
  betterwx restore [文件]

无参数启动时进入交互界面。
文件可选 Weixin.exe 或 Weixin.dll。
省略路径时，读取微信安装目录中的最新版本。
系统通知头像模式：square 方形、circle 圆形。
restore：还原已备份的原版文件。
--force：确认以当前文件作为备份和补丁基准。";

fn run() -> Result<()> {
    let mut arguments = env::args_os().skip(1).peekable();
    let Some(command) = arguments.next() else {
        return tui::run();
    };
    if command == "--help" || command == "-h" {
        println!("{HELP}");
        for feature in feature::FEATURES {
            println!("{}：{}", feature.id, feature.name);
        }
        println!("\n提示音类型：");
        for sound in sound::SOUNDS {
            println!("{}：{}", sound.id, sound.name);
        }
        return Ok(());
    }
    if command == "--version" {
        println!("BetterWX {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let command = command.to_str().ok_or("命令必须为文字")?;
    let mut force = false;
    let mut arguments = arguments
        .filter(|argument| {
            if argument == "--force" {
                force = true;
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>()
        .into_iter()
        .peekable();
    let mut entry = None;
    let mut remove = false;
    let mut audio = None;
    let mut picture = None;
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
        "sound" => {
            let operation = arguments.next().ok_or("需要指定 import 或 restore")?;
            let operation = operation.to_str().ok_or("操作名称必须为文字")?.to_owned();
            let name = arguments.next().ok_or("需要指定提示音类型")?;
            let sound = sound::get(name.to_str().ok_or("提示音类型必须为文字")?)?;
            let file = match operation.as_str() {
                "import" => Some(PathBuf::from(arguments.next().ok_or("需要指定音频文件")?)),
                "restore" => None,
                _ => return Err(format!("未知提示音操作：{operation}").into()),
            };
            audio = Some((operation, sound, file));
            Some(feature::find(sound::FEATURE.id)?)
        }
        "icon" => {
            let operation = arguments.next().ok_or("需要指定 import 或 restore")?;
            let operation = operation.to_str().ok_or("操作名称必须为文字")?.to_owned();
            let file = match operation.as_str() {
                "import" => Some(PathBuf::from(arguments.next().ok_or("需要指定图片文件")?)),
                "restore" => None,
                _ => return Err(format!("未知图标操作：{operation}").into()),
            };
            picture = Some((operation, file));
            Some(feature::find(icon::FEATURE.id)?)
        }
        "status" | "restore" => None,
        _ => return Err(format!("未知命令：{command}").into()),
    };
    let mode = if command == "enable" && arguments.peek().is_some_and(|value| value == "--mode") {
        arguments.next();
        Some(arguments.next().ok_or("需要指定模式")?)
    } else {
        None
    };
    let path = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() {
        return Err("参数数量过多".into());
    }
    let path = install::resolve(match path {
        Some(path) => path,
        None => install::scan()?
            .into_iter()
            .next()
            .ok_or("安装目录中找不到微信版本")?,
    })?;
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
    println!("目标：{}", store::display(&store.target));
    if force {
        for file in store.files.values_mut() {
            file.confirmed = true;
        }
    }
    match command {
        "status" => {
            for issue in store
                .files
                .values()
                .filter_map(|file| file.source_issue.as_ref())
            {
                println!("{issue}");
            }
            for patch in &prepared {
                println!(
                    "{}：{}",
                    patch.feature.name,
                    if let Some(error) = patch.issue(&store) {
                        error.as_str()
                    } else {
                        patch.label(patch.state(&store))
                    },
                );
            }
        }
        "sound" => {
            let (operation, sound, file) = audio.ok_or("缺少提示音操作")?;
            let patch = prepared
                .iter()
                .find(|patch| patch.feature.id == sound::FEATURE.id)
                .ok_or("找不到提示音分析结果")?;
            let message = match operation.as_str() {
                "import" => {
                    sound.import(&store, &file.ok_or("缺少音频文件")?, &progress)?;
                    "已替换"
                }
                "restore" => {
                    sound.restore(&store, patch, &progress)?;
                    "已恢复"
                }
                _ => unreachable!(),
            };
            println!("{}：{message}", sound.name);
        }
        "icon" => {
            let (operation, file) = picture.ok_or("缺少图标操作")?;
            let patch = prepared
                .iter()
                .find(|patch| patch.feature.id == icon::FEATURE.id)
                .ok_or("找不到图标分析结果")?;
            let message = match operation.as_str() {
                "import" => {
                    icon::import(&store, &file.ok_or("缺少图片文件")?, &progress)?;
                    "已替换"
                }
                "restore" => {
                    icon::restore(&store, patch, &progress)?;
                    "已恢复"
                }
                _ => unreachable!(),
            };
            println!("托盘图标：{message}");
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
                if !patch.state(&store).enabled() {
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
            let mode = if enable {
                Some(match mode {
                    Some(mode) => {
                        let mode = mode.to_str().ok_or("模式名称必须为文字")?;
                        let choices = patch.edits.as_ref().map_err(|error| error.clone())?;
                        choices
                            .iter()
                            .position(|choice| choice.id == mode)
                            .ok_or_else(|| {
                                format!(
                                    "未知模式：{mode}；可选：{}",
                                    choices
                                        .iter()
                                        .map(|choice| choice.id)
                                        .collect::<Vec<_>>()
                                        .join("、")
                                )
                            })?
                    }
                    None => match patch.state(&store) {
                        feature::State::Enabled(mode) => mode,
                        _ => 0,
                    },
                })
            } else {
                None
            };
            let requested = mode.map_or(feature::State::Disabled, feature::State::Enabled);
            let contents = feature::change(&store, patch, mode, &prepared, &progress)?;
            store.save(contents, &progress)?;
            if feature.id == sound::FEATURE.id && !enable {
                sound::cleanup(&mut store, &prepared, &progress)?;
            }
            if feature.id == icon::FEATURE.id && !enable {
                icon::cleanup(&mut store, &prepared, &progress)?;
            }
            println!(
                "{}：{}",
                feature.name,
                if !enable {
                    "已关闭"
                } else if patch.edits.as_ref().expect("modes").len() == 1 {
                    "已启用"
                } else {
                    patch.label(requested)
                }
            );
        }
        "restore" => {
            let changed = !store.changed().is_empty();
            store.save(store.originals()?, &progress)?;
            sound::cleanup(&mut store, &prepared, &progress)?;
            icon::cleanup(&mut store, &prepared, &progress)?;
            println!(
                "{}",
                if changed {
                    "已恢复原版"
                } else {
                    "已是原版"
                }
            );
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
