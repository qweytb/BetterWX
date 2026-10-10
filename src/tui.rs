use std::{
    io::{IsTerminal, Stdout, Write, stdout},
    path::Path,
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Print, SetAttribute, StyledContent, Stylize, style},
    terminal::{
        self, BeginSynchronizedUpdate, Clear, ClearType, EndSynchronizedUpdate,
        EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::{
    Result, feature, install,
    progress::{FRAME, Progress, Step},
    store::Store,
};

type Line = StyledContent<String>;

struct Item {
    label: Line,
    value: String,
    detail: String,
}

impl Item {
    fn action(label: StyledContent<&str>) -> Self {
        Self {
            label: label.style().apply((*label.content()).to_owned()),
            value: String::new(),
            detail: String::new(),
        }
    }
}

struct Screen {
    output: Stdout,
    rows: u16,
    alternate: bool,
    exiting: bool,
    #[cfg(windows)]
    pressed: std::collections::HashSet<KeyCode>,
}

impl Screen {
    fn open() -> Result<Self> {
        let mut screen = Self {
            output: stdout(),
            rows: 0,
            alternate: true,
            exiting: false,
            #[cfg(windows)]
            pressed: Default::default(),
        };
        terminal::enable_raw_mode()?;
        execute!(
            screen.output,
            Clear(ClearType::All),
            Clear(ClearType::Purge),
            MoveTo(0, 0),
            EnterAlternateScreen,
            Hide,
        )?;
        Ok(screen)
    }

    fn draw(
        &mut self,
        title: &str,
        lines: Vec<Line>,
        selected: Option<(usize, usize)>,
    ) -> Result<()> {
        let (width, height) = terminal::size()?;
        queue!(
            self.output,
            BeginSynchronizedUpdate,
            MoveTo(0, 0),
            SetAttribute(Attribute::Bold),
            Print(clip(
                &format!("==== BetterWX [{title}] ===="),
                width as usize
            )),
            SetAttribute(Attribute::Reset),
            Clear(ClearType::UntilNewLine),
            MoveTo(0, 1),
            Clear(ClearType::UntilNewLine),
        )?;
        for (index, line) in lines
            .iter()
            .take(height.saturating_sub(2) as usize)
            .enumerate()
        {
            queue!(self.output, MoveTo(0, index as u16 + 2))?;
            let text = clip(line.content(), width as usize);
            if let Some((_, count)) = selected.filter(|(row, _)| *row == index) {
                let end = text
                    .char_indices()
                    .nth(count)
                    .map_or(text.len(), |(index, _)| index);
                let mut appearance = *line.style();
                appearance.attributes.set(Attribute::Reverse);
                queue!(
                    self.output,
                    Print(appearance.apply(&text[..end])),
                    Print(line.style().apply(&text[end..]))
                )?;
            } else {
                queue!(self.output, Print(line.style().apply(text)))?;
            }
            queue!(
                self.output,
                SetAttribute(Attribute::Reset),
                Clear(ClearType::UntilNewLine),
            )?;
        }
        let end = (lines.len() + 2).min(height as usize);
        if end < height as usize {
            queue!(
                self.output,
                MoveTo(0, end as u16),
                Clear(ClearType::FromCursorDown)
            )?;
        }
        queue!(self.output, EndSynchronizedUpdate)?;
        self.output.flush()?;
        self.rows = end as u16;
        Ok(())
    }

    fn key(&mut self) -> Result<Option<KeyCode>> {
        let Event::Key(key) = event::read()? else {
            return Ok(None);
        };
        #[cfg(windows)]
        if matches!(
            key.code,
            KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ')
        ) {
            if key.kind == KeyEventKind::Release {
                self.pressed.remove(&key.code);
            } else if !self.pressed.insert(key.code) {
                return Ok(None);
            }
        }
        if key.kind == KeyEventKind::Release {
            return Ok(None);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.exiting = true;
            return Ok(Some(KeyCode::Esc));
        }
        Ok(Some(key.code))
    }

    fn select(
        &mut self,
        title: &str,
        items: &[Item],
        selected: &mut usize,
        notice: &str,
        help: &str,
    ) -> Result<bool> {
        loop {
            let (width, height) = terminal::size()?;
            let mut footer = Vec::new();
            let item = &items[*selected];
            let detail = &item.detail;
            if !detail.is_empty() {
                footer.push(style(String::new()));
                footer.extend(wrap(detail, width as usize).into_iter().map(style));
            }
            if !notice.is_empty() && notice != detail {
                footer.push(style(String::new()));
                footer.extend(
                    wrap(notice, width as usize)
                        .into_iter()
                        .map(|line| line.red()),
                );
            }
            footer.push(style(String::new()));
            footer.extend(help.lines().map(|line| line.to_owned().bold()));
            let visible = (height as usize).saturating_sub(footer.len() + 2).max(1);
            let start = selected.saturating_sub(visible - 1);
            let mut lines: Vec<Line> = items
                .iter()
                .skip(start)
                .take(visible)
                .map(|item| {
                    item.label.style().apply(format!(
                        "  > {}   {}",
                        item.label.content(),
                        item.value
                    ))
                })
                .collect();
            lines.extend(footer);
            self.draw(
                title,
                lines,
                Some((*selected - start, item.label.content().chars().count() + 7)),
            )?;
            let Some(key) = self.key()? else {
                continue;
            };
            match key {
                KeyCode::Up => *selected = (*selected + items.len() - 1) % items.len(),
                KeyCode::Down => *selected = (*selected + 1) % items.len(),
                KeyCode::Home | KeyCode::PageUp => *selected = 0,
                KeyCode::End | KeyCode::PageDown => *selected = items.len() - 1,
                KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => {
                    return Ok(true);
                }
                KeyCode::Esc | KeyCode::Left => return Ok(false),
                _ => {}
            }
        }
    }

    fn work<T: Send>(
        &mut self,
        title: &str,
        detail: &str,
        operation: impl FnOnce(&Progress) -> Result<T> + Send,
    ) -> Result<Option<T>> {
        let progress = Progress::default();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::scope(|scope| {
            let worker_progress = progress.clone();
            scope.spawn(move || {
                let _ = sender.send(operation(&worker_progress));
            });
            let mut cancelled = false;
            let mut deadline = Instant::now();
            loop {
                let (width, height) = terminal::size()?;
                let steps = progress.steps();
                let mut lines: Vec<Line> = wrap(detail, width as usize)
                    .into_iter()
                    .map(style)
                    .collect();
                lines.push(style(String::new()));
                let available = (height as usize).saturating_sub(lines.len() + 7);
                for step in steps
                    .iter()
                    .rev()
                    .skip(1)
                    .take(available)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    let text = step.text();
                    lines.push(style(clip(
                        &format!(
                            "  {}  {}",
                            step.name,
                            text.result.as_deref().unwrap_or(&text.detail)
                        ),
                        width as usize,
                    )));
                }
                if let Some(step) = steps.last() {
                    let text = step.text();
                    lines.push(style(format!("  {}", step.name)));
                    if let Some(result) = text.result {
                        lines.extend(
                            wrap(&result, width.saturating_sub(2) as usize)
                                .into_iter()
                                .map(|line| style(format!("  {line}"))),
                        );
                    } else {
                        lines.extend(
                            wrap(&text.detail, width.saturating_sub(2) as usize)
                                .into_iter()
                                .map(|line| style(format!("  {line}"))),
                        );
                        if step.total != 0 {
                            if step.unit != "字节" {
                                lines.push(style(format!(
                                    "  {} / {} {}",
                                    step.completed(),
                                    step.total,
                                    step.unit
                                )));
                            }
                            lines.push(style(format!(
                                "  {}",
                                bar(step, width.saturating_sub(4) as usize)
                            )));
                        }
                    }
                }
                lines.push(style(String::new()));
                lines.push(
                    (if cancelled {
                        "正在取消…".to_owned()
                    } else {
                        "Esc 取消".to_owned()
                    })
                    .bold(),
                );
                self.draw(title, lines, None)?;
                if event::poll(Duration::ZERO)? && self.key()? == Some(KeyCode::Esc) {
                    cancelled = true;
                    progress.cancel();
                }
                deadline += FRAME;
                match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(result) => {
                        return if cancelled {
                            Ok(None)
                        } else {
                            result.map(Some)
                        };
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return Err("处理线程已中断".into()),
                }
                if deadline < Instant::now() {
                    deadline = Instant::now();
                }
            }
        })
    }

    fn about(&mut self) -> Result<()> {
        self.draw("关于", Vec::new(), None)?;
        execute!(self.output, MoveTo(0, 2))?;
        let body = format!(
            "\x1b[1m   BetterWX v{}\n\x1b[0m   By zetaloop\n\n[",
            env!("CARGO_PKG_VERSION")
        );
        let mut bytes = Vec::new();
        for (index, byte) in body.bytes().chain(Some(0)).enumerate() {
            bytes.push(byte);
            if let Ok(text) = std::str::from_utf8(&bytes) {
                self.output
                    .write_all(if text == "\n" { b"\r\n" } else { &bytes })?;
                self.output.flush()?;
                bytes.clear();
            }
            sleep(index as u32 % 2);
        }
        let repository = "github.com/zetaloop/BetterWX";
        for (index, byte) in repository.bytes().chain(Some(0)).enumerate() {
            let frame = format!(
                "\x1b[34;1m\x1b[4m\x1b]8;;https://{repository}\x1b\\{}\x1b]8;;\x1b\\\x1b[0m]\x1b[1D",
                char::from(byte)
            );
            self.output.write_all(frame.as_bytes())?;
            self.output.flush()?;
            sleep(index as u32 % 2);
        }
        execute!(
            self.output,
            Print("]\r\n\r\n"),
            Print("  > 返回   ".reverse())
        )?;
        self.rows = 8;
        while self.key()?.is_none() {}
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let heading = "==== BetterWX [退出] ====";
        execute!(
            self.output,
            MoveTo(0, 0),
            Print(heading.bold()),
            Clear(ClearType::UntilNewLine)
        )?;
        for (index, row) in (2..self.rows).rev().enumerate() {
            sleep(4 + index as u32 * 5);
            execute!(self.output, MoveTo(0, row), Clear(ClearType::CurrentLine))?;
        }
        let banner = "  BetterWX  ";
        execute!(self.output, MoveTo(1, 2), SetAttribute(Attribute::Reverse))?;
        let mut written = 0;
        for tick in 0..39 {
            let visible = (tick + 1) * banner.len() / 39;
            self.output
                .write_all(&banner.as_bytes()[written..visible])?;
            self.output.flush()?;
            written = visible;
            sleep(tick as u32 % 2);
        }
        sleep(500);
        execute!(
            self.output,
            SetAttribute(Attribute::Reset),
            BeginSynchronizedUpdate,
            LeaveAlternateScreen,
        )?;
        self.alternate = false;
        execute!(
            self.output,
            Print(heading.bold()),
            Print("\r\n\r\n "),
            Print(banner.reverse()),
            Print("\r\n"),
            EndSynchronizedUpdate,
        )?;
        Ok(())
    }
}

fn sleep(milliseconds: u32) {
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Threading::Sleep(milliseconds)
    };
    #[cfg(not(windows))]
    thread::sleep(Duration::from_millis(milliseconds as u64));
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = execute!(
            self.output,
            EndSynchronizedUpdate,
            SetAttribute(Attribute::Reset),
            Show,
        );
        if self.alternate {
            let _ = execute!(self.output, LeaveAlternateScreen);
        }
        let _ = terminal::disable_raw_mode();
    }
}

fn clip(text: &str, width: usize) -> String {
    if text.width() <= width {
        return text.to_owned();
    }
    let mut length = 0;
    let mut result = String::new();
    for character in text.chars() {
        length += character.width().unwrap_or(0);
        if length >= width {
            break;
        }
        result.push(character);
    }
    if width != 0 {
        result.push('…');
    }
    result
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut length = 0;
    for character in text.chars() {
        let size = character.width().unwrap_or(0);
        if character == '\n' || (!line.is_empty() && length + size > width) {
            lines.push(std::mem::take(&mut line));
            length = 0;
        }
        if character != '\n' {
            line.push(character);
            length += size;
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn bar(step: &Step, width: usize) -> String {
    let fraction = if step.total == 0 {
        1.0
    } else {
        step.completed() as f64 / step.total as f64
    };
    let cells = width.saturating_sub(8);
    let units = (fraction * cells as f64 * 8.0) as usize;
    let whole = units / 8;
    let partial = units % 8;
    let mut result = "█".repeat(whole);
    if partial != 0 {
        result.push([' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'][partial]);
    }
    result.push_str(&" ".repeat(cells.saturating_sub(whole + usize::from(partial != 0))));
    format!("{result} {:5.1}%", fraction * 100.0)
}

fn configure(screen: &mut Screen, path: &Path) -> Result<()> {
    let detail = path.display().to_string();
    let Some((mut store, prepared)) = screen.work("分析", &detail, |progress| {
        let mut store = Store::open(path, progress)?;
        let prepared = feature::scan(&mut store, progress)?;
        feature::inspect(&mut store, &prepared, progress)?;
        Ok((store, prepared))
    })?
    else {
        return Ok(());
    };
    let mut selected = 0;
    let mut notice = String::new();
    let mut pending = None;
    loop {
        let mut items: Vec<Item> = prepared
            .iter()
            .enumerate()
            .map(|(index, patch)| {
                let error = patch.issue(&store);
                let state = patch.state(&store);
                let label = patch.feature.name.to_owned();
                let value = if pending == Some(index) {
                    format!(
                        " 结束占用进程并{}",
                        if state == feature::State::Enabled {
                            "关闭"
                        } else {
                            "开启"
                        }
                    )
                } else {
                    format!(
                        " {}",
                        if error.is_some() {
                            "不可用"
                        } else {
                            state.label()
                        }
                    )
                };
                Item {
                    label: if error.is_some() || pending == Some(index) {
                        label.red()
                    } else {
                        style(label)
                    },
                    value,
                    detail: error
                        .cloned()
                        .unwrap_or_else(|| patch.feature.description.to_owned()),
                }
            })
            .collect();
        let mut restore = Item::action(style("恢复原版"));
        if pending == Some(prepared.len()) {
            restore.label = restore.label.red();
            restore.value = " 结束占用进程并恢复".to_owned();
        }
        items.extend([restore, Item::action(style("返回"))]);
        if !screen.select(
            "功能",
            &items,
            &mut selected,
            &notice,
            "方向键 选择\n回车键 切换\nEsc 返回",
        )? {
            return Ok(());
        };
        let change = if let Some(patch) = prepared.get(selected) {
            if let Some(error) = patch.issue(&store) {
                notice = error.clone();
                continue;
            }
            Some((patch, patch.state(&store) != feature::State::Enabled))
        } else if selected == prepared.len() {
            None
        } else {
            return Ok(());
        };
        let targets = match change {
            Some((patch, enable)) => patch.targets(&store, enable)?,
            None => store.changed(),
        };
        if targets.is_empty() {
            notice.clear();
            continue;
        }
        let error = store.write_error(&targets);
        let terminate = error.is_some() && pending == Some(selected);
        if let Some(error) = error
            && !terminate
        {
            notice = error;
            #[cfg(windows)]
            {
                pending = Some(selected);
            }
            continue;
        }
        pending = None;
        let result = screen.work("写入", &detail, |progress| {
            #[cfg(windows)]
            if terminate {
                let step = progress.activity("查询占用进程");
                step.detail(
                    targets
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
                let processes = crate::process::using(&targets)?;
                step.finish(
                    processes
                        .iter()
                        .map(|process| process.description())
                        .collect::<Vec<_>>()
                        .join("、"),
                );
                for process in processes {
                    progress.check()?;
                    process.terminate(progress)?;
                }
            }
            let step = progress.activity("准备文件内容");
            let contents = match change {
                Some((patch, enable)) => {
                    let contents = feature::change(&store, patch, enable, &prepared)?;
                    step.finish(format!(
                        "{}：{}",
                        patch.feature.name,
                        if enable { "开启" } else { "关闭" }
                    ));
                    contents
                }
                None => {
                    let contents = store.originals();
                    step.finish("恢复原始内容");
                    contents
                }
            };
            store.save(contents, progress)
        });
        notice = match result {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        };
        if screen.exiting {
            return Ok(());
        }
    }
}

pub fn run() -> Result<()> {
    if !std::io::stdin().is_terminal() || !stdout().is_terminal() {
        return Err("交互界面需要终端；命令行用法见 --help".into());
    }
    let mut screen = Screen::open()?;
    let mut notice = String::new();
    let mut versions = match install::scan() {
        Ok(versions) => versions,
        Err(error) => {
            notice = error.to_string();
            Vec::new()
        }
    };
    let mut selected = 0;
    while !screen.exiting {
        let mut items: Vec<Item> = versions
            .iter()
            .map(|file| {
                let directory = file.parent().unwrap_or(file);
                Item {
                    label: style(
                        directory
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                    ),
                    value: String::new(),
                    detail: file.display().to_string(),
                }
            })
            .collect();
        items.extend([
            Item::action(style("选择文件…")),
            Item::action(style("重新扫描")),
            Item::action(style("关于")),
            Item::action("退出".red()),
        ]);
        if !screen.select(
            "选择版本",
            &items,
            &mut selected,
            &notice,
            "方向键 选择\n回车键 确定\nEsc 退出",
        )? {
            break;
        }
        if selected == versions.len() + 1 {
            match install::scan() {
                Ok(found) => {
                    versions = found;
                    notice.clear();
                }
                Err(error) => notice = error.to_string(),
            }
            selected = 0;
            continue;
        }
        if selected == versions.len() + 2 {
            screen.about()?;
            continue;
        }
        if selected == versions.len() + 3 {
            break;
        }
        let path = if let Some(path) = versions.get(selected) {
            path.clone()
        } else {
            match install::pick() {
                Ok(Some(path)) => {
                    if !versions.contains(&path) {
                        versions.push(path.clone());
                        selected = versions.len() - 1;
                    }
                    path
                }
                Ok(None) => continue,
                Err(error) => {
                    notice = error.to_string();
                    continue;
                }
            }
        };
        notice = match configure(&mut screen, &path) {
            Ok(()) => String::new(),
            Err(error) => error.to_string(),
        };
    }
    screen.finish()
}
