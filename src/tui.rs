use std::{
    collections::BTreeMap,
    io::{IsTerminal, Stdout, Write, stdout},
    path::{Path, PathBuf},
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
    store::{self, Content, Store},
};

type Line = StyledContent<String>;

enum Change<'a> {
    Feature(&'a feature::Prepared, Option<usize>),
    Update(BTreeMap<PathBuf, Content>),
    Restore,
}

impl Change<'_> {
    fn targets(&self, store: &Store) -> Result<Vec<PathBuf>> {
        match self {
            Self::Feature(patch, mode) => patch.targets(store, *mode),
            Self::Update(contents) => Ok(contents.keys().cloned().collect()),
            Self::Restore => Ok(store.changed()),
        }
    }
}

struct Item {
    marker: &'static str,
    label: Line,
    value: String,
    detail: String,
}

impl Item {
    fn action(label: StyledContent<&str>) -> Self {
        Self {
            marker: ">",
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
        heading: &str,
        items: &[Item],
        selected: &mut usize,
        notice: &str,
        help: &str,
    ) -> Result<bool> {
        let label_width = items
            .iter()
            .map(|item| item.label.content().width())
            .max()
            .unwrap_or_default();
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
            let mut lines = Vec::new();
            if !heading.is_empty() {
                lines.push(style(heading.to_owned()));
                lines.push(style(String::new()));
            }
            let offset = lines.len();
            let visible = (height as usize)
                .saturating_sub(footer.len() + offset + 2)
                .max(1);
            let start = selected.saturating_sub(visible - 1);
            lines.extend(items.iter().enumerate().skip(start).take(visible).map(
                |(index, item)| {
                    item.label.style().apply(format!(
                        "  {} {}{}    {}",
                        item.marker,
                        item.label.content(),
                        " ".repeat(label_width - item.label.content().width()),
                        if index == *selected { &item.value } else { "" },
                    ))
                },
            ));
            lines.extend(footer);
            self.draw(
                title,
                lines,
                Some((
                    offset + *selected - start,
                    item.label.content().chars().count() + label_width
                        - item.label.content().width()
                        + 7,
                )),
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
            let started = Instant::now();
            let mut deadline = started;
            loop {
                let (width, height) = terminal::size()?;
                let steps = progress.steps();
                let mut lines: Vec<Line> = wrap(detail, width as usize)
                    .into_iter()
                    .map(style)
                    .collect();
                lines.push(style(String::new()));
                let mut logs = Vec::new();
                let mut current = Vec::new();
                for record in progress.records() {
                    let name = record.group.as_deref().unwrap_or(&record.name);
                    for line in record.detail.lines() {
                        logs.extend(
                            wrap(&format!("{name}：{line}"), width as usize)
                                .into_iter()
                                .map(style),
                        );
                    }
                }
                if let Some((step, text)) = steps.iter().rev().find_map(|step| {
                    let text = step.text();
                    (!text.finished).then_some((step, text))
                }) {
                    let name = step.group.as_deref().unwrap_or(&step.name);
                    step.request();
                    let mut detail = text.detail.lines();
                    let heading = if step.total != 0 {
                        format!(
                            "{name}：{}/{} {}；",
                            step.completed(),
                            step.total,
                            step.unit
                        )
                    } else {
                        format!("{name}：")
                    };
                    let size = (width as usize).saturating_sub(heading.width());
                    current.push(style(clip(
                        &format!("{heading}{}", bar(step, size, started.elapsed())),
                        width as usize,
                    )));
                    if step.total == 0
                        && let Some(line) = detail.next()
                    {
                        current.push(style(clip(&format!("  {line}"), width as usize)));
                    }
                    current.push(style(clip(
                        &format!("  {}", detail.collect::<Vec<_>>().join("；")),
                        width as usize,
                    )));
                }
                let available = (height as usize).saturating_sub(lines.len() + current.len() + 4);
                let skip = logs.len().saturating_sub(available);
                lines.extend(logs.into_iter().skip(skip));
                lines.extend(current);
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

    fn sources(&mut self, store: &mut Store, targets: &[PathBuf]) -> Result<bool> {
        for target in targets {
            let file = store.files.get_mut(target).ok_or("找不到目标文件")?;
            if file.confirmed || file.source_issue.is_none() {
                continue;
            }
            let items = [
                Item::action(style("无视风险继续操作")),
                Item::action(style("返回")),
            ];
            let notice = format!(
                "{} 似乎被修改过。\n\n如果以当前文件为基准进行修补，可能导致部分功能异常，推荐重新安装再来修补。",
                store::display(target),
            );
            let mut selected = 0;
            if !self.select(
                "基准存在改动",
                "",
                &items,
                &mut selected,
                &notice,
                "方向键 选择\n回车键 确定\nEsc 返回",
            )? || selected == 1
            {
                return Ok(false);
            }
            file.confirmed = true;
        }
        Ok(true)
    }

    fn change(
        &mut self,
        store: &mut Store,
        prepared: &[feature::Prepared],
        change: Change<'_>,
        pending: bool,
    ) -> Result<(bool, String)> {
        let targets = change.targets(store)?;
        if !self.sources(store, &targets)? {
            return Ok((false, String::new()));
        }
        let error = store.write_error(&targets);
        let terminate = error.is_some() && pending;
        if let Some(error) = error
            && !terminate
        {
            return Ok(if cfg!(windows) {
                (true, String::new())
            } else {
                (false, error)
            });
        }
        let detail = format!(" -- {}", version(&store.target));
        let notice = match self.work("写入", &detail, |progress| {
            apply(store, prepared, change, terminate, progress)
        }) {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        };
        Ok((false, notice))
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
        let start = Instant::now();
        for row in (2..self.rows).rev() {
            let remaining = f64::from(row - 2) / f64::from(self.rows - 2);
            let deadline = start + Duration::from_millis(350).mul_f64(1.0 - remaining.sqrt());
            sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u32,
            );
            execute!(self.output, MoveTo(0, row), Clear(ClearType::CurrentLine))?;
        }
        let banner = format!("  BetterWX v{}  ", env!("CARGO_PKG_VERSION"));
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
        sleep(250);
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

fn bar(step: &Step, width: usize, elapsed: Duration) -> String {
    if step.total == 0 {
        let mut cells = vec![' '; width];
        cells[..width.div_ceil(4)].fill('█');
        if !cells.is_empty() {
            cells.rotate_right((elapsed.as_millis() / 50) as usize % width);
        }
        return cells.into_iter().collect();
    }
    let fraction = step.completed() as f64 / step.total as f64;
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

fn version(path: &Path) -> String {
    path.parent()
        .unwrap_or(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

fn occupied(action: &str) -> String {
    format!("再按一下可以结束进程以继续{action}")
}

fn apply(
    store: &mut Store,
    prepared: &[feature::Prepared],
    change: Change<'_>,
    terminate: bool,
    progress: &Progress,
) -> Result<()> {
    let targets = change.targets(store)?;
    #[cfg(not(windows))]
    let _ = terminate;
    #[cfg(windows)]
    if terminate {
        let step = progress.activity("查询占用进程");
        step.detail(
            targets
                .iter()
                .map(|path| store::display(path))
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
    if let Change::Update(contents) = change {
        return feature::update(store, contents, prepared, progress);
    }
    let step = progress.activity("准备文件内容");
    let contents = match &change {
        Change::Feature(patch, mode) => {
            let contents = feature::change(store, patch, *mode, prepared, progress)?;
            step.finish(format!(
                "{}；{}",
                patch.feature.name,
                patch.label(mode.map_or(feature::State::Disabled, feature::State::Enabled))
            ));
            contents
        }
        Change::Restore => {
            let contents = store.originals()?;
            step.finish("恢复原始内容");
            contents
        }
        Change::Update(_) => unreachable!(),
    };
    feature::describe(store, &contents, prepared, progress)?;
    store.save(contents, progress)?;
    if matches!(&change, Change::Restore)
        || matches!(&change, Change::Feature(patch, None) if patch.feature.id == crate::sound::FEATURE.id)
    {
        crate::sound::cleanup(store, prepared, progress)?;
    }
    if matches!(&change, Change::Restore)
        || matches!(&change, Change::Feature(patch, None) if patch.feature.id == crate::icon::FEATURE.id)
    {
        crate::icon::cleanup(store, prepared, progress)?;
    }
    Ok(())
}

fn coexist(
    screen: &mut Screen,
    store: &mut Store,
    prepared: &[feature::Prepared],
    patch: &feature::Prepared,
) -> Result<()> {
    let directory = crate::coexist::directory(&store.target)?;
    let detail = format!(" -- {}", version(&store.target));
    let mut selected = 0;
    let mut pending = false;
    let mut notice = String::new();
    loop {
        let enabled = patch.state(store).enabled();
        let error = patch.issue(store);
        let mut items = vec![Item {
            marker: if enabled { "■" } else { "□" },
            label: if error.is_some() {
                "共存支持".to_owned().red()
            } else if pending {
                "共存支持".to_owned().dark_green()
            } else {
                style("共存支持".to_owned())
            },
            value: if pending {
                occupied(if enabled { "关闭" } else { "开启" })
            } else if error.is_some() {
                "不可用".to_owned()
            } else if enabled {
                "已启用".to_owned()
            } else {
                "未启用".to_owned()
            },
            detail: error
                .cloned()
                .unwrap_or_else(|| patch.feature.description.to_owned()),
        }];
        if enabled {
            for letter in (b'A'..=b'Z').map(char::from) {
                let path = directory.join(letter.to_string());
                let state = crate::coexist::exists(&path);
                let exists = state.as_ref().is_ok_and(|exists| *exists);
                items.push(Item {
                    marker: if exists { "■" } else { "□" },
                    label: if state.is_err() {
                        letter.to_string().red()
                    } else {
                        style(letter.to_string())
                    },
                    value: if state.is_err() {
                        "不可用".to_owned()
                    } else if exists {
                        "已创建".to_owned()
                    } else {
                        "未创建".to_owned()
                    },
                    detail: state.err().map_or_else(
                        || store::display(&path.join("Weixin.exe")),
                        |error| error.to_string(),
                    ),
                });
            }
        }
        items.push(Item::action(style("返回")));
        if !screen.select(
            patch.feature.name,
            &detail,
            &items,
            &mut selected,
            &notice,
            "方向键 选择\n回车键 切换\nEsc 返回",
        )? || selected == items.len() - 1
        {
            return Ok(());
        }
        if selected == 0 {
            if let Some(error) = patch.issue(store) {
                notice = error.clone();
                continue;
            }
            (pending, notice) = screen.change(
                store,
                prepared,
                Change::Feature(patch, (!enabled).then_some(0)),
                pending,
            )?;
            if screen.exiting {
                return Ok(());
            }
            continue;
        }
        pending = false;
        let letter = char::from(b'A' + selected as u8 - 1);
        let path = directory.join(letter.to_string());
        let exists = match crate::coexist::exists(&path) {
            Ok(exists) => exists,
            Err(error) => {
                notice = error.to_string();
                continue;
            }
        };
        let result = screen.work(
            if exists {
                "删除共存入口"
            } else {
                "创建共存入口"
            },
            &detail,
            |progress| {
                if exists {
                    crate::coexist::remove(&path, progress)
                } else {
                    crate::coexist::create(&path, progress)
                }
            },
        );
        notice = match result {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        };
        if screen.exiting {
            return Ok(());
        }
    }
}

fn sound(
    screen: &mut Screen,
    store: &Store,
    patch: &feature::Prepared,
    sound: &crate::sound::Sound,
) -> Result<()> {
    let path = sound.path(&store.target)?;
    let detail = format!(" -- {}", version(&store.target));
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let description = format!("{}\n重启微信后生效", store::display(&path));
        let mut replace = Item::action(style("更换提示音"));
        replace.detail = description.clone();
        let mut restore = Item::action(style("恢复默认"));
        restore.detail = description;
        let items = [replace, restore, Item::action(style("返回"))];
        if !screen.select(
            sound.name,
            &detail,
            &items,
            &mut selected,
            &notice,
            "方向键 选择\n回车键 确定\nEsc 返回",
        )? || selected == items.len() - 1
        {
            return Ok(());
        }
        let file = if selected == 0 {
            match crate::sound::pick(sound) {
                Ok(Some(path)) => Some(path),
                Ok(None) => continue,
                Err(error) => {
                    notice = error.to_string();
                    continue;
                }
            }
        } else {
            None
        };
        notice = match screen.work(sound.name, &detail, |progress| match selected {
            0 => sound.import(store, file.as_deref().ok_or("缺少音频文件")?, progress),
            1 => sound.restore(store, patch, progress),
            _ => unreachable!(),
        }) {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        };
        if screen.exiting {
            return Ok(());
        }
    }
}

fn sounds(
    screen: &mut Screen,
    store: &mut Store,
    prepared: &[feature::Prepared],
    patch: &feature::Prepared,
) -> Result<()> {
    let detail = format!(" -- {}", version(&store.target));
    let mut selected = 0;
    let mut pending = false;
    let mut notice = String::new();
    loop {
        let enabled = patch.state(store).enabled();
        let error = patch.issue(store);
        let mut items = vec![Item {
            marker: if enabled { "■" } else { "□" },
            label: if error.is_some() {
                "外置提示音支持".to_owned().red()
            } else if pending {
                "外置提示音支持".to_owned().dark_green()
            } else {
                style("外置提示音支持".to_owned())
            },
            value: if pending {
                occupied(if enabled { "关闭" } else { "开启" })
            } else if error.is_some() {
                "不可用".to_owned()
            } else if enabled {
                "已启用".to_owned()
            } else {
                "未启用".to_owned()
            },
            detail: error
                .cloned()
                .unwrap_or_else(|| "启用后可以编辑外置提示音".to_owned()),
        }];
        if enabled {
            for sound in crate::sound::SOUNDS {
                let mut item = Item::action(style(sound.name));
                item.detail = store::display(&sound.path(&store.target)?);
                items.push(item);
            }
        }
        items.push(Item::action(style("返回")));
        if !screen.select(
            patch.feature.name,
            &detail,
            &items,
            &mut selected,
            &notice,
            "方向键 选择\n回车键 确定\nEsc 返回",
        )? || selected == items.len() - 1
        {
            return Ok(());
        }
        if selected != 0 {
            pending = false;
            notice = match sound(screen, store, patch, &crate::sound::SOUNDS[selected - 1]) {
                Ok(()) => String::new(),
                Err(error) => error.to_string(),
            };
            if screen.exiting {
                return Ok(());
            }
            continue;
        }
        if let Some(error) = patch.issue(store) {
            notice = error.clone();
            continue;
        }
        (pending, notice) = screen.change(
            store,
            prepared,
            Change::Feature(patch, (!enabled).then_some(0)),
            pending,
        )?;
        if screen.exiting {
            return Ok(());
        }
    }
}

fn icon(
    screen: &mut Screen,
    store: &mut Store,
    prepared: &[feature::Prepared],
    patch: &feature::Prepared,
) -> Result<()> {
    let detail = format!(" -- {}", version(&store.target));
    let path = crate::icon::path(&store.target)?;
    let mut selected = 0;
    let mut pending = false;
    let mut notice = String::new();
    loop {
        let enabled = patch.state(store).enabled();
        let error = patch.issue(store);
        let mut items = vec![Item {
            marker: if enabled { "■" } else { "□" },
            label: if error.is_some() {
                "外置图标支持".to_owned().red()
            } else if pending {
                "外置图标支持".to_owned().dark_green()
            } else {
                style("外置图标支持".to_owned())
            },
            value: if pending {
                occupied(if enabled { "关闭" } else { "开启" })
            } else if error.is_some() {
                "不可用".to_owned()
            } else if enabled {
                "已启用".to_owned()
            } else {
                "未启用".to_owned()
            },
            detail: error
                .cloned()
                .unwrap_or_else(|| patch.feature.description.to_owned()),
        }];
        if enabled {
            for label in ["更换图标", "恢复默认"] {
                let mut item = Item::action(style(label));
                item.detail = format!("{}\n重启微信后生效", store::display(&path));
                items.push(item);
            }
        }
        items.push(Item::action(style("返回")));
        if !screen.select(
            patch.feature.name,
            &detail,
            &items,
            &mut selected,
            &notice,
            "方向键 选择\n回车键 确定\nEsc 返回",
        )? || selected == items.len() - 1
        {
            return Ok(());
        }
        if selected == 0 {
            if let Some(error) = patch.issue(store) {
                notice = error.clone();
                continue;
            }
            (pending, notice) = screen.change(
                store,
                prepared,
                Change::Feature(patch, (!enabled).then_some(0)),
                pending,
            )?;
            if screen.exiting {
                return Ok(());
            }
            continue;
        }
        pending = false;
        let file = if selected == 1 {
            match crate::icon::pick() {
                Ok(Some(path)) => Some(path),
                Ok(None) => continue,
                Err(error) => {
                    notice = error.to_string();
                    continue;
                }
            }
        } else {
            None
        };
        notice = match screen.work(patch.feature.name, &detail, |progress| match selected {
            1 => crate::icon::import(store, file.as_deref().ok_or("缺少图片文件")?, progress),
            2 => crate::icon::restore(store, patch, progress),
            _ => unreachable!(),
        }) {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        };
        if screen.exiting {
            return Ok(());
        }
    }
}

fn configure(screen: &mut Screen, path: &Path) -> Result<()> {
    let detail = format!(" -- {}", version(path));
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
    let mut notice = store
        .files
        .values()
        .filter_map(|file| file.source_issue.as_deref())
        .collect::<Vec<_>>()
        .join("\n");
    let mut pending = None;
    loop {
        let outdated = store.files.values().any(|file| file.issue.is_some());
        let offset = usize::from(outdated);
        let mut items: Vec<Item> = prepared
            .iter()
            .enumerate()
            .map(|(index, patch)| {
                if [
                    crate::coexist::FEATURE.id,
                    crate::sound::FEATURE.id,
                    crate::icon::FEATURE.id,
                ]
                .contains(&patch.feature.id)
                {
                    let mut item = Item::action(style(patch.feature.name));
                    item.detail = patch.feature.description.to_owned();
                    return item;
                }
                let error = patch.issue(&store);
                let state = patch.state(&store);
                let multiple = patch.edits.as_ref().is_ok_and(|modes| modes.len() > 1);
                let label = patch.feature.name.to_owned();
                let value = if pending == Some(index) {
                    let action = match patch.next(&store) {
                        None if patch.feature.id == crate::time::FEATURE.id => {
                            "恢复默认".to_owned()
                        }
                        None => "关闭".to_owned(),
                        Some(mode) if multiple => {
                            format!("切换为{}", patch.label(feature::State::Enabled(mode)))
                        }
                        Some(_) => "开启".to_owned(),
                    };
                    occupied(&action)
                } else {
                    if error.is_some() {
                        "不可用"
                    } else if multiple {
                        patch.label(state)
                    } else if state.enabled() {
                        "已启用"
                    } else {
                        "未启用"
                    }
                    .to_owned()
                };
                Item {
                    marker: if error.is_none() && state.enabled() {
                        "■"
                    } else {
                        "□"
                    },
                    label: if error.is_some() {
                        label.red()
                    } else if pending == Some(index) {
                        label.dark_green()
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
        if outdated {
            let mut update = Item::action("更新补丁".dark_green());
            if pending == Some(prepared.len() + 1) {
                update.value = occupied("更新");
            }
            items.insert(0, update);
        }
        let mut restore = Item::action(style("恢复原版"));
        restore.detail = "还原已备份的原版文件".to_owned();
        if pending == Some(prepared.len()) {
            restore.label = restore.label.dark_green();
            restore.value = occupied("恢复");
        } else if store.changed().is_empty() {
            restore.value = if store.files.values().any(|file| file.source_issue.is_some()) {
                "缺少原版备份"
            } else {
                "已是原版"
            }
            .to_owned();
        }
        items.extend([restore, Item::action(style("返回"))]);
        if !screen.select(
            "功能",
            &detail,
            &items,
            &mut selected,
            &notice,
            "方向键 选择\n回车键 切换\nEsc 返回",
        )? {
            return Ok(());
        };
        let index = if outdated && selected == 0 {
            prepared.len() + 1
        } else {
            selected - offset
        };
        let change = if outdated && selected == 0 {
            let targets: Vec<_> = store.files.keys().cloned().collect();
            if !screen.sources(&mut store, &targets)? {
                if screen.exiting {
                    return Ok(());
                }
                continue;
            }
            match screen.work("准备更新", &detail, |progress| {
                feature::rebuild(&store, &prepared, progress)
            }) {
                Ok(Some(contents)) => Change::Update(contents),
                Ok(None) => return Ok(()),
                Err(error) => {
                    notice = error.to_string();
                    continue;
                }
            }
        } else if let Some(patch) = prepared.get(index) {
            if [
                crate::coexist::FEATURE.id,
                crate::sound::FEATURE.id,
                crate::icon::FEATURE.id,
            ]
            .contains(&patch.feature.id)
            {
                pending = None;
                let result = if patch.feature.id == crate::coexist::FEATURE.id {
                    coexist(screen, &mut store, &prepared, patch)
                } else if patch.feature.id == crate::sound::FEATURE.id {
                    sounds(screen, &mut store, &prepared, patch)
                } else {
                    icon(screen, &mut store, &prepared, patch)
                };
                notice = match result {
                    Ok(()) => String::new(),
                    Err(error) => error.to_string(),
                };
                if screen.exiting {
                    return Ok(());
                }
                continue;
            }
            if let Some(error) = patch.issue(&store) {
                notice = error.clone();
                continue;
            }
            Change::Feature(patch, patch.next(&store))
        } else if index == prepared.len() {
            Change::Restore
        } else {
            return Ok(());
        };
        let (retry, message) =
            screen.change(&mut store, &prepared, change, pending == Some(index))?;
        pending = retry.then_some(index);
        notice = message;
        if outdated && store.files.values().all(|file| file.issue.is_none()) {
            selected = selected.saturating_sub(1);
        }
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
            .map(|file| Item {
                marker: ">",
                label: style(version(file)),
                value: String::new(),
                detail: store::display(file),
            })
            .collect();
        items.extend([
            Item::action(style("手动选择")),
            Item::action(style("刷新列表")),
            Item::action(style("关于")),
            Item::action("退出".red()),
        ]);
        if !screen.select(
            "选择版本",
            "",
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
