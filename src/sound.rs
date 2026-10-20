use std::{
    fs,
    io::ErrorKind,
    ops::Range,
    path::{Path, PathBuf},
};

use crate::{
    Result,
    feature::{self, Analysis, Edit, Feature, Mode, Prepared, Resources, Target},
    image::{Image, References, Symbols},
    progress::Progress,
    qrc,
    store::{self, Store},
};

const ROOT: &str = "multimedia";
const PREFIX: &str = ":/multimedia/wav/";

pub const FEATURE: Feature = Feature {
    id: "sound",
    name: "自定义提示音",
    description: "替换消息提示音",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

pub struct Sound {
    pub id: &'static str,
    pub name: &'static str,
    file: &'static str,
}

pub const SOUNDS: &[Sound] = &[
    Sound {
        id: "message",
        name: "新消息",
        file: "wechat_notify.wav",
    },
    Sound {
        id: "ring",
        name: "来电",
        file: "voip_phone_ringing.wav",
    },
    Sound {
        id: "call",
        name: "通话结束",
        file: "voip_phone_ending.wav",
    },
    Sound {
        id: "lock",
        name: "锁定",
        file: "lock_closing.wav",
    },
    Sound {
        id: "unlock",
        name: "解锁",
        file: "lock_opening.wav",
    },
];

impl Sound {
    pub fn path(&self, target: &Path) -> Result<PathBuf> {
        Ok(target
            .parent()
            .ok_or("目标文件缺少父目录")?
            .join(ROOT)
            .join("wav")
            .join(self.file))
    }

    pub fn original<'a>(&self, store: &'a Store, patch: &Prepared) -> Result<&'a [u8]> {
        let range = patch
            .resources
            .get(&store.target)
            .and_then(|resources| resources.get(self.file))
            .ok_or_else(|| format!("找不到{}的内置音频", self.name))?;
        store.files[&store.target]
            .original
            .get(range.clone())
            .ok_or_else(|| "音频资源超出文件范围".into())
    }

    pub fn import(&self, store: &Store, source: &Path, progress: &Progress) -> Result<()> {
        let data = decode(source, progress)?;
        let path = self.path(&store.target)?;
        fs::create_dir_all(path.parent().ok_or("音频文件缺少父目录")?)?;
        store::write(&path, &data, progress)
    }

    pub fn restore(&self, store: &Store, patch: &Prepared, progress: &Progress) -> Result<()> {
        let path = self.path(&store.target)?;
        fs::create_dir_all(path.parent().ok_or("音频文件缺少父目录")?)?;
        store::write(&path, self.original(store, patch)?, progress)
    }
}

pub fn get(id: &str) -> Result<&'static Sound> {
    SOUNDS
        .iter()
        .find(|sound| sound.id == id)
        .ok_or_else(|| format!("未知提示音：{id}").into())
}

#[cfg(windows)]
pub fn pick(sound: &Sound) -> Result<Option<PathBuf>> {
    Ok(native_dialog::DialogBuilder::file()
        .set_title(format!("更换提示音：{}", sound.name))
        .open_single_file()
        .show()?)
}

#[cfg(not(windows))]
pub fn pick(_sound: &Sound) -> Result<Option<PathBuf>> {
    Err("系统文件选择器需要 Windows".into())
}

pub fn initialize(store: &Store, patch: &Prepared, progress: &Progress) -> Result<()> {
    for sound in SOUNDS {
        progress.check()?;
        let path = sound.path(&store.target)?;
        match fs::read(&path) {
            Ok(data) => {
                validate(&data).map_err(|error| format!("{}：{error}", store::display(&path)))?
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                sound.restore(store, patch, progress)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn cleanup(store: &mut Store, prepared: &[Prepared], progress: &Progress) -> Result<()> {
    let mut files = Vec::new();
    for sound in SOUNDS {
        let path = sound.path(&store.target)?;
        if path.try_exists()? {
            files.push((sound, path));
        }
    }
    let step = progress.activity("清理默认音效");
    if !files.is_empty() {
        let analyzed;
        let patch = match prepared.iter().find(|patch| patch.feature.id == FEATURE.id) {
            Some(patch) => patch,
            None => {
                analyzed = feature::analyze(store, &[FEATURE], progress)?;
                analyzed.first().ok_or("找不到提示音分析结果")?
            }
        };
        patch.edits.as_ref().map_err(|error| error.clone())?;
        for (sound, path) in files {
            progress.check()?;
            let data = match fs::read(&path) {
                Ok(data) => data,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if data == sound.original(store, patch)? {
                fs::remove_file(&path)?;
                step.record(format!("删除 {}", store::display(&path)));
            }
        }
    }
    let directory = store
        .target
        .parent()
        .ok_or("目标文件缺少父目录")?
        .join(ROOT);
    for path in [directory.join("wav"), directory] {
        progress.check()?;
        let mut entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let empty = entries.next().transpose()?.is_none();
        drop(entries);
        if empty {
            fs::remove_dir(&path)?;
            step.record(format!("删除 {}", store::display(&path)));
        }
    }
    step.finish("默认音效清理完成");
    Ok(())
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let paths = image.find(PREFIX, PREFIX.as_bytes(), progress)?;
    if paths.is_empty() {
        return Err("找不到提示音资源路径".into());
    }
    Ok(Symbols::from([
        (ROOT.to_owned(), qrc::find(image, ROOT, progress)?),
        (PREFIX.to_owned(), paths),
    ]))
}

struct Scan {
    symbols: Symbols,
    qrc: qrc::Scan,
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    let qrc = qrc::Scan::new(
        symbols[ROOT].clone(),
        SOUNDS
            .iter()
            .map(|sound| (format!("/{ROOT}/wav/{}", sound.file), sound.file.to_owned()))
            .collect(),
    );
    Box::new(Scan { symbols, qrc })
}

impl Analysis for Scan {
    fn resources(&self) -> Resources {
        self.qrc.resources.clone()
    }

    fn visit(
        &mut self,
        image: &Image<'_>,
        function: &Range<u64>,
        _references: &References,
        progress: &Progress,
    ) -> Result<Vec<Edit>> {
        self.qrc.visit(image, function, progress)?;
        Ok(Vec::new())
    }

    fn finish(
        self: Box<Self>,
        image: &Image<'_>,
        _references: &References,
        progress: &Progress,
    ) -> Result<Vec<Mode>> {
        let step = progress.activity("准备提示音资源");
        for sound in SOUNDS {
            let range = self
                .qrc
                .resources
                .get(sound.file)
                .ok_or_else(|| format!("找不到{}音频资源", sound.name))?;
            validate(image.data(image.address(range.start)?, range.len())?)?;
            step.record(format!(
                "{}；{}；offset 0x{:08X}；{} 字节",
                sound.name,
                sound.file,
                range.start,
                range.len(),
            ));
        }
        let edits = self.symbols[PREFIX]
            .iter()
            .map(|address| {
                let offset = image.offset(*address)?;
                Ok(Edit {
                    range: offset..offset + 1,
                    bytes: vec![b'.'],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        step.finish(format!("{} 音频；{} 资源路径", SOUNDS.len(), edits.len()));
        Ok(vec![Mode::enabled(edits)])
    }
}

fn header(size: usize) -> Result<[u8; 44]> {
    let size = u32::try_from(size)?;
    let mut bytes = [0; 44];
    bytes[..4].copy_from_slice(b"RIFF");
    bytes[4..8].copy_from_slice(&size.checked_add(36).ok_or("WAV 长度溢出")?.to_le_bytes());
    bytes[8..16].copy_from_slice(b"WAVEfmt ");
    bytes[16..20].copy_from_slice(&16u32.to_le_bytes());
    bytes[20..22].copy_from_slice(&1u16.to_le_bytes());
    bytes[22..24].copy_from_slice(&2u16.to_le_bytes());
    bytes[24..28].copy_from_slice(&44100u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&176400u32.to_le_bytes());
    bytes[32..34].copy_from_slice(&4u16.to_le_bytes());
    bytes[34..36].copy_from_slice(&16u16.to_le_bytes());
    bytes[36..40].copy_from_slice(b"data");
    bytes[40..44].copy_from_slice(&size.to_le_bytes());
    Ok(bytes)
}

fn validate(data: &[u8]) -> Result<()> {
    let size = data.len().checked_sub(44).ok_or("WAV 文件头不完整")?;
    if !size.is_multiple_of(4) || data[..44] != header(size)? {
        return Err("音频需要 44.1 kHz、双声道、16 位 PCM 和标准 WAV 文件头".into());
    }
    Ok(())
}

#[cfg(windows)]
fn decode(path: &Path, progress: &Progress) -> Result<Vec<u8>> {
    use std::{os::windows::ffi::OsStrExt, ptr::null_mut, slice};

    use windows::{
        Win32::{
            Media::MediaFoundation::{
                MF_MT_AUDIO_AVG_BYTES_PER_SECOND, MF_MT_AUDIO_BITS_PER_SAMPLE,
                MF_MT_AUDIO_BLOCK_ALIGNMENT, MF_MT_AUDIO_NUM_CHANNELS,
                MF_MT_AUDIO_SAMPLES_PER_SECOND, MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE,
                MF_SOURCE_READER_ALL_STREAMS, MF_SOURCE_READER_FIRST_AUDIO_STREAM,
                MF_SOURCE_READERF_ENDOFSTREAM, MF_SOURCE_READERF_ERROR, MF_VERSION,
                MFAudioFormat_PCM, MFCreateMediaType, MFCreateSourceReaderFromURL,
                MFMediaType_Audio, MFSTARTUP_FULL, MFShutdown, MFStartup,
            },
            System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize},
        },
        core::PCWSTR,
    };

    struct Runtime(bool);

    impl Drop for Runtime {
        fn drop(&mut self) {
            unsafe {
                if self.0 {
                    let _ = MFShutdown();
                }
                CoUninitialize();
            }
        }
    }

    progress.check()?;
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
    let mut runtime = Runtime(false);
    unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL)? };
    runtime.0 = true;
    // The source reader expects regular Win32 paths.
    let path = std::path::absolute(path)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let wide: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
    let step = progress.activity("转换音频");
    step.detail(name.as_ref());
    let mut output = header(0)?.to_vec();
    unsafe {
        let reader = MFCreateSourceReaderFromURL(PCWSTR(wide.as_ptr()), None)?;
        let stream = MF_SOURCE_READER_FIRST_AUDIO_STREAM.0 as u32;
        reader.SetStreamSelection(MF_SOURCE_READER_ALL_STREAMS.0 as u32, false)?;
        reader.SetStreamSelection(stream, true)?;
        let media = MFCreateMediaType()?;
        media.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio)?;
        media.SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_PCM)?;
        for (attribute, value) in [
            (MF_MT_AUDIO_NUM_CHANNELS, 2),
            (MF_MT_AUDIO_SAMPLES_PER_SECOND, 44100),
            (MF_MT_AUDIO_BITS_PER_SAMPLE, 16),
            (MF_MT_AUDIO_BLOCK_ALIGNMENT, 4),
            (MF_MT_AUDIO_AVG_BYTES_PER_SECOND, 176400),
        ] {
            media.SetUINT32(&attribute, value)?;
        }
        reader.SetCurrentMediaType(stream, None, &media)?;
        loop {
            progress.check()?;
            let mut flags = 0;
            let mut sample = None;
            reader.ReadSample(stream, 0, None, Some(&mut flags), None, Some(&mut sample))?;
            if flags & MF_SOURCE_READERF_ERROR.0 as u32 != 0 {
                return Err("音频解码失败".into());
            }
            if let Some(sample) = sample {
                let buffer = sample.ConvertToContiguousBuffer()?;
                let mut data = null_mut();
                let mut length = 0;
                buffer.Lock(&mut data, None, Some(&mut length))?;
                if length != 0 {
                    output.extend_from_slice(slice::from_raw_parts(data, length as usize));
                }
                buffer.Unlock()?;
            }
            if step.sample() {
                step.detail(format!("{name}；{} 个采样帧", (output.len() - 44) / 4));
            }
            if flags & MF_SOURCE_READERF_ENDOFSTREAM.0 as u32 != 0 {
                break;
            }
        }
    }
    let size = output.len() - 44;
    output[..44].copy_from_slice(&header(size)?);
    validate(&output)?;
    step.finish(format!("44100 Hz；2 声道；PCM 16；{} 个采样帧", size / 4));
    Ok(output)
}

#[cfg(not(windows))]
fn decode(_path: &Path, _progress: &Progress) -> Result<Vec<u8>> {
    Err("音频转换需要 Windows".into())
}
