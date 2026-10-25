use std::{
    collections::BTreeMap,
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

const ROOT: &str = "gui";
const ICON: &str = "gui/icon/tray_window_icon/wechat_icon_64x64";

pub const FEATURE: Feature = Feature {
    id: "tray-icon",
    name: "自定义托盘图标",
    description: "替换微信托盘图标",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

pub fn path(target: &Path) -> Result<PathBuf> {
    Ok(target
        .parent()
        .ok_or("目标文件缺少父目录")?
        .join(format!("{ICON}.png")))
}

fn original<'a>(store: &'a Store, patch: &Prepared) -> Result<&'a [u8]> {
    let range = patch
        .resources
        .get(&store.target)
        .and_then(|resources| resources.get(ICON))
        .ok_or("找不到内置托盘图标")?;
    store.files[&store.target]
        .original
        .get(range.clone())
        .ok_or_else(|| "图标资源超出文件范围".into())
}

pub fn import(store: &Store, source: &Path, progress: &Progress) -> Result<()> {
    let data = fs::read(source)?;
    let step = progress.activity("读取图片");
    step.detail(store::display(source));
    let data = decode(data, progress)?;
    step.finish(format!("{} 字节", data.len()));
    let path = path(&store.target)?;
    fs::create_dir_all(path.parent().ok_or("图标文件缺少父目录")?)?;
    store::write(&path, &data, progress)
}

pub fn restore(store: &Store, patch: &Prepared, progress: &Progress) -> Result<()> {
    let path = path(&store.target)?;
    fs::create_dir_all(path.parent().ok_or("图标文件缺少父目录")?)?;
    store::write(&path, original(store, patch)?, progress)
}

pub fn initialize(store: &Store, patch: &Prepared, progress: &Progress) -> Result<()> {
    let path = path(&store.target)?;
    match fs::read(&path) {
        Ok(data) => validate(&data, progress)
            .map_err(|error| format!("{}：{error}", store::display(&path)))?,
        Err(error) if error.kind() == ErrorKind::NotFound => restore(store, patch, progress)?,
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub fn cleanup(store: &mut Store, prepared: &[Prepared], progress: &Progress) -> Result<()> {
    let path = path(&store.target)?;
    let step = progress.activity("清理默认图标");
    match fs::read(&path) {
        Ok(data) => {
            let analyzed;
            let patch = match prepared.iter().find(|patch| patch.feature.id == FEATURE.id) {
                Some(patch) => patch,
                None => {
                    analyzed = feature::analyze(store, &[FEATURE], progress)?;
                    analyzed.first().ok_or("找不到图标分析结果")?
                }
            };
            patch.edits.as_ref().map_err(|error| error.clone())?;
            if data == original(store, patch)? {
                progress.check()?;
                fs::remove_file(&path)?;
                step.record(format!("删除 {}", store::display(&path)));
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for directory in path
        .ancestors()
        .skip(1)
        .take_while(|directory| Some(*directory) != store.target.parent())
    {
        progress.check()?;
        let mut entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let empty = entries.next().transpose()?.is_none();
        drop(entries);
        if empty {
            fs::remove_dir(directory)?;
            step.record(format!("删除 {}", store::display(directory)));
        }
    }
    step.finish("默认图标清理完成");
    Ok(())
}

pub fn pick() -> Result<Option<PathBuf>> {
    crate::dialog::pick("更换托盘图标", Vec::new())
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let resource = format!(":/{ICON}\0");
    let paths = image.find(ICON, resource.as_bytes(), progress)?;
    if paths.is_empty() {
        return Err("找不到托盘图标资源路径".into());
    }
    Ok(Symbols::from([
        (ROOT.to_owned(), qrc::find(image, ROOT, progress)?),
        (ICON.to_owned(), paths),
    ]))
}

struct Scan {
    symbols: Symbols,
    qrc: qrc::Scan,
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    let qrc = qrc::Scan::new(
        symbols[ROOT].clone(),
        BTreeMap::from([(format!("/{ICON}.png"), ICON.to_owned())]),
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
        let range = self.qrc.resources.get(ICON).ok_or("找不到内置托盘图标")?;
        let step = progress.activity("准备托盘图标");
        step.record(format!(
            "{ICON}；offset 0x{:08X}；{} 字节",
            range.start,
            range.len(),
        ));
        let edits = self.symbols[ICON]
            .iter()
            .map(|address| {
                let offset = image.offset(*address)?;
                Ok(Edit {
                    range: offset..offset + 1,
                    bytes: vec![b'.'],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        step.finish(format!("{} 资源路径", edits.len()));
        Ok(vec![Mode::enabled(edits)])
    }
}

#[cfg(windows)]
struct Runtime;

#[cfg(windows)]
impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe { windows::Win32::System::Com::CoUninitialize() };
    }
}

#[cfg(windows)]
fn decode(data: Vec<u8>, progress: &Progress) -> Result<Vec<u8>> {
    use std::ptr::{null, null_mut};

    use windows::Win32::{
        Graphics::Imaging::{
            CLSID_WICImagingFactory2, GUID_ContainerFormatIco, GUID_ContainerFormatPng,
            IWICImagingFactory, WICBitmapCacheOnLoad, WICBitmapEncoderNoCache,
            WICConvertBitmapSource, WICDecodeMetadataCacheOnLoad,
        },
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            STREAM_SEEK_END, STREAM_SEEK_SET, StructuredStorage::CreateStreamOnHGlobal,
        },
    };

    progress.check()?;
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
    let _runtime = Runtime;
    unsafe {
        let factory: IWICImagingFactory =
            CoCreateInstance(&CLSID_WICImagingFactory2, None, CLSCTX_INPROC_SERVER)?;
        let stream = factory.CreateStream()?;
        stream.InitializeFromMemory(&data)?;
        let decoder =
            factory.CreateDecoderFromStream(&stream, null(), WICDecodeMetadataCacheOnLoad)?;
        let mut source = decoder.GetFrame(0)?;
        let format = decoder.GetContainerFormat()?;
        if format == GUID_ContainerFormatPng {
            factory.CreateBitmapFromSource(&source, WICBitmapCacheOnLoad)?;
            return Ok(data);
        }
        if format == GUID_ContainerFormatIco {
            let (mut width, mut height) = (0, 0);
            source.GetSize(&mut width, &mut height)?;
            let mut size = u64::from(width) * u64::from(height);
            for index in 1..decoder.GetFrameCount()? {
                progress.check()?;
                let frame = decoder.GetFrame(index)?;
                frame.GetSize(&mut width, &mut height)?;
                let area = u64::from(width) * u64::from(height);
                if area > size {
                    source = frame;
                    size = area;
                }
            }
        }
        let output = CreateStreamOnHGlobal(Default::default(), true)?;
        let encoder = factory.CreateEncoder(&GUID_ContainerFormatPng, null())?;
        encoder.Initialize(&output, WICBitmapEncoderNoCache)?;
        let mut frame = None;
        encoder.CreateNewFrame(&mut frame, null_mut())?;
        let frame = frame.ok_or("无法创建图像帧")?;
        frame.Initialize(None)?;
        let mut format = source.GetPixelFormat()?;
        frame.SetPixelFormat(&mut format)?;
        let bitmap = WICConvertBitmapSource(&format, &source)?;
        frame.WriteSource(&bitmap, null())?;
        frame.Commit()?;
        encoder.Commit()?;
        let mut size = 0;
        output.Seek(0, STREAM_SEEK_END, Some(&mut size))?;
        output.Seek(0, STREAM_SEEK_SET, None)?;
        let mut data = vec![0; usize::try_from(size)?];
        output
            .Read(data.as_mut_ptr().cast(), data.len().try_into()?, None)
            .ok()?;
        Ok(data)
    }
}

#[cfg(not(windows))]
fn decode(_data: Vec<u8>, _progress: &Progress) -> Result<Vec<u8>> {
    Err("图片转换需要 Windows".into())
}

#[cfg(windows)]
fn validate(data: &[u8], progress: &Progress) -> Result<()> {
    use std::ptr::null;

    use windows::Win32::{
        Graphics::Imaging::{
            CLSID_WICImagingFactory2, GUID_ContainerFormatPng, IWICImagingFactory,
            WICBitmapCacheOnLoad, WICDecodeMetadataCacheOnLoad,
        },
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        },
    };

    progress.check()?;
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
    let _runtime = Runtime;
    unsafe {
        let factory: IWICImagingFactory =
            CoCreateInstance(&CLSID_WICImagingFactory2, None, CLSCTX_INPROC_SERVER)?;
        let stream = factory.CreateStream()?;
        stream.InitializeFromMemory(data)?;
        let decoder =
            factory.CreateDecoderFromStream(&stream, null(), WICDecodeMetadataCacheOnLoad)?;
        if decoder.GetContainerFormat()? != GUID_ContainerFormatPng {
            return Err("图标文件需要 PNG 格式".into());
        }
        factory.CreateBitmapFromSource(&decoder.GetFrame(0)?, WICBitmapCacheOnLoad)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate(_data: &[u8], _progress: &Progress) -> Result<()> {
    Err("图片读取需要 Windows".into())
}
