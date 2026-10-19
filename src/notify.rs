use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use iced_x86::{
    Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register,
    code_asm::{
        AsmMemoryOperand, AsmRegister64, CodeAssembler, CodeLabel, al, byte_ptr, dword_ptr, eax,
        ecx, edi, edx, ptr, qword_ptr, r8, r8d, r9, r9d, r10, r14, rax, rbx, rcx, rdi, rdx, rsi,
        rsp, word_ptr, xmm0, xmm1,
    },
};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, functions},
    progress::Progress,
    xlog,
};

const INIT: &str = "virtual mmui::MessageNotificationUIService::OnInit";
const LOAD: &str = "mmui::MessageNotificationUIService::LoadSystemTrayIfNeeded";
const CREATE: &str = "mmui::MessageNotificationUIService::CreateTrayWindowIfNeed";
const TIMER: &str = "mmui::MessageNotificationUIService::InitializeCheckHoverTimerIfNeed";
const SHOW: &str = "mmui::MessageNotificationUIService::TryShowTrayHoverWindow";
const HOVER: &str = "mmui::MessageNotificationUIService::TrayMouseHovered";
const HIDE: &str = "mmui::MessageNotificationUIService::HideTrayWindow";
const CLOSE: &str = "mmui::MessageNotificationUIService::OnHideUnreadWindow";
const DESTROY: &str = "virtual mmui::MessageNotificationUIService::~MessageNotificationUIService";
const UPDATE: &str = "mmui::MessageNotificationUIService::UpdateSession";
const FILTER: &str = "mmui::MessageNotificationUIService::ShouldFilter";
const ADD: &str = "mmui::MessageNotificationUIService::AddOrUpdateUnreadSession";
const WINDOW: &str = "mmui::UnreadMessageHoverWindow::UnreadMessageHoverWindow";
const ROUTER: &str = "mmui::AppRouter::Navigate";
const SUMMARY: &str = "virtual kernel::xweb::JsApiReadSubscriptionSessionSummary::Invoke";
const PREVIEW: &str = "mmui::ChatMasterViewModel::UpdateBrandDisorderIfNeeded";
const LOGIN: &str = "kernel::KernelPrivate::CoLogin";
const TASK: &str = "kernel::service::AgentCheckService::OnClientConfigReady";
const HEAD: &str = "mmui::ContactHeadView::SetUserName";
const AVATAR: &str = "kernel::service::ContactService::GetContactSmallHeadUrl";
const PATHS: &str = "kernel::datapathutil::InitDirs";
const MESSAGES: &str = "InitNewMessageNotify";
const DELETED: &str = "delete all message for:";
const FUNCTIONS: &[&str] = &[
    INIT, LOAD, CREATE, TIMER, SHOW, HOVER, HIDE, CLOSE, DESTROY, UPDATE, FILTER, ADD, WINDOW,
    ROUTER, SUMMARY, PREVIEW, LOGIN, TASK, HEAD, AVATAR, PATHS, MESSAGES, DELETED,
];
const CAPTURE: &str = "WebRTC.DesktopCapture.Win.WgcCaptureSessionStartResult";
const FACTORY: &str = "RoGetActivationFactory";
const STRING: &str = "WindowsCreateString";
const STRING_DELETE: &str = "WindowsDeleteString";
const STRING_BUFFER: &str = "WindowsGetStringRawBuffer";
const MANAGER: &str = "Microsoft.Windows.AppNotifications.AppNotificationManager";
const BUILDER: &str = "Microsoft.Windows.AppNotifications.Builder.AppNotificationBuilder";
const FAMILY: &str = "Microsoft.WindowsAppRuntime.2_8wekyb3d8bbwe";
const MANAGER_IID: [u8; 16] = [
    0x8d, 0x0d, 0xfc, 0x6c, 0xa3, 0x84, 0x92, 0x55, 0xb4, 0xc6, 0xe3, 0xe7, 0xe7, 0xc6, 0x80, 0xe4,
];
const BUILDER_IID: [u8; 16] = [
    0x1f, 0xd3, 0x01, 0xe8, 0x03, 0xce, 0x5c, 0x50, 0xad, 0xec, 0x8a, 0x02, 0x72, 0x4e, 0xc9, 0xde,
];
const ARGUMENTS_IID: [u8; 16] = [
    0x9b, 0x6b, 0xc0, 0x52, 0x50, 0x2c, 0x37, 0x50, 0x94, 0x16, 0xa3, 0xbe, 0x47, 0xb9, 0xd5, 0xbd,
];
const FACTORY_IID: [u8; 16] = [0x35, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
const HANDLER_IID: [u8; 16] = [
    0xb0, 0xb0, 0x09, 0x99, 0x99, 0xef, 0xce, 0x5b, 0x97, 0xc8, 0x78, 0x19, 0x0d, 0x41, 0x1b, 0x61,
];
const URI_IID: [u8; 16] = [
    0x6f, 0x79, 0xa9, 0x44, 0x3e, 0x72, 0xdf, 0x4f, 0xa2, 0x18, 0x03, 0x3e, 0x75, 0xb0, 0xc0, 0x84,
];

pub const FEATURE: Feature = Feature {
    id: "notify",
    name: "系统通知",
    description: "将托盘消息菜单改为接入系统通知",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

#[cfg(windows)]
pub fn initialize(progress: &Progress) -> Result<()> {
    use windows::{
        Foundation::Uri,
        Management::Deployment::{DeploymentOptions, PackageManager},
        System::ProcessorArchitecture,
        Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize},
        core::HSTRING,
    };

    struct Runtime;

    impl Drop for Runtime {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }

    progress.check()?;
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
    let _runtime = Runtime;
    let manager = PackageManager::new()?;
    let user = HSTRING::new();
    let mut frameworks = Vec::new();
    for package in
        manager.FindPackagesByUserSecurityIdPackageFamilyName(&user, &HSTRING::from(FAMILY))?
    {
        let id = package.Id()?;
        if id.Architecture()? == ProcessorArchitecture::X64 {
            let version = id.Version()?;
            frameworks.push((
                (
                    version.Major,
                    version.Minor,
                    version.Build,
                    version.Revision,
                ),
                package,
            ));
        }
    }
    let (_, framework) = frameworks
        .into_iter()
        .max_by_key(|(version, _)| *version)
        .ok_or("找不到 Windows App Runtime")?;
    let registered = manager.FindPackagesByUserSecurityIdNamePublisher(
        &user,
        &HSTRING::from("MicrosoftCorporationII.WinAppRuntime.Singleton"),
        &HSTRING::from(
            "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
        ),
    )?;
    if registered.First()?.HasCurrent()? {
        return Ok(());
    }
    let directory = framework.InstalledPath()?.to_string();
    let uri = Uri::CreateUri(&HSTRING::from(format!(
        "file:///{}/MSIX/Singleton.msix",
        directory.replace('\\', "/"),
    )))?;
    let step = progress.activity("登记系统通知服务");
    manager
        .AddPackageAsync(&uri, None, DeploymentOptions::None)?
        .join()?
        .ExtendedErrorCode()?
        .ok()?;
    step.finish("系统通知服务");
    Ok(())
}

#[cfg(not(windows))]
pub fn initialize(_progress: &Progress) -> Result<()> {
    Err("系统通知需要 Windows".into())
}

struct Scan {
    symbols: Symbols,
}

struct Native {
    imports: Symbols,
    factory: u64,
    string: u64,
    utf8: u64,
    read_string: u64,
    delete_string: u64,
    destroy_string: u64,
    allocate: u64,
    free: u64,
    compare: u64,
    delegate: u64,
    module: u64,
    bind: u64,
    invoke: u64,
    destroy_task: u64,
    post: u64,
    location: u64,
    source: u64,
    summary: u64,
    alert: u64,
    settings: u64,
    muted: u64,
    exposed: u64,
    state: i64,
    sessions: i64,
    title: i64,
    avatar: u64,
    registry: Registry,
}

struct Registry {
    path: u64,
    destroy_path: u64,
    open: u64,
    read: u64,
    write: u64,
}

struct Constants {
    start: u64,
    entries: Vec<(u64, Vec<u8>)>,
}

impl Constants {
    fn new(end: u64) -> Self {
        Self {
            start: end,
            entries: Vec::new(),
        }
    }

    fn push(&mut self, bytes: Vec<u8>) -> u64 {
        self.start = (self.start - bytes.len() as u64) & !3;
        self.entries.push((self.start, bytes));
        self.start
    }
}

fn unique<T>(values: Vec<T>, description: &str) -> Result<T> {
    let [value]: [T; 1] = values
        .try_into()
        .map_err(|_| format!("无法唯一定位{description}"))?;
    Ok(value)
}

fn wide(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn relative(address: u64) -> AsmMemoryOperand {
    qword_ptr(Register::RIP) + address
}

fn calls(instructions: &[Instruction]) -> BTreeSet<u64> {
    instructions
        .iter()
        .filter(|instruction| instruction.code() == Code::Call_rel32_64)
        .map(Instruction::near_branch_target)
        .collect()
}

fn references(instructions: &[Instruction]) -> BTreeSet<u64> {
    instructions
        .iter()
        .filter(|instruction| {
            instruction.is_ip_rel_memory_operand() && instruction.mnemonic() == Mnemonic::Lea
        })
        .map(Instruction::ip_rel_memory_address)
        .collect()
}

fn pointed(image: &Image<'_>, address: u64) -> Result<u64> {
    Ok(u64::from_le_bytes(image.data(address, 8)?.try_into()?))
}

fn body(image: &Image<'_>, address: u64) -> Result<Vec<Instruction>> {
    match image.function(address)? {
        Some(function) => image.instructions(&function),
        None => Ok(Vec::new()),
    }
}

fn tail(instructions: &[Instruction]) -> bool {
    instructions.iter().any(|instruction| {
        instruction.code() == Code::Jmp_rm64 && instruction.op0_kind() == OpKind::Register
    })
}

fn argument(instructions: &[Instruction], index: usize, register: Register) -> Option<Instruction> {
    instructions[..index]
        .iter()
        .rev()
        .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
        .find(|instruction| {
            instruction.op0_kind() == OpKind::Register && instruction.op0_register() == register
        })
        .copied()
}

fn pointer_argument(instructions: &[Instruction], index: usize, register: Register) -> Option<u64> {
    argument(instructions, index, register)
        .filter(|instruction| {
            instruction.mnemonic() == Mnemonic::Lea && instruction.is_ip_rel_memory_operand()
        })
        .map(|instruction| instruction.ip_rel_memory_address())
}

fn zero_argument(instructions: &[Instruction], index: usize, register: Register) -> bool {
    argument(instructions, index, register).is_some_and(|instruction| {
        instruction.mnemonic() == Mnemonic::Xor && instruction.op1_register() == register
    })
}

fn methods(
    image: &Image<'_>,
    instructions: &[Instruction],
    slot: u64,
) -> Result<BTreeMap<u64, u64>> {
    let mut result = BTreeMap::new();
    for table in references(instructions) {
        let Ok(address) = pointed(image, table + slot * 8) else {
            continue;
        };
        if image
            .function(address)?
            .is_some_and(|function| function.start == address)
        {
            result.insert(table, address);
        }
    }
    Ok(result)
}

fn strings(
    image: &Image<'_>,
    symbols: &Symbols,
    references: &References,
    name: &str,
    matches: impl Fn(&[Instruction]) -> bool,
) -> Result<u64> {
    let mut found = Vec::new();
    for function in functions(name, symbols, references).into_values() {
        if matches(&image.instructions(&function)?) {
            found.push(function.start);
        }
    }
    unique(found, name)
}

fn native(
    image: &Image<'_>,
    symbols: &Symbols,
    found: &BTreeMap<&str, Range<u64>>,
    refs: &References,
) -> Result<(Native, Range<u64>, Range<u64>, Instruction)> {
    let factory = strings(image, symbols, refs, FACTORY, tail)?;
    let string = strings(image, symbols, refs, STRING, |instructions| {
        instructions.iter().any(|instruction| {
            instruction.code() == Code::Mov_rm8_imm8
                && instruction.memory_displacement64() == 16
                && instruction.immediate8() == 0
        })
    })?;
    let string_body = body(image, string)?;
    let loader = unique(
        string_body
            .iter()
            .enumerate()
            .filter(|(index, instruction)| {
                instruction.code() == Code::Call_rel32_64
                    && pointer_argument(&string_body, *index, Register::RCX)
                        .is_some_and(|address| symbols[STRING].contains(&address))
            })
            .map(|(_, instruction)| instruction.near_branch_target())
            .collect(),
        "HSTRING API 加载函数",
    )?;
    let delete_string = strings(image, symbols, refs, STRING_DELETE, |instructions| {
        tail(instructions) && calls(instructions).contains(&loader)
    })?;
    let read_string = strings(image, symbols, refs, STRING_BUFFER, |instructions| {
        instructions.iter().any(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.op0_register() == Register::RCX
                && instruction.memory_base() == Register::RCX
                && instruction.memory_displacement64() == 8
        })
    })?;
    let mut utf8 = Vec::new();
    for function in refs.get(string).into_iter().flatten() {
        if image.instructions(function)?.iter().any(|instruction| {
            instruction.code() == Code::Cmp_rm64_imm8 && instruction.immediate8() == 8
        }) {
            utf8.push(function.start);
        }
    }
    let utf8 = unique(utf8, "UTF-8 HSTRING 构造函数")?;
    let create = image.instructions(&found[CREATE])?;
    let mut allocators = BTreeSet::new();
    for (index, instruction) in create.iter().enumerate() {
        if instruction.code() == Code::Call_rel32_64
            && argument(&create, index, Register::ECX).is_some_and(|argument| {
                argument.code() == Code::Mov_r32_imm32 && argument.immediate32() > 16
            })
        {
            allocators.insert(instruction.near_branch_target());
        }
    }
    let allocate = unique(allocators.into_iter().collect(), "原生对象分配函数")?;

    let deleted = image.instructions(&found[DELETED])?;
    let mut bindings = Vec::new();
    let mut posts = Vec::new();
    for (index, instruction) in deleted.iter().enumerate() {
        if instruction.code() != Code::Call_rel32_64 {
            continue;
        }
        if let (Some(invoke), Some(destroy)) = (
            pointer_argument(&deleted, index, Register::RDX),
            pointer_argument(&deleted, index, Register::R8),
        ) && image.function(invoke)?.is_some()
            && image.function(destroy)?.is_some()
        {
            bindings.push((instruction.near_branch_target(), invoke));
        }
        if zero_argument(&deleted, index, Register::R8D)
            && zero_argument(&deleted, index, Register::R9D)
        {
            posts.push(instruction.near_branch_target());
        }
    }
    let (bind, publish) = unique(bindings, "GUI 任务构造函数")?;
    let post = unique(posts, "GUI 任务队列")?;
    let publish = body(image, publish)?;
    let subject = unique(
        publish
            .windows(2)
            .filter(|part| {
                part.iter()
                    .all(|instruction| instruction.code() == Code::Mov_r64_rm64)
                    && part[0].op0_register() == Register::RAX
                    && part[1].op0_register() == Register::RAX
                    && part[1].memory_base() == Register::RAX
                    && part[1].memory_displacement64() > 16
            })
            .map(|part| part[1].memory_displacement64())
            .collect(),
        "会话清空事件",
    )?;
    let subscriptions = image.instructions(&found[MESSAGES])?;
    let callbacks = methods(image, &subscriptions, 2)?;
    let publisher = unique(
        subscriptions
            .iter()
            .position(|instruction| {
                instruction.code() == Code::Mov_r64_rm64
                    && !matches!(instruction.memory_base(), Register::RSP | Register::RBP)
                    && instruction.memory_displacement64() == subject
            })
            .into_iter()
            .collect(),
        "会话清空事件订阅",
    )?;
    let clear = subscriptions[publisher..]
        .iter()
        .find_map(|instruction| {
            instruction
                .is_ip_rel_memory_operand()
                .then(|| callbacks.get(&instruction.ip_rel_memory_address()).copied())
                .flatten()
        })
        .ok_or("找不到会话清空回调")?;
    let clear = image.function(clear)?.ok_or("找不到会话清空函数")?;
    let mut message = Vec::new();
    for &callback in callbacks.values() {
        let instructions = body(image, callback)?;
        if calls(&instructions).contains(&found[UPDATE].start) {
            message.push(instructions);
        }
    }
    let message = unique(message, "新消息通知回调")?;
    let update = message
        .iter()
        .position(|instruction| {
            instruction.code() == Code::Call_rel32_64
                && instruction.near_branch_target() == found[UPDATE].start
        })
        .ok_or("找不到会话更新调用")?;
    let alert_call = *message[update + 1..]
        .iter()
        .find(|instruction| instruction.code() == Code::Call_rel32_64)
        .ok_or("找不到原消息提醒调用")?;
    let alert = image.instructions(
        &image
            .function(alert_call.near_branch_target())?
            .ok_or("找不到原消息提醒函数")?,
    )?;
    let alert_calls: Vec<_> = alert
        .iter()
        .filter(|instruction| instruction.code() == Code::Call_rel32_64)
        .map(Instruction::near_branch_target)
        .collect();
    let settings = *alert_calls.first().ok_or("找不到通知设置")?;
    let muted = *alert_calls.get(1).ok_or("找不到全局通知开关")?;

    let window = image.instructions(&found[WINDOW])?;
    let mut click = Vec::new();
    for address in methods(image, &window, 0)?.into_values() {
        if calls(&body(image, address)?).contains(&found[ROUTER].start) {
            click.push(image.function(address)?.ok_or("找不到通知点击函数")?);
        }
    }
    let click = unique(click, "通知条目点击函数")?;
    let mut destroy_string = Vec::new();
    for address in calls(&image.instructions(&clear)?) {
        let instructions = body(image, address)?;
        if instructions.first().is_some_and(|instruction| {
            instruction.mnemonic() == Mnemonic::Sub && instruction.op0_register() == Register::RSP
        }) && instructions.iter().any(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.memory_base() == Register::RCX
                && instruction.memory_displacement64() == 24
        }) && instructions
            .iter()
            .any(|instruction| instruction.code() == Code::Jmp_rel32_64)
        {
            destroy_string.push(address);
        }
    }
    let destroy_string = unique(destroy_string, "字符串析构函数")?;
    let mut compare = Vec::new();
    for part in image.instructions(&found[ADD])?.windows(3) {
        if part[0].code() == Code::Call_rel32_64
            && part[1].code() == Code::Test_rm32_r32
            && part[1].op0_register() == Register::EAX
            && part[2].mnemonic() == Mnemonic::Sete
        {
            compare.push(part[0].near_branch_target());
        }
    }
    let compare = unique(compare, "会话名称比较函数")?;
    let summary_calls = calls(&image.instructions(&found[SUMMARY])?);
    let preview_calls = calls(&image.instructions(&found[PREVIEW])?);
    let mut summary = Vec::new();
    for &address in summary_calls.intersection(&preview_calls) {
        if references(&body(image, address)?)
            .iter()
            .any(|address| image.data(*address, 3).is_ok_and(|bytes| bytes == b": \0"))
        {
            summary.push(address);
        }
    }
    let summary = unique(summary, "消息摘要生成函数")?;

    let mut delegate = Vec::new();
    for function in functions(CAPTURE, symbols, refs).into_values() {
        for (table, address) in methods(image, &image.instructions(&function)?, 3)? {
            let instructions = body(image, address)?;
            if instructions.iter().any(|instruction| {
                instruction.code() == Code::Call_rm64 && instruction.memory_displacement64() == 24
            }) && instructions.iter().any(|instruction| {
                instruction.code() == Code::Mov_r64_rm64
                    && instruction.memory_displacement64() == 16
                    && instruction.op0_register() == Register::RCX
            }) {
                delegate.push(table);
            }
        }
    }
    delegate.sort_unstable();
    delegate.dedup();
    let delegate = unique(delegate, "WinRT 事件委托")?;
    let destructor = body(image, pointed(image, delegate + 32)?)?;
    let free = unique(calls(&destructor).into_iter().collect(), "原生对象释放函数")?;
    let module = unique(
        body(image, pointed(image, delegate + 16)?)?
            .iter()
            .filter(|instruction| {
                instruction.code() == Code::Mov_r64_rm64
                    && instruction.op0_register() == Register::RCX
                    && instruction.is_ip_rel_memory_operand()
            })
            .map(Instruction::ip_rel_memory_address)
            .collect(),
        "WinRT 模块引用",
    )?;
    let task = image.instructions(&found[TASK])?;
    let mut invoke = Vec::new();
    for (index, instruction) in task.iter().enumerate() {
        if instruction.code() == Code::Call_rel32_64
            && instruction.near_branch_target() == bind
            && let Some(address) = pointer_argument(&task, index, Register::RDX)
        {
            let instructions: Vec<_> =
                Decoder::new(64, image.data(address, 16)?, DecoderOptions::NONE)
                    .into_iter()
                    .take(3)
                    .collect();
            if instructions.len() == 3
                && instructions[0].mnemonic() == Mnemonic::Mov
                && instructions[0].op0_register() == Register::RAX
                && instructions[0].op1_register() == Register::RCX
                && instructions[1].mnemonic() == Mnemonic::Add
                && instructions[1].op0_register() == Register::RCX
                && instructions[1].immediate8() == 0x28
                && instructions[2].code() == Code::Jmp_rm64
                && instructions[2].memory_base() == Register::RAX
                && instructions[2].memory_displacement64() == 0x20
            {
                invoke.push(address);
            }
        }
    }
    let invoke = unique(invoke, "任务执行器")?;
    let mut destroy_task = Vec::new();
    let login = image.instructions(&found[LOGIN])?;
    for (index, instruction) in login.iter().enumerate() {
        if instruction.code() != Code::Call_rel32_64 || instruction.near_branch_target() != bind {
            continue;
        }
        if let Some(address) = pointer_argument(&login, index, Register::R8) {
            let instructions = body(image, address)?;
            if instructions.iter().any(|instruction| {
                instruction.code() == Code::Mov_r64_rm64
                    && instruction.memory_base() == Register::RCX
                    && instruction.memory_displacement64() == 0x40
            }) && instructions.iter().any(|instruction| {
                instruction.code() == Code::Jmp_rel32_64 && instruction.near_branch_target() == free
            }) {
                destroy_task.push(address);
            }
        }
    }
    destroy_task.sort_unstable();
    destroy_task.dedup();
    let destroy_task = unique(destroy_task, "任务析构函数")?;
    let mut locations = BTreeSet::new();
    for (index, instruction) in subscriptions.iter().enumerate() {
        if instruction.code() == Code::Call_rel32_64
            && pointer_argument(&subscriptions, index, Register::RDX)
                .is_some_and(|address| symbols[MESSAGES].contains(&address))
            && let Some(source) = pointer_argument(&subscriptions, index, Register::R8)
        {
            locations.insert((instruction.near_branch_target(), source));
        }
    }
    let (location, source) = unique(locations.into_iter().collect(), "任务来源信息")?;
    let timer = image.instructions(&found[TIMER])?;
    let state = unique(
        timer
            .iter()
            .filter(|instruction| {
                instruction.code() == Code::Cmp_rm64_imm8
                    && instruction.memory_base() == Register::RCX
                    && instruction.immediate8() == 0
            })
            .map(|instruction| instruction.memory_displacement64() as i64)
            .collect(),
        "通知组件状态字段",
    )?;
    let mut sessions = BTreeSet::new();
    let mut exposed = BTreeSet::new();
    for part in alert.windows(3) {
        if part[0].code() == Code::Mov_r64_rm64
            && part[0].op0_register() == Register::RCX
            && part[0].memory_displacement64() == 0
            && part[1].code() == Code::Call_rel32_64
            && part[2].code() == Code::Test_rm8_r8
            && part[2].op0_register() == Register::AL
        {
            exposed.insert(part[1].near_branch_target());
        }
    }
    for part in alert.windows(2) {
        if part[0].code() == Code::Mov_r64_rm64
            && part[1].code() == Code::Mov_r64_rm64
            && part[0].memory_base() == part[1].memory_base()
            && part[0].memory_base() != Register::RSP
            && part[0].memory_base() != Register::RBP
            && part[0].memory_displacement64() + 8 == part[1].memory_displacement64()
        {
            sessions.insert(part[0].memory_displacement64() as i64);
        }
    }
    let sessions = unique(sessions.into_iter().collect(), "未读会话列表")?;
    let exposed = unique(exposed.into_iter().collect(), "会话提醒状态")?;
    let mut titles = BTreeSet::new();
    for method in methods(image, &window, 3)?.into_values() {
        for setter in calls(&body(image, method)?) {
            let setter = body(image, setter)?;
            if !calls(&setter).contains(&found[HEAD].start) {
                continue;
            }
            for instruction in &setter {
                if instruction.code() == Code::Cmp_rm64_imm8
                    && instruction.memory_base() == Register::RAX
                    && instruction.memory_displacement64() >= 24
                    && instruction.immediate8() == 16
                {
                    titles.insert(instruction.memory_displacement64() as i64 - 24);
                }
            }
        }
    }
    let title = unique(titles.into_iter().collect(), "通知会话名称")?;
    let paths = image.instructions(&found[PATHS])?;
    let mut path = Vec::new();
    for (index, instruction) in paths.iter().enumerate() {
        if instruction.code() == Code::Call_rel32_64
            && paths[..index]
                .iter()
                .rev()
                .take_while(|instruction| instruction.code() != Code::Call_rel32_64)
                .any(|instruction| {
                    instruction.code() == Code::Mov_r32_imm32
                        && instruction.op0_register() == Register::ECX
                        && instruction.immediate32() == 6
                })
        {
            path.push(instruction.near_branch_target());
        }
    }
    let path = unique(path, "程序路径查询")?;
    let deallocate = unique(
        body(image, destroy_string)?
            .iter()
            .filter(|instruction| instruction.code() == Code::Jmp_rel32_64)
            .map(Instruction::near_branch_target)
            .collect(),
        "字符串内存释放函数",
    )?;
    let mut destroy_path = Vec::new();
    for address in calls(&paths) {
        let instructions = body(image, address)?;
        if instructions.iter().any(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.memory_base() == Register::RCX
                && instruction.memory_displacement64() == 24
        }) && instructions.iter().any(|instruction| {
            instruction.code() == Code::Cmp_rm64_imm8 && instruction.immediate8() == 8
        }) && instructions.iter().any(|instruction| {
            instruction.code() == Code::Jmp_rel32_64
                && instruction.near_branch_target() == deallocate
        }) {
            destroy_path.push(address);
        }
    }
    let destroy_path = unique(destroy_path, "路径析构函数")?;
    let imports = image.imports()?;
    let mut open = Vec::new();
    for function in functions("RegOpenKeyExW", &imports, refs).into_values() {
        let instructions = image.instructions(&function)?;
        let imported: BTreeSet<_> = instructions
            .iter()
            .filter(|instruction| {
                instruction.code() == Code::Call_rm64 && instruction.is_ip_rel_memory_operand()
            })
            .map(Instruction::ip_rel_memory_address)
            .collect();
        if imported.contains(&imports["RegCloseKey"][0])
            && !imported.contains(&imports["RegCreateKeyExW"][0])
            && instructions.iter().any(|instruction| {
                instruction.mnemonic() == Mnemonic::And
                    && instruction.op1_kind() == OpKind::Immediate32
                    && instruction.immediate32() == 0x300
            })
        {
            open.push(function.start);
        }
    }
    let open = unique(open, "注册表打开方法")?;
    let mut read = Vec::new();
    for function in functions("RegQueryValueExW", &imports, refs).into_values() {
        if image.instructions(&function)?.iter().any(|instruction| {
            instruction.code() == Code::Call_rm64
                && instruction.is_ip_rel_memory_operand()
                && instruction.ip_rel_memory_address() == imports["ExpandEnvironmentStringsW"][0]
        }) {
            read.push(function.start);
        }
    }
    let read = unique(read, "注册表字符串读取方法")?;
    let mut write = Vec::new();
    for function in functions("RegSetValueExW", &imports, refs).into_values() {
        let instructions = image.instructions(&function)?;
        if calls(&instructions).len() == 1
            && instructions.iter().any(|instruction| {
                instruction.code() == Code::Mov_r32_imm32
                    && instruction.op0_register() == Register::R9D
                    && instruction.immediate32() == 1
            })
        {
            write.push(function.start);
        }
    }
    let write = unique(write, "注册表字符串写入方法")?;
    Ok((
        Native {
            imports,
            factory,
            string,
            utf8,
            read_string,
            delete_string,
            destroy_string,
            allocate,
            free,
            compare,
            delegate,
            module,
            bind,
            invoke,
            destroy_task,
            post,
            location,
            source,
            summary,
            alert: alert_call.near_branch_target(),
            settings,
            muted,
            exposed,
            state,
            sessions,
            title,
            avatar: found[AVATAR].start,
            registry: Registry {
                path,
                destroy_path,
                open,
                read,
                write,
            },
        },
        click,
        clear,
        alert_call,
    ))
}

fn begin(code: &mut CodeAssembler, saved: &[AsmRegister64], stack: i32) -> Result<Vec<u8>> {
    let mut operations = Vec::new();
    for &saved in saved {
        code.push(saved)?;
        let offset = u8::try_from(code.assemble(0)?.len())?;
        let register = Register::from(saved) as u8 - Register::RAX as u8;
        operations.push(vec![offset, register << 4]);
    }
    code.sub(rsp, stack)?;
    let offset = u8::try_from(code.assemble(0)?.len())?;
    if stack <= 128 {
        operations.push(vec![offset, (((stack / 8 - 1) as u8) << 4) | 2]);
    } else {
        let size = u16::try_from(stack / 8)?.to_le_bytes();
        operations.push(vec![offset, 1, size[0], size[1]]);
    }
    let count = operations.iter().map(Vec::len).sum::<usize>() / 2;
    let mut unwind = vec![1, offset, u8::try_from(count)?, 0];
    unwind.extend(operations.into_iter().rev().flatten());
    unwind.resize(unwind.len().next_multiple_of(4), 0);
    Ok(unwind)
}

fn end(code: &mut CodeAssembler, saved: &[AsmRegister64], stack: i32) -> Result<()> {
    code.add(rsp, stack)?;
    for &saved in saved.iter().rev() {
        code.pop(saved)?;
    }
    code.ret()?;
    Ok(())
}

fn finish(
    image: &Image<'_>,
    function: &Range<u64>,
    mut code: CodeAssembler,
    constants: Constants,
    unwind: &[u8],
) -> Result<Vec<Edit>> {
    let mut cursor = function.start + code.assemble(function.start)?.len() as u64;
    if cursor > constants.start {
        return Err(format!(
            "RVA {:#x} 的指令空间不足：需要 {} 字节，可用 {} 字节",
            function.start - image.base(),
            cursor - function.start + function.end - constants.start,
            function.end - function.start,
        )
        .into());
    }
    for (address, bytes) in constants.entries.into_iter().rev() {
        code.db(&vec![0xcc; usize::try_from(address - cursor)?])?;
        code.db(&bytes)?;
        cursor = address + bytes.len() as u64;
    }
    image.replace_function(function, &mut code, unwind)
}

fn patch(image: &Image<'_>, range: Range<u64>, code: &mut CodeAssembler) -> Result<Edit> {
    let mut bytes = code.assemble(range.start)?;
    let size = usize::try_from(range.end - range.start)?;
    if bytes.len() > size {
        return Err(format!("RVA {:#x} 的指令空间不足", range.start - image.base()).into());
    }
    bytes.resize(size, 0x90);
    let offset = image.offset(range.start)?;
    Ok(Edit {
        range: offset..offset + size,
        bytes,
    })
}

fn redirect(image: &Image<'_>, instruction: &Instruction, target: u64) -> Result<Edit> {
    let mut code = CodeAssembler::new(64)?;
    code.call(target)?;
    patch(image, instruction.ip()..instruction.next_ip(), &mut code)
}

fn com(code: &mut CodeAssembler, method: i32) -> Result<()> {
    code.mov(rax, qword_ptr(rcx))?;
    code.call(qword_ptr(rax + method * 8))?;
    Ok(())
}

fn release(code: &mut CodeAssembler, offset: i32) -> Result<()> {
    let mut done = code.create_label();
    code.mov(rcx, qword_ptr(rsp + offset))?;
    code.test(rcx, rcx)?;
    code.jz(done)?;
    com(code, 2)?;
    code.set_label(&mut done)?;
    Ok(())
}

fn hresult(code: &mut CodeAssembler, failure: CodeLabel) -> Result<()> {
    code.test(eax, eax)?;
    code.js(failure)?;
    Ok(())
}

impl Native {
    fn import(&self, name: &str) -> Result<u64> {
        self.imports
            .get(name)
            .and_then(|addresses| addresses.first())
            .copied()
            .ok_or_else(|| format!("找不到导入函数 {name}").into())
    }

    fn proc(
        &self,
        code: &mut CodeAssembler,
        constants: &mut Constants,
        module: AsmRegister64,
        name: &str,
    ) -> Result<()> {
        let name = constants.push(name.bytes().chain([0]).collect());
        code.mov(rcx, module)?;
        code.lea(rdx, relative(name))?;
        code.call(relative(self.import("GetProcAddress")?))?;
        Ok(())
    }

    fn literal(
        &self,
        code: &mut CodeAssembler,
        constants: &mut Constants,
        value: &str,
        output: i32,
        view: i32,
    ) -> Result<u64> {
        let value_address = constants.push(wide(value));
        code.lea(rax, relative(value_address))?;
        code.mov(qword_ptr(rsp + view), rax)?;
        code.mov(
            qword_ptr(rsp + view + 8),
            value.encode_utf16().count() as i32,
        )?;
        code.lea(rcx, ptr(rsp + output))?;
        code.lea(rdx, ptr(rsp + view))?;
        code.call(self.string)?;
        Ok(value_address)
    }

    fn text(
        &self,
        code: &mut CodeAssembler,
        source: AsmRegister64,
        output: i32,
        view: i32,
    ) -> Result<()> {
        code.mov(r8, qword_ptr(source + 16))?;
        code.mov(rax, source)?;
        code.cmp(qword_ptr(source + 24), 16)?;
        code.cmovae(rax, qword_ptr(source))?;
        code.mov(qword_ptr(rsp + view), rax)?;
        code.mov(qword_ptr(rsp + view + 8), r8)?;
        code.lea(rcx, ptr(rsp + output))?;
        code.lea(rdx, ptr(rsp + view))?;
        code.call(self.utf8)?;
        Ok(())
    }

    fn activate(
        &self,
        code: &mut CodeAssembler,
        constants: &mut Constants,
        class: &str,
        iid: &[u8; 16],
        slots: [i32; 3],
    ) -> Result<(u64, u64)> {
        let [output, string, view] = slots;
        let class = self.literal(code, constants, class, string, view)?;
        let iid = constants.push(iid.to_vec());
        code.mov(rcx, qword_ptr(rsp + string + 8))?;
        code.lea(rdx, relative(iid))?;
        code.lea(r8, ptr(rsp + output))?;
        code.call(self.factory)?;
        code.mov(edi, eax)?;
        code.mov(rcx, qword_ptr(rsp + string + 8))?;
        code.call(self.delete_string)?;
        code.mov(eax, edi)?;
        Ok((class, iid))
    }

    fn trace(
        &self,
        code: &mut CodeAssembler,
        constants: &mut Constants,
        message: &str,
    ) -> Result<()> {
        let message = constants.push(message.bytes().chain([0]).collect());
        code.lea(rcx, relative(message))?;
        code.call(relative(self.import("OutputDebugStringA")?))?;
        Ok(())
    }
}

fn runtime(image: &Image<'_>, function: &Range<u64>, native: &Native) -> Result<Vec<Edit>> {
    let mut code = CodeAssembler::new(64)?;
    let mut constants = Constants::new(function.end);
    let saved = [rbx, rsi, rdi];
    let unwind = begin(&mut code, &saved, 0x60)?;
    let mut done = code.create_label();
    let mut free = code.create_label();
    let kernel = constants.push(wide("kernelbase.dll"));
    let family = constants.push(wide(FAMILY));
    code.mov(rbx, rcx)?;
    code.mov(qword_ptr(rsp + 0x40), 0)?;
    code.lea(rcx, relative(kernel))?;
    code.call(relative(native.import("GetModuleHandleW")?))?;
    code.mov(rsi, rax)?;
    native.proc(&mut code, &mut constants, rsi, "TryCreatePackageDependency")?;
    code.xor(ecx, ecx)?;
    code.lea(rdx, relative(family))?;
    code.xor(r8d, r8d)?;
    code.mov(r9d, 4)?;
    code.mov(qword_ptr(rsp + 0x20), 0)?;
    code.mov(qword_ptr(rsp + 0x28), 0)?;
    code.mov(qword_ptr(rsp + 0x30), 0)?;
    code.lea(r10, ptr(rsp + 0x40))?;
    code.mov(qword_ptr(rsp + 0x38), r10)?;
    code.call(rax)?;
    code.mov(edi, eax)?;
    hresult(&mut code, free)?;
    native.proc(&mut code, &mut constants, rsi, "AddPackageDependency")?;
    code.mov(rcx, qword_ptr(rsp + 0x40))?;
    code.xor(edx, edx)?;
    code.xor(r8d, r8d)?;
    code.lea(r9, ptr(rbx + 16))?;
    code.mov(qword_ptr(rsp + 0x20), 0)?;
    code.call(rax)?;
    code.mov(edi, eax)?;
    native.proc(&mut code, &mut constants, rsi, "DeletePackageDependency")?;
    code.mov(rcx, qword_ptr(rsp + 0x40))?;
    code.call(rax)?;
    code.set_label(&mut free)?;
    code.cmp(qword_ptr(rsp + 0x40), 0)?;
    code.je(done)?;
    code.call(relative(native.import("GetProcessHeap")?))?;
    code.mov(rcx, rax)?;
    code.xor(edx, edx)?;
    code.mov(r8, qword_ptr(rsp + 0x40))?;
    code.call(relative(native.import("HeapFree")?))?;
    code.set_label(&mut done)?;
    code.mov(eax, edi)?;
    end(&mut code, &saved, 0x60)?;
    finish(image, function, code, constants, &unwind)
}

fn window(
    image: &Image<'_>,
    function: &Range<u64>,
    native: &Native,
) -> Result<(Vec<Edit>, [u64; 4])> {
    let mut code = CodeAssembler::new(64)?;
    let mut constants = Constants::new(function.end);
    let saved = [rbx, rdi];
    let unwind = begin(&mut code, &saved, 0x58)?;
    let mut done = code.create_label();
    let mut path = code.create_label();
    let mut next = code.create_label();
    code.mov(rbx, rcx)?;
    code.mov(qword_ptr(rsp + 0x20), 0)?;
    for (name, iid, offset) in [
        (BUILDER, &FACTORY_IID, 24),
        ("Windows.Foundation.Uri", &URI_IID, 32),
    ] {
        native.activate(&mut code, &mut constants, name, iid, [0x20, 0x28, 0x40])?;
        hresult(&mut code, done)?;
        code.mov(rax, qword_ptr(rsp + 0x20))?;
        code.mov(qword_ptr(rbx + offset), rax)?;
        code.mov(qword_ptr(rsp + 0x20), 0)?;
    }
    code.mov(ecx, 1)?;
    code.lea(rdx, ptr(rbx + 40))?;
    code.call(native.registry.path)?;
    code.mov(edi, 0x8000_4005u32)?;
    code.test(al, al)?;
    code.jz(done)?;
    code.xor(edi, edi)?;
    code.lea(rax, ptr(rbx + 40))?;
    code.cmp(qword_ptr(rbx + 64), 8)?;
    code.cmovae(rax, qword_ptr(rbx + 40))?;
    code.set_label(&mut path)?;
    code.cmp(word_ptr(rax), 0)?;
    code.je(done)?;
    code.cmp(word_ptr(rax), i32::from(b'\\'))?;
    code.jne(next)?;
    code.mov(word_ptr(rax), i32::from(b'.'))?;
    code.set_label(&mut next)?;
    code.add(rax, 2)?;
    code.jmp(path)?;
    code.set_label(&mut done)?;
    release(&mut code, 0x20)?;
    code.mov(eax, edi)?;
    end(&mut code, &saved, 0x58)?;
    let names = [
        r"Software\Classes\AppUserModelId",
        "NotificationGUID",
        "DisplayName",
        "微信",
    ]
    .map(|name| constants.push(wide(name)));
    Ok((finish(image, function, code, constants, &unwind)?, names))
}

fn create(
    image: &Image<'_>,
    found: &BTreeMap<&str, Range<u64>>,
    native: &Native,
    click: u64,
    names: [u64; 4],
) -> Result<(Vec<Edit>, [u64; 2])> {
    let mut code = CodeAssembler::new(64)?;
    let mut constants = Constants::new(found[CREATE].end);
    let saved = [rbx, rsi, rdi];
    let unwind = begin(&mut code, &saved, 0x80)?;
    let mut cleanup = code.create_label();
    let mut done = code.create_label();
    let mut module = code.create_label();
    let mut named = code.create_label();
    code.mov(rbx, rcx)?;
    code.call(found[LOAD].start)?;
    code.cmp(qword_ptr(rbx + native.state), 0)?;
    code.jne(done)?;
    code.mov(qword_ptr(rsp + 0x20), 0)?;
    code.mov(qword_ptr(rsp + 0x28), 0)?;
    code.mov(ecx, 72)?;
    code.call(native.allocate)?;
    code.mov(rsi, rax)?;
    code.xorps(xmm0, xmm0)?;
    code.movups(ptr(rsi), xmm0)?;
    code.movups(ptr(rsi + 16), xmm0)?;
    code.movups(ptr(rsi + 32), xmm0)?;
    code.movups(ptr(rsi + 48), xmm0)?;
    code.mov(qword_ptr(rsi + 64), 7)?;
    code.mov(qword_ptr(rbx + native.state), rsi)?;
    code.mov(rcx, rsi)?;
    code.call(found[TIMER].start)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    let (class, iid) = native.activate(
        &mut code,
        &mut constants,
        MANAGER,
        &MANAGER_IID,
        [0x20, 0x30, 0x50],
    )?;
    hresult(&mut code, cleanup)?;
    code.mov(rcx, qword_ptr(rsp + 0x20))?;
    code.mov(rdx, rsi)?;
    com(&mut code, 6)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.mov(rcx, rsi)?;
    code.call(found[WINDOW].start)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.mov(ecx, 32)?;
    code.call(native.allocate)?;
    code.mov(qword_ptr(rsp + 0x28), rax)?;
    code.lea(rdx, relative(native.delegate))?;
    code.mov(qword_ptr(rax), rdx)?;
    code.mov(dword_ptr(rax + 8), 0)?;
    code.mov(dword_ptr(rax + 12), 1)?;
    code.mov(qword_ptr(rax + 16), 0)?;
    code.lea(rdx, relative(click))?;
    code.mov(qword_ptr(rax + 24), rdx)?;
    code.mov(rcx, relative(native.module))?;
    code.test(rcx, rcx)?;
    code.jz(module)?;
    com(&mut code, 1)?;
    code.set_label(&mut module)?;
    code.mov(rcx, qword_ptr(rsi))?;
    code.mov(rdx, qword_ptr(rsp + 0x28))?;
    code.lea(r8, ptr(rsi + 8))?;
    com(&mut code, 9)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.mov(rcx, qword_ptr(rsi))?;
    com(&mut code, 6)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.xorps(xmm0, xmm0)?;
    for offset in [0x30, 0x40, 0x50, 0x60, 0x70] {
        code.movups(ptr(rsp + offset), xmm0)?;
    }
    code.mov(qword_ptr(rsp + 0x78), 7)?;
    code.lea(rcx, ptr(rsp + 0x30))?;
    code.mov(rdx, -0x7fff_ffffi64)?;
    code.lea(r8, relative(names[0]))?;
    code.mov(r9d, 0x20019)?;
    code.call(native.registry.open)?;
    code.mov(edi, eax)?;
    code.test(edi, edi)?;
    code.jnz(named)?;
    code.lea(rcx, ptr(rsp + 0x48))?;
    code.mov(rdx, qword_ptr(rsp + 0x30))?;
    code.lea(r8, ptr(rsi + 40))?;
    code.cmp(qword_ptr(rsi + 64), 8)?;
    code.cmovae(r8, qword_ptr(rsi + 40))?;
    code.mov(r9d, 0x20019)?;
    code.call(native.registry.open)?;
    code.mov(edi, eax)?;
    code.test(edi, edi)?;
    code.jnz(named)?;
    code.lea(rcx, ptr(rsp + 0x48))?;
    code.lea(rdx, relative(names[1]))?;
    code.lea(r8, ptr(rsp + 0x60))?;
    code.call(native.registry.read)?;
    code.mov(edi, eax)?;
    code.test(edi, edi)?;
    code.jnz(named)?;
    code.lea(rcx, ptr(rsp + 0x48))?;
    code.mov(rdx, qword_ptr(rsp + 0x30))?;
    code.lea(r8, ptr(rsp + 0x60))?;
    code.cmp(qword_ptr(rsp + 0x78), 8)?;
    code.cmovae(r8, qword_ptr(rsp + 0x60))?;
    code.mov(r9d, 2)?;
    code.call(native.registry.open)?;
    code.mov(edi, eax)?;
    code.test(edi, edi)?;
    code.jnz(named)?;
    code.lea(rcx, ptr(rsp + 0x48))?;
    code.lea(rdx, relative(names[2]))?;
    code.lea(r8, relative(names[3]))?;
    code.call(native.registry.write)?;
    code.mov(edi, eax)?;
    code.set_label(&mut named)?;
    code.lea(rcx, ptr(rsp + 0x60))?;
    code.call(native.registry.destroy_path)?;
    for offset in [0x48, 0x30] {
        let mut closed = code.create_label();
        code.mov(rcx, qword_ptr(rsp + offset))?;
        code.test(rcx, rcx)?;
        code.jz(closed)?;
        code.call(relative(native.import("RegCloseKey")?))?;
        code.set_label(&mut closed)?;
    }
    code.test(edi, edi)?;
    code.jz(cleanup)?;
    code.or(edi, 0x8007_0000u32 as i32)?;
    code.set_label(&mut cleanup)?;
    release(&mut code, 0x28)?;
    release(&mut code, 0x20)?;
    code.test(edi, edi)?;
    code.jns(done)?;
    code.mov(rcx, rbx)?;
    code.call(found[CLOSE].start)?;
    native.trace(
        &mut code,
        &mut constants,
        "AppNotificationManager initialization failed.\n",
    )?;
    code.set_label(&mut done)?;
    end(&mut code, &saved, 0x80)?;
    Ok((
        finish(image, &found[CREATE], code, constants, &unwind)?,
        [class, iid],
    ))
}

fn close(image: &Image<'_>, function: &Range<u64>, native: &Native) -> Result<Vec<Edit>> {
    let mut code = CodeAssembler::new(64)?;
    let mut constants = Constants::new(function.end);
    let saved = [rbx];
    let unwind = begin(&mut code, &saved, 0x30)?;
    let mut done = code.create_label();
    let mut package = code.create_label();
    let mut free = code.create_label();
    let kernel = constants.push(wide("kernelbase.dll"));
    code.mov(rbx, qword_ptr(rcx + native.state))?;
    code.test(rbx, rbx)?;
    code.jz(done)?;
    code.mov(qword_ptr(rcx + native.state), 0)?;
    code.mov(rcx, qword_ptr(rbx))?;
    code.test(rcx, rcx)?;
    code.jz(package)?;
    code.mov(qword_ptr(rsp + 0x20), 0)?;
    code.lea(rdx, ptr(rsp + 0x20))?;
    com(&mut code, 19)?;
    release(&mut code, 0x20)?;
    code.mov(rcx, qword_ptr(rbx))?;
    code.mov(rdx, qword_ptr(rbx + 8))?;
    com(&mut code, 10)?;
    code.mov(rcx, qword_ptr(rbx))?;
    com(&mut code, 7)?;
    code.mov(rcx, qword_ptr(rbx))?;
    com(&mut code, 2)?;
    code.set_label(&mut package)?;
    for offset in [32, 24] {
        let mut released = code.create_label();
        code.mov(rcx, qword_ptr(rbx + offset))?;
        code.test(rcx, rcx)?;
        code.jz(released)?;
        com(&mut code, 2)?;
        code.set_label(&mut released)?;
    }
    code.lea(rcx, ptr(rbx + 40))?;
    code.call(native.registry.destroy_path)?;
    code.cmp(qword_ptr(rbx + 16), 0)?;
    code.je(free)?;
    code.lea(rcx, relative(kernel))?;
    code.call(relative(native.import("GetModuleHandleW")?))?;
    native.proc(&mut code, &mut constants, rax, "RemovePackageDependency")?;
    code.mov(rcx, qword_ptr(rbx + 16))?;
    code.call(rax)?;
    code.set_label(&mut free)?;
    code.mov(rcx, rbx)?;
    code.call(native.free)?;
    code.set_label(&mut done)?;
    end(&mut code, &saved, 0x30)?;
    finish(image, function, code, constants, &unwind)
}

fn clear(
    image: &Image<'_>,
    function: &Range<u64>,
    native: &Native,
    manager: [u64; 2],
) -> Result<Vec<Edit>> {
    let mut code = CodeAssembler::new(64)?;
    let mut constants = Constants::new(function.end);
    let saved = [rbx, rsi, rdi];
    let unwind = begin(&mut code, &saved, 0x80)?;
    let mut cleanup = code.create_label();
    let mut done = code.create_label();
    code.mov(rbx, rdx)?;
    code.xorps(xmm0, xmm0)?;
    code.movups(ptr(rsp + 0x20), xmm0)?;
    code.movq(qword_ptr(rsp + 0x30), xmm0)?;
    code.movq(qword_ptr(rsp + 0x40), xmm0)?;
    code.lea(rax, relative(manager[0]))?;
    code.mov(qword_ptr(rsp + 0x68), rax)?;
    code.mov(qword_ptr(rsp + 0x70), MANAGER.encode_utf16().count() as i32)?;
    code.lea(rcx, ptr(rsp + 0x50))?;
    code.lea(rdx, ptr(rsp + 0x68))?;
    code.call(native.string)?;
    code.mov(rcx, qword_ptr(rsp + 0x58))?;
    code.lea(rdx, relative(manager[1]))?;
    code.lea(r8, ptr(rsp + 0x20))?;
    code.call(native.factory)?;
    code.mov(edi, eax)?;
    code.mov(rcx, qword_ptr(rsp + 0x58))?;
    code.call(native.delete_string)?;
    code.test(edi, edi)?;
    code.js(cleanup)?;
    code.mov(rcx, qword_ptr(rsp + 0x20))?;
    code.lea(rdx, ptr(rsp + 0x28))?;
    com(&mut code, 6)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    native.text(&mut code, rbx, 0x38, 0x68)?;
    code.mov(rcx, qword_ptr(rsp + 0x28))?;
    code.mov(rdx, qword_ptr(rsp + 0x40))?;
    code.lea(r8, ptr(rsp + 0x30))?;
    com(&mut code, 16)?;
    code.mov(edi, eax)?;
    code.set_label(&mut cleanup)?;
    release(&mut code, 0x30)?;
    release(&mut code, 0x28)?;
    release(&mut code, 0x20)?;
    code.mov(rcx, qword_ptr(rsp + 0x40))?;
    code.call(native.delete_string)?;
    code.test(edi, edi)?;
    code.jns(done)?;
    native.trace(
        &mut code,
        &mut constants,
        "AppNotificationManager::RemoveByTagAsync failed.\n",
    )?;
    code.set_label(&mut done)?;
    code.mov(eax, edi)?;
    end(&mut code, &saved, 0x80)?;
    finish(image, function, code, constants, &unwind)
}

fn fluent(code: &mut CodeAssembler, method: i32, cleanup: CodeLabel) -> Result<()> {
    com(code, method)?;
    code.mov(edi, eax)?;
    release(code, 0x20)?;
    code.test(edi, edi)?;
    code.js(cleanup)?;
    Ok(())
}

fn show(image: &Image<'_>, function: &Range<u64>, native: &Native, crop: i32) -> Result<Vec<Edit>> {
    let mut code = CodeAssembler::new(64)?;
    let mut constants = Constants::new(function.end);
    let saved = [rbx, rsi, rdi, r14];
    let unwind = begin(&mut code, &saved, 0x118)?;
    let mut next = code.create_label();
    let mut advance = code.create_label();
    let mut matched = code.create_label();
    let mut cleanup = code.create_label();
    let mut build = code.create_label();
    let mut done = code.create_label();
    code.mov(rbx, rcx)?;
    code.mov(rsi, rdx)?;
    code.call(native.alert)?;
    code.cmp(qword_ptr(rbx + native.state), 0)?;
    code.je(done)?;
    code.call(native.settings)?;
    code.mov(rcx, rax)?;
    code.call(native.muted)?;
    code.test(al, al)?;
    code.jnz(done)?;
    code.mov(r14, qword_ptr(rbx + native.sessions))?;
    code.set_label(&mut next)?;
    code.cmp(r14, qword_ptr(rbx + native.sessions + 8))?;
    code.je(done)?;
    code.mov(rdi, qword_ptr(r14))?;
    code.mov(r8, qword_ptr(rsi + 16))?;
    code.cmp(r8, qword_ptr(rdi + 16))?;
    code.jne(advance)?;
    code.mov(rcx, rdi)?;
    code.cmp(qword_ptr(rdi + 24), 16)?;
    code.cmovae(rcx, qword_ptr(rdi))?;
    code.mov(rdx, rsi)?;
    code.cmp(qword_ptr(rsi + 24), 16)?;
    code.cmovae(rdx, qword_ptr(rsi))?;
    code.call(native.compare)?;
    code.test(eax, eax)?;
    code.je(matched)?;
    code.set_label(&mut advance)?;
    code.add(r14, 16)?;
    code.jmp(next)?;
    code.set_label(&mut matched)?;
    code.mov(rcx, rdi)?;
    code.call(native.exposed)?;
    code.test(al, al)?;
    code.jz(done)?;
    code.lea(rdi, ptr(rsp + 0x20))?;
    code.xor(eax, eax)?;
    code.mov(ecx, 0x1e)?;
    code.rep().stosq()?;
    code.mov(rcx, rsi)?;
    code.lea(rdx, ptr(rsp + 0xd0))?;
    code.call(native.summary)?;
    native.text(&mut code, rsi, 0x48, 0xc0)?;
    code.lea(r14, ptr(rsi + native.title))?;
    native.text(&mut code, r14, 0x60, 0xc0)?;
    code.lea(r14, ptr(rsp + 0xd0))?;
    native.text(&mut code, r14, 0x78, 0xc0)?;
    native.literal(&mut code, &mut constants, "session", 0x90, 0xc0)?;
    code.mov(rcx, qword_ptr(rbx + native.state))?;
    code.mov(rcx, qword_ptr(rcx + 24))?;
    code.lea(rdx, ptr(rsp + 0x30))?;
    com(&mut code, 6)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    let iid = constants.push(BUILDER_IID.to_vec());
    code.mov(rcx, qword_ptr(rsp + 0x30))?;
    code.lea(rdx, relative(iid))?;
    code.lea(r8, ptr(rsp + 0x38))?;
    com(&mut code, 0)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.mov(rcx, qword_ptr(rsp + 0x38))?;
    code.mov(rdx, qword_ptr(rsp + 0x98))?;
    code.mov(r8, qword_ptr(rsp + 0x50))?;
    code.lea(r9, ptr(rsp + 0x20))?;
    fluent(&mut code, 6, cleanup)?;
    for offset in [0x68, 0x80] {
        code.mov(rcx, qword_ptr(rsp + 0x38))?;
        code.mov(rdx, qword_ptr(rsp + offset))?;
        code.lea(r8, ptr(rsp + 0x20))?;
        fluent(&mut code, 10, cleanup)?;
    }
    code.mov(rcx, qword_ptr(rsp + 0x38))?;
    code.lea(rdx, ptr(rsp + 0x20))?;
    fluent(&mut code, 26, cleanup)?;
    code.mov(rcx, qword_ptr(rsp + 0x38))?;
    code.mov(rdx, qword_ptr(rsp + 0x50))?;
    code.lea(r8, ptr(rsp + 0x20))?;
    fluent(&mut code, 33, cleanup)?;
    code.lea(rdx, ptr(rsp + 0xf0))?;
    code.mov(r8, rsi)?;
    code.call(native.avatar)?;
    code.cmp(qword_ptr(rsp + 0x100), 0)?;
    code.je(build)?;
    code.lea(r14, ptr(rsp + 0xf0))?;
    native.text(&mut code, r14, 0xa8, 0xc0)?;
    code.mov(rcx, qword_ptr(rbx + native.state))?;
    code.mov(rcx, qword_ptr(rcx + 32))?;
    code.mov(rdx, qword_ptr(rsp + 0xb0))?;
    code.lea(r8, ptr(rsp + 0x28))?;
    com(&mut code, 6)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.mov(rcx, qword_ptr(rsp + 0x38))?;
    code.mov(rdx, qword_ptr(rsp + 0x28))?;
    code.mov(r8d, crop)?;
    code.lea(r9, ptr(rsp + 0x20))?;
    fluent(&mut code, 18, cleanup)?;
    code.set_label(&mut build)?;
    code.mov(rcx, qword_ptr(rsp + 0x38))?;
    code.lea(rdx, ptr(rsp + 0x40))?;
    com(&mut code, 32)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.mov(rcx, qword_ptr(rbx + native.state))?;
    code.mov(rcx, qword_ptr(rcx))?;
    code.mov(rdx, qword_ptr(rsp + 0x40))?;
    com(&mut code, 11)?;
    code.mov(edi, eax)?;
    code.set_label(&mut cleanup)?;
    for offset in [0x40, 0x38, 0x30, 0x28] {
        release(&mut code, offset)?;
    }
    for offset in [0xb0, 0x98, 0x80, 0x68, 0x50] {
        code.mov(rcx, qword_ptr(rsp + offset))?;
        code.call(native.delete_string)?;
    }
    for offset in [0xf0, 0xd0] {
        code.lea(rcx, ptr(rsp + offset))?;
        code.call(native.destroy_string)?;
    }
    code.test(edi, edi)?;
    code.jns(done)?;
    native.trace(
        &mut code,
        &mut constants,
        "AppNotificationManager::Show failed.\n",
    )?;
    code.set_label(&mut done)?;
    end(&mut code, &saved, 0x118)?;
    finish(image, function, code, constants, &unwind)
}

fn click(
    image: &Image<'_>,
    function: &Range<u64>,
    native: &Native,
    router: u64,
) -> Result<Vec<Edit>> {
    let mut code = CodeAssembler::new(64)?;
    let mut constants = Constants::new(function.end);
    let saved = [rbx, rsi, rdi];
    let unwind = begin(&mut code, &saved, 0xa0)?;
    let mut cleanup = code.create_label();
    code.mov(rsi, r8)?;
    code.xorps(xmm0, xmm0)?;
    code.movups(ptr(rsp + 0x20), xmm0)?;
    code.movq(qword_ptr(rsp + 0x38), xmm0)?;
    code.movq(qword_ptr(rsp + 0x50), xmm0)?;
    let iid = constants.push(ARGUMENTS_IID.to_vec());
    code.mov(rcx, rsi)?;
    code.lea(rdx, relative(iid))?;
    code.lea(r8, ptr(rsp + 0x20))?;
    com(&mut code, 0)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.mov(rcx, qword_ptr(rsp + 0x20))?;
    code.lea(rdx, ptr(rsp + 0x28))?;
    com(&mut code, 6)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    native.literal(&mut code, &mut constants, "session", 0x48, 0x68)?;
    code.mov(rax, qword_ptr(rsp + 0x48))?;
    code.mov(qword_ptr(rsp + 0x30), rax)?;
    code.mov(byte_ptr(rsp + 0x40), 0)?;
    code.mov(rcx, qword_ptr(rsp + 0x28))?;
    code.mov(rdx, qword_ptr(rsp + 0x50))?;
    code.lea(r8, ptr(rsp + 0x38))?;
    com(&mut code, 6)?;
    code.mov(edi, eax)?;
    hresult(&mut code, cleanup)?;
    code.mov(ecx, 0x80)?;
    code.call(native.allocate)?;
    code.mov(rbx, rax)?;
    code.mov(rcx, rbx)?;
    code.lea(rdx, relative(native.invoke))?;
    code.lea(r8, relative(native.destroy_task))?;
    code.call(native.bind)?;
    code.lea(rax, relative(router))?;
    code.mov(qword_ptr(rbx + 0x20), rax)?;
    code.xorps(xmm0, xmm0)?;
    code.movups(ptr(rbx + 0x48), xmm0)?;
    code.movups(ptr(rbx + 0x58), xmm0)?;
    code.movups(ptr(rbx + 0x68), xmm0)?;
    code.movq(qword_ptr(rbx + 0x78), xmm0)?;
    code.mov(dword_ptr(rbx + 0x48), 3)?;
    code.mov(byte_ptr(rbx + 0x4c), 1)?;
    code.lea(rcx, ptr(rsp + 0x30))?;
    code.lea(rdx, ptr(rbx + 0x28))?;
    code.call(native.read_string)?;
    code.mov(qword_ptr(rsp + 0x60), rbx)?;
    let name = constants.push(b"NotificationInvoked\0".to_vec());
    code.lea(rcx, ptr(rsp + 0x78))?;
    code.lea(rdx, relative(name))?;
    code.lea(r8, relative(native.source))?;
    code.xor(r9d, r9d)?;
    code.call(native.location)?;
    code.lea(rcx, ptr(rsp + 0x78))?;
    code.lea(rdx, ptr(rsp + 0x60))?;
    code.xor(r8d, r8d)?;
    code.xor(r9d, r9d)?;
    code.call(native.post)?;
    code.mov(edi, 0x8000_4005u32)?;
    code.test(al, al)?;
    code.jz(cleanup)?;
    code.xor(edi, edi)?;
    code.set_label(&mut cleanup)?;
    release(&mut code, 0x28)?;
    release(&mut code, 0x20)?;
    code.mov(rcx, qword_ptr(rsp + 0x38))?;
    code.call(native.delete_string)?;
    code.mov(rcx, qword_ptr(rsp + 0x50))?;
    code.call(native.delete_string)?;
    code.mov(eax, edi)?;
    end(&mut code, &saved, 0xa0)?;
    finish(image, function, code, constants, &unwind)
}

fn delegate(image: &Image<'_>, native: &Native) -> Result<Vec<Edit>> {
    let query = image
        .function(pointed(image, native.delegate)?)?
        .ok_or("找不到事件接口查询函数")?;
    let original: Vec<_> = image
        .instructions(&query)?
        .iter()
        .filter(|instruction| {
            instruction.mnemonic() == Mnemonic::Xor && instruction.op1_kind() == OpKind::Immediate32
        })
        .map(Instruction::immediate32)
        .collect();
    let original = original
        .get(
            original
                .len()
                .checked_sub(4)
                .ok_or("找不到原事件接口 IID")?..,
        )
        .ok_or("找不到原事件接口 IID")?;
    let mut code = CodeAssembler::new(64)?;
    let mut constants = Constants::new(query.end);
    let unwind = begin(&mut code, &[], 0x28)?;
    let mut matched = code.create_label();
    let mut done = code.create_label();
    code.mov(qword_ptr(r8), 0)?;
    code.movups(xmm0, ptr(rdx))?;
    let unknown = vec![0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
    for iid in [
        unknown,
        original
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect(),
        HANDLER_IID.to_vec(),
    ] {
        let iid = constants.push(iid);
        code.movups(xmm1, ptr(Register::RIP) + iid)?;
        code.pcmpeqd(xmm1, xmm0)?;
        code.movmskps(eax, xmm1)?;
        code.cmp(al, 15)?;
        code.je(matched)?;
    }
    code.mov(eax, 0x8000_4002u32)?;
    code.jmp(done)?;
    code.set_label(&mut matched)?;
    code.mov(qword_ptr(r8), rcx)?;
    com(&mut code, 1)?;
    code.xor(eax, eax)?;
    code.set_label(&mut done)?;
    end(&mut code, &[], 0x28)?;
    finish(image, &query, code, constants, &unwind)
}

fn saved_argument(instructions: &[Instruction], argument: Register) -> Result<Register> {
    unique(
        instructions
            .iter()
            .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
            .filter(|instruction| {
                instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op1_register() == argument
                    && instruction.op0_register() != argument
            })
            .map(Instruction::op0_register)
            .collect(),
        "通知函数保存的参数",
    )
}

fn window_block(instructions: &[Instruction], offset: i64) -> Result<Range<u64>> {
    let ranges: Vec<_> = instructions
        .windows(3)
        .filter(|part| {
            part[0].code() == Code::Mov_r64_rm64
                && part[0].op0_register() == Register::RCX
                && part[0].memory_displacement64() as i64 == offset
                && part[1].mnemonic() == Mnemonic::Test
                && part[1].op0_register() == Register::RCX
                && part[2].mnemonic() == Mnemonic::Je
        })
        .map(|part| part[0].ip()..part[2].near_branch_target())
        .collect();
    unique(
        ranges
            .iter()
            .filter(|range| {
                !ranges
                    .iter()
                    .any(|other| other.start < range.start && other.end >= range.end)
            })
            .cloned()
            .collect(),
        "原悬浮窗口操作",
    )
}

fn prepare(
    image: &Image<'_>,
    symbols: &Symbols,
    found: &BTreeMap<&str, Range<u64>>,
    references: &References,
    progress: &Progress,
) -> Result<Vec<Mode>> {
    let step = progress.activity("定位系统通知");
    let (native, click_function, clear_function, alert_call) =
        native(image, symbols, found, references)?;
    let mut edits = runtime(image, &found[TIMER], &native)?;
    let (window, names) = window(image, &found[WINDOW], &native)?;
    edits.extend(window);
    edits.extend(close(image, &found[CLOSE], &native)?);
    edits.extend(delegate(image, &native)?);
    let (creation, manager) = create(image, found, &native, click_function.start, names)?;
    edits.extend(creation);
    edits.extend(clear(image, &clear_function, &native, manager)?);
    edits.extend(click(image, &click_function, &native, found[ROUTER].start)?);
    let init = image.instructions(&found[INIT])?;
    let load = unique(
        init.iter()
            .filter(|instruction| {
                instruction.code() == Code::Call_rel32_64
                    && instruction.near_branch_target() == found[LOAD].start
            })
            .collect(),
        "通知初始化调用",
    )?;
    edits.push(redirect(image, load, found[CREATE].start)?);
    edits.push(redirect(image, &alert_call, found[SHOW].start)?);
    for name in [HOVER, HIDE] {
        let offset = image.offset(found[name].start)?;
        edits.push(Edit {
            range: offset..offset + 1,
            bytes: vec![0xc3],
        });
    }
    let destructor = image.instructions(&found[DESTROY])?;
    let receiver = saved_argument(&destructor, Register::RCX)?;
    let mut code = CodeAssembler::new(64)?;
    code.add_instruction(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RCX,
        receiver,
    )?)?;
    code.call(found[CLOSE].start)?;
    edits.push(patch(
        image,
        window_block(&destructor, native.state - 8)?,
        &mut code,
    )?);
    let update = image.instructions(&found[UPDATE])?;
    let session = saved_argument(&update, Register::RDX)?;
    let range = window_block(&update, native.state - 8)?;
    let mut code = CodeAssembler::new(64)?;
    code.add_instruction(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RCX,
        session,
    )?)?;
    code.call(found[FILTER].start)?;
    code.test(al, al)?;
    code.jz(range.end)?;
    code.add_instruction(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RDX,
        session,
    )?)?;
    code.call(clear_function.start)?;
    edits.push(patch(image, range, &mut code)?);
    for (name, address) in [
        ("通知显示", found[SHOW].start),
        ("通知点击", click_function.start),
        ("通知清理", clear_function.start),
        ("消息摘要", native.summary),
        ("GUI 派发", native.post),
    ] {
        step.record(format!("{name}；RVA 0x{:08X}", address - image.base()));
    }
    let modes = [("square", "方形头像", 0), ("circle", "圆形头像", 1)]
        .into_iter()
        .map(|(id, name, crop)| {
            let mut edits = edits.clone();
            edits.extend(show(image, &found[SHOW], &native, crop)?);
            Ok(Mode { id, name, edits })
        })
        .collect::<Result<_>>()?;
    step.finish("系统通知");
    Ok(modes)
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let mut symbols = xlog::find(image, FUNCTIONS, progress)?;
    for name in [CAPTURE, FACTORY, STRING, STRING_DELETE, STRING_BUFFER] {
        let bytes: Vec<_> = name.bytes().chain([0]).collect();
        symbols.insert(name.to_owned(), image.find(name, &bytes, progress)?);
    }
    Ok(symbols)
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
        let mut found = BTreeMap::new();
        for &name in FUNCTIONS {
            found.insert(
                name,
                unique(
                    functions(name, &self.symbols, references)
                        .into_values()
                        .collect(),
                    name,
                )?,
            );
        }
        prepare(image, &self.symbols, &found, references, progress)
    }
}
