use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    ops::Range,
    path::{Path, PathBuf},
};

use iced_x86::{
    Code, Decoder, DecoderOptions, Instruction, MemoryOperand, Mnemonic, OpKind, Register,
    code_asm::{
        CodeAssembler, al, byte_ptr, dl, dword_ptr, eax, ecx, edi, edx, esi, ptr, qword_ptr, r8d,
        r9, r9d, r10, r11, rax, rbp, rcx, rdi, rdx, rsi, rsp, word_ptr,
    },
};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, functions},
    progress::Progress,
    store, xlog,
};

const INIT: &str = "kernel::datapathutil::InitDirs";
const OTHER: &str = "kernel::service::NativeIpcService::ForwardExistedProcessExceptSelf";
const WINDOW: &str = "xWechatWindow";
const MUTEX: &str = "XWeChat_App_Instance_Identity_Mutex_Name";
const CLASS: &str = "Chrome_MessageWindow";
const LOCKED: &str = "mmkv_key_logout_locked_flag";
const FUNCTIONS: &[&str] = &[INIT, OTHER, LOCKED];
const KEYS: &[&str] = &[
    "mmkv_key_user_name",
    "mmkv_key_auto_login_flag",
    "mmkv_key_push_login_url_expired_time",
    "mmkv_key_nick_name",
    "mmkv_key_auto_auth_key",
    "mmkv_key_head_img_url",
    "mmkv_key_pc_account_name",
    "mmkv_key_server_id",
    LOCKED,
];

pub const FEATURE: Feature = Feature {
    id: "coexist",
    name: "多账号共存",
    description: "各字母入口分别记住各自的账号，共用程序文件和聊天数据",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

pub fn letter(value: &str) -> Result<char> {
    let [value] = value.as_bytes() else {
        return Err("入口名称应为一个英文字母".into());
    };
    if !value.is_ascii_alphabetic() {
        return Err("入口名称应为一个英文字母".into());
    }
    Ok(char::from(value.to_ascii_uppercase()))
}

pub fn directory(target: &Path) -> Result<PathBuf> {
    let directory = target
        .parent()
        .and_then(Path::parent)
        .ok_or("找不到微信安装目录")?;
    let launcher = directory.join("Weixin.exe");
    let metadata = fs::metadata(&launcher)
        .map_err(|error| format!("无法读取 {}：{error}", store::display(&launcher)))?;
    if !metadata.is_file() {
        return Err("Weixin.exe 不是文件".into());
    }
    Ok(directory.to_owned())
}

pub fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    let directory = path.parent().ok_or("入口缺少父目录")?;
    let target = fs::read_link(path)
        .map_err(|error| format!("无法读取 {} 的联接目标：{error}", store::display(path)))?;
    if directory.join(target).canonicalize()? != directory.canonicalize()? {
        return Err(format!("{} 指向其他目录", store::display(path)).into());
    }
    Ok(true)
}

#[cfg(windows)]
pub fn remove(path: &Path, progress: &Progress) -> Result<()> {
    if !exists(path)? {
        return Err(format!("{} 不存在", store::display(path)).into());
    }
    let step = progress.activity("删除目录联接");
    step.detail(store::display(path));
    progress.check()?;
    fs::remove_dir(path)?;
    step.finish(store::display(path));
    Ok(())
}

#[cfg(not(windows))]
pub fn remove(_path: &Path, _progress: &Progress) -> Result<()> {
    Err("删除共存入口需要 Windows".into())
}

#[cfg(windows)]
pub fn create(path: &Path, progress: &Progress) -> Result<()> {
    use std::{
        fs::OpenOptions,
        io,
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        ptr::null_mut,
    };

    use windows_sys::Win32::{
        Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT},
        System::{
            IO::DeviceIoControl, Ioctl::FSCTL_SET_REPARSE_POINT,
            SystemServices::IO_REPARSE_TAG_MOUNT_POINT,
        },
    };

    let directory = path.parent().ok_or("入口缺少父目录")?.canonicalize()?;
    let mut substitute: Vec<u16> = directory.as_os_str().encode_wide().collect();
    // Junction targets use the NT path namespace.
    substitute[1] = u16::from(b'?');
    let display: Vec<u16> = store::display(&directory).encode_utf16().collect();
    let size = u16::try_from(12 + (substitute.len() + display.len()) * 2)?;
    let substitute_size = u16::try_from(substitute.len() * 2)?;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    for value in [
        size,
        0,
        0,
        substitute_size,
        substitute_size + 2,
        u16::try_from(display.len() * 2)?,
    ] {
        buffer.extend_from_slice(&value.to_le_bytes());
    }
    buffer.extend(
        substitute
            .into_iter()
            .chain([0])
            .chain(display)
            .chain([0])
            .flat_map(u16::to_le_bytes),
    );
    let step = progress.activity("创建目录联接");
    step.detail(format!(
        "{} → {}",
        store::display(path),
        store::display(&directory)
    ));
    progress.check()?;
    fs::create_dir(path)?;
    let result = (|| -> io::Result<()> {
        let handle = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let mut returned = 0;
        if unsafe {
            DeviceIoControl(
                handle.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    if let Err(error) = result {
        if let Err(remove) = fs::remove_dir(path) {
            return Err(format!("创建入口失败：{error}；无法移除空目录：{remove}").into());
        }
        return Err(error.into());
    }
    step.finish(store::display(&path.join("Weixin.exe")));
    Ok(())
}

#[cfg(not(windows))]
pub fn create(_path: &Path, _progress: &Progress) -> Result<()> {
    Err("创建共存入口需要 Windows".into())
}

struct Scan {
    symbols: Symbols,
    emitted: bool,
}

struct Cleanup {
    range: Range<usize>,
    object: i32,
    free: u64,
    fail: u64,
}

fn wide(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn relative(address: u64) -> MemoryOperand {
    MemoryOperand::new(
        Register::RIP,
        Register::None,
        1,
        address as i64,
        4,
        false,
        Register::None,
    )
}

fn address(symbols: &Symbols, name: &str) -> Result<u64> {
    let values = symbols.get(name).ok_or_else(|| format!("找不到{name}"))?;
    let [address] = values[..] else {
        return Err(format!("无法唯一定位{name}").into());
    };
    Ok(address)
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let mut symbols = xlog::find(image, &[INIT, OTHER], progress)?;
    for name in [WINDOW, MUTEX] {
        symbols.insert(name.to_owned(), image.find(name, &wide(name), progress)?);
        address(&symbols, name)?;
    }
    symbols.insert(CLASS.to_owned(), image.find(CLASS, &wide(CLASS), progress)?);
    for &key in KEYS {
        let bytes: Vec<_> = key.bytes().chain([0]).collect();
        symbols.insert(key.to_owned(), image.find(key, &bytes, progress)?);
        address(&symbols, key)?;
    }
    Ok(symbols)
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan {
        symbols,
        emitted: false,
    })
}

impl Analysis for Scan {
    fn visit(
        &mut self,
        image: &Image<'_>,
        _function: &Range<u64>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Edit>> {
        if self.emitted {
            return Ok(Vec::new());
        }
        let mut found = BTreeMap::new();
        for &name in FUNCTIONS {
            let matches = functions(name, &self.symbols, references);
            if matches.len() > 1 {
                return Err(format!("无法唯一定位{name}").into());
            }
            if let Some(function) = matches.into_values().next() {
                found.insert(name, function);
            }
        }
        if found.len() != FUNCTIONS.len() {
            return Ok(Vec::new());
        }
        let edits = prepare(image, &self.symbols, &found, references, progress)?;
        self.emitted = true;
        Ok(edits)
    }

    fn finish(
        self: Box<Self>,
        _image: &Image<'_>,
        _references: &References,
        _progress: &Progress,
    ) -> Result<Vec<Mode>> {
        if !self.emitted {
            return Err("找不到完整的共存初始化流程".into());
        }
        Ok(vec![Mode::enabled(Vec::new())])
    }
}

fn same(left: Instruction, right: Instruction) -> bool {
    let mut left = left;
    let mut right = right;
    left.set_ip(0);
    right.set_ip(0);
    left == right
}

fn cleanups(instructions: &[Instruction], before: u64) -> Vec<Cleanup> {
    instructions
        .windows(16)
        .enumerate()
        .filter(|(_, part)| {
            part[0].ip() < before
                && part[0].code() == Code::Mov_r64_rm64
                && part[0].op0_register() == Register::RAX
                && part[0].memory_base() == Register::RBP
                && part[0].memory_index() == Register::None
                && part[1].code() == Code::Cmp_rm64_imm8
                && part[1].op0_register() == Register::RAX
                && part[1].immediate8() == 16
                && matches!(part[2].code(), Code::Jb_rel8_64 | Code::Jb_rel32_64)
                && part[3].code() == Code::Mov_r64_rm64
                && part[3].op0_register() == Register::RCX
                && part[3].memory_base() == Register::RBP
                && part[3].memory_index() == Register::None
                && part[3].memory_displacement64().wrapping_add(24)
                    == part[0].memory_displacement64()
                && part[15].code() == Code::Call_rel32_64
                && part[2].near_branch_target() == part[15].next_ip()
                && matches!(part[6].code(), Code::Jb_rel8_64 | Code::Jb_rel32_64)
                && part[6].near_branch_target() == part[15].ip()
                && matches!(part[11].code(), Code::Jae_rel8_64 | Code::Jae_rel32_64)
        })
        .map(|(index, part)| Cleanup {
            range: index..index + 16,
            object: part[3].memory_displacement64() as i32,
            free: part[15].near_branch_target(),
            fail: part[11].near_branch_target(),
        })
        .collect()
}

fn destructor(
    image: &Image<'_>,
    instructions: &[Instruction],
    cleanup: &[Cleanup],
    references: &References,
) -> Result<u64> {
    let first = cleanup.first().ok_or("找不到可复用的字符串清理代码")?;
    let failure = Decoder::with_ip(
        64,
        image.data(first.fail, 5)?,
        first.fail,
        DecoderOptions::NONE,
    )
    .decode();
    if failure.code() != Code::Call_rel32_64 {
        return Err("无法识别字符串内存检查".into());
    }
    let mut found = Vec::new();
    for function in references.get(first.free).into_iter().flatten() {
        let body = image.instructions(function)?;
        let [
            enter,
            load,
            compare,
            small,
            pointer,
            middle @ ..,
            leave,
            jump,
            leave_small,
            ret,
            fail,
            trap,
        ] = body.as_slice()
        else {
            continue;
        };
        if middle.len() != 11
            || enter.code() != Code::Sub_rm64_imm8
            || enter.op0_register() != Register::RSP
            || enter.immediate8() != 40
            || load.code() != Code::Mov_r64_rm64
            || load.op0_register() != Register::RAX
            || load.memory_base() != Register::RCX
            || load.memory_index() != Register::None
            || load.memory_displacement64() != 24
            || compare.code() != Code::Cmp_rm64_imm8
            || compare.op0_register() != Register::RAX
            || compare.immediate8() != 16
            || !matches!(small.code(), Code::Jb_rel8_64 | Code::Jb_rel32_64)
            || small.near_branch_target() != leave_small.ip()
            || pointer.code() != Code::Mov_r64_rm64
            || pointer.op0_register() != Register::RCX
            || pointer.memory_base() != Register::RCX
            || pointer.memory_index() != Register::None
            || pointer.memory_displacement64() != 0
            || leave.code() != Code::Add_rm64_imm8
            || leave.op0_register() != Register::RSP
            || leave.immediate8() != 40
            || !same(*leave, *leave_small)
            || jump.code() != Code::Jmp_rel32_64
            || jump.near_branch_target() != first.free
            || ret.mnemonic() != Mnemonic::Ret
            || fail.code() != Code::Call_rel32_64
            || fail.near_branch_target() != failure.near_branch_target()
            || trap.mnemonic() != Mnemonic::Int3
        {
            continue;
        }
        let equivalent = cleanup.iter().all(|cleanup| {
            let part = &instructions[cleanup.range.clone()];
            cleanup.free == first.free
                && cleanup.fail == first.fail
                && [
                    (4, 5),
                    (5, 6),
                    (7, 8),
                    (8, 9),
                    (9, 10),
                    (10, 11),
                    (12, 13),
                    (13, 14),
                    (14, 15),
                ]
                .iter()
                .all(|&(inline, shared)| same(part[inline], body[shared]))
                && matches!(body[7].code(), Code::Jb_rel8_64 | Code::Jb_rel32_64)
                && body[7].near_branch_target() == leave.ip()
                && matches!(body[12].code(), Code::Jae_rel8_64 | Code::Jae_rel32_64)
                && body[12].near_branch_target() == fail.ip()
        });
        if equivalent {
            found.push(function.start);
        }
    }
    let [address] = found[..] else {
        return Err("无法唯一定位等效的字符串析构函数".into());
    };
    Ok(address)
}

fn initialize(
    image: &Image<'_>,
    function: &Range<u64>,
    symbols: &Symbols,
    locked: u64,
    imports: &Symbols,
    references: &References,
) -> Result<Vec<Edit>> {
    let mut targets = KEYS
        .iter()
        .map(|key| Ok(address(symbols, key)? + key.len() as u64 - 1))
        .collect::<Result<Vec<_>>>()?;
    for name in [MUTEX, WINDOW] {
        targets.push(address(symbols, name)? + (name.len() as u64 - 1) * 2);
    }
    targets.sort_unstable();
    let first = targets[0];
    let size = u32::try_from(targets[targets.len() - 1] - first + 1)?;
    image.data(first, size as usize)?;
    let protect = address(imports, "VirtualProtect")?;
    let body = image.instructions(function)?;
    let failures: Vec<_> =
        body.windows(4)
            .filter(|part| {
                [0, 2].iter().all(|&index| {
                    part[index].code() == Code::Cmp_rm64_imm8
                        && part[index].is_ip_rel_memory_operand()
                        && part[index].immediate8() == 0
                }) && [1, 3].iter().all(|&index| {
                    matches!(part[index].code(), Code::Je_rel8_64 | Code::Je_rel32_64)
                }) && part[1].near_branch_target() == part[3].near_branch_target()
            })
            .map(|part| part[1].near_branch_target())
            .collect();
    let [failure] = failures[..] else {
        return Err("无法定位目录初始化失败处理".into());
    };
    let constructors: Vec<_> = body
        .windows(7)
        .filter(|part| {
            matches!(part[0].code(), Code::Mov_r64_rm64 | Code::Mov_rm64_r64)
                && part[0].op0_register() == Register::RCX
                && part[0].op1_kind() == OpKind::Register
                && part[0].op1_register() == Register::RSI
                && part[1].code() == Code::Call_rel32_64
                && part[2].mnemonic() == Mnemonic::Nop
                && part[3].code() == Code::Mov_r32_imm32
                && part[3].op0_register() == Register::ECX
                && part[3].immediate32() == 6
                && matches!(part[4].code(), Code::Mov_r64_rm64 | Code::Mov_rm64_r64)
                && part[4].op0_register() == Register::RDX
                && part[4].op1_kind() == OpKind::Register
                && part[4].op1_register() == Register::RSI
                && part[5].code() == Code::Call_rel32_64
        })
        .map(|part| (part[2].ip(), part[5].near_branch_target()))
        .collect();
    let [(insert, query)] = constructors[..] else {
        return Err("无法定位目录对象的初始化位置".into());
    };
    let cleanup = cleanups(&body, failure);
    let drop = destructor(image, &body, &cleanup, references)?;
    let mut code = CodeAssembler::new(64)?;
    let mut done = code.create_label();
    code.mov(ecx, 3)?;
    code.mov(rdx, rsi)?;
    code.call(query)?;
    code.test(al, al)?;
    code.je(failure)?;
    code.mov(rax, qword_ptr(rsi + 16))?;
    code.cmp(rax, 2)?;
    code.jb(done)?;
    code.mov(rdx, rsi)?;
    code.cmp(qword_ptr(rsi + 24), 8)?;
    code.cmovae(rdx, qword_ptr(rsi))?;
    code.cmp(word_ptr(rdx + rax * 2 - 4), 92)?;
    code.jne(done)?;
    code.movzx(eax, word_ptr(rdx + rax * 2 - 2))?;
    code.and(eax, -33)?;
    code.lea(ecx, ptr(rax - i32::from(b'A')))?;
    code.cmp(ecx, i32::from(b'Z' - b'A'))?;
    code.ja(done)?;
    // Logging calls reserve outgoing stack argument slots here.
    code.mov(byte_ptr(rsp + 40), al)?;
    code.add_instruction(Instruction::with2(
        Code::Lea_r64_m,
        Register::RCX,
        relative(first),
    )?)?;
    code.mov(edx, size)?;
    code.mov(r8d, 8)?;
    code.lea(r9, ptr(rsp + 32))?;
    code.add_instruction(Instruction::with1(Code::Call_rm64, relative(protect))?)?;
    code.test(eax, eax)?;
    code.je(failure)?;
    code.mov(dl, byte_ptr(rsp + 40))?;
    for target in targets {
        code.add_instruction(Instruction::with2(
            Code::Mov_rm8_r8,
            relative(target),
            Register::DL,
        )?)?;
    }
    code.add_instruction(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        relative(locked),
    )?)?;
    code.mov(byte_ptr(rax + LOCKED.len() as i32 - 1), dl)?;
    code.add_instruction(Instruction::with2(
        Code::Lea_r64_m,
        Register::RCX,
        relative(first),
    )?)?;
    code.mov(edx, size)?;
    code.mov(r8d, dword_ptr(rsp + 32))?;
    code.lea(r9, ptr(rsp + 36))?;
    code.add_instruction(Instruction::with1(Code::Call_rm64, relative(protect))?)?;
    code.test(eax, eax)?;
    code.je(failure)?;
    code.set_label(&mut done)?;
    code.nop()?;
    let staging = image.end();
    let bytes = code.assemble(staging)?;
    let mut prefix: Vec<_> = Decoder::with_ip(64, &bytes, staging, DecoderOptions::NONE)
        .into_iter()
        .collect();
    prefix[0].set_ip(insert);
    let mut instructions = Vec::new();
    for (index, instruction) in body.iter().enumerate() {
        if instruction.ip() == insert {
            instructions.extend_from_slice(&prefix);
        } else if let Some(cleanup) = cleanup.iter().find(|cleanup| cleanup.range.start == index) {
            let mut code = CodeAssembler::new(64)?;
            code.lea(rcx, ptr(rbp + cleanup.object))?;
            code.call(drop)?;
            let bytes = code.assemble(instruction.ip())?;
            instructions.extend(Decoder::with_ip(
                64,
                &bytes,
                instruction.ip(),
                DecoderOptions::NONE,
            ));
        } else if !cleanup.iter().any(|cleanup| cleanup.range.contains(&index)) {
            instructions.push(*instruction);
        }
    }
    image.reencode(function, &instructions)
}

fn forward(
    image: &Image<'_>,
    function: &Range<u64>,
    symbols: &Symbols,
    imports: &Symbols,
) -> Result<Vec<Edit>> {
    let body = image.instructions(function)?;
    let pid = address(imports, "GetCurrentProcessId")?;
    let classes: Vec<_> = body
        .iter()
        .filter(|instruction| {
            instruction.code() == Code::Lea_r64_m
                && instruction.op0_register() == Register::R8
                && instruction.is_ip_rel_memory_operand()
                && symbols[CLASS].contains(&instruction.ip_rel_memory_address())
        })
        .map(Instruction::ip_rel_memory_address)
        .collect();
    let [class] = classes[..] else {
        return Err("无法定位消息窗口查找使用的窗口类".into());
    };
    let candidates: Vec<_> = body
        .windows(3)
        .filter(|part| {
            part[0].is_ip_rel_memory_operand()
                && part[0].ip_rel_memory_address() == pid
                && matches!(part[1].code(), Code::Cmp_r32_rm32 | Code::Cmp_rm32_r32)
                && part[1].op0_register() == Register::EDI
                && part[1].op1_register() == Register::EAX
                && matches!(part[2].code(), Code::Jne_rel8_64 | Code::Jne_rel32_64)
        })
        .collect();
    let [candidate] = candidates[..] else {
        return Err("无法定位其它实例的进程判断".into());
    };
    let found = candidate[2].near_branch_target();
    let end = candidate[2].next_ip();
    let missing: Vec<_> = body
        .windows(2)
        .filter(|part| {
            part[0].ip() < candidate[0].ip()
                && part[0].code() == Code::Test_rm64_r64
                && part[0].op0_register() == Register::RSI
                && part[0].op1_register() == Register::RSI
                && matches!(part[1].code(), Code::Je_rel8_64 | Code::Je_rel32_64)
        })
        .map(|part| part[1].near_branch_target())
        .collect();
    let [missing] = missing[..] else {
        return Err("无法定位消息窗口的查找结果".into());
    };
    let begin = body
        .iter()
        .find(|instruction| {
            instruction.code() == Code::Mov_rm64_imm32
                && instruction.memory_base() == Register::RBP
                && instruction.immediate32() == (-2i32) as u32
        })
        .ok_or("找不到消息窗口查找的函数入口")?
        .next_ip();
    let mut code = CodeAssembler::new(64)?;
    let mut next = code.create_label();
    let mut prefix = code.create_label();
    code.add_instruction(Instruction::with1(Code::Call_rm64, relative(pid))?)?;
    code.mov(edi, eax)?;
    code.xor(esi, esi)?;
    code.set_label(&mut next)?;
    code.mov(rcx, -3i64)?;
    code.mov(rdx, rsi)?;
    code.add_instruction(Instruction::with2(
        Code::Lea_r64_m,
        Register::R8,
        relative(class),
    )?)?;
    code.xor(r9d, r9d)?;
    code.add_instruction(Instruction::with1(
        Code::Call_rm64,
        relative(address(imports, "FindWindowExW")?),
    )?)?;
    code.mov(rsi, rax)?;
    code.test(rsi, rsi)?;
    code.je(missing)?;
    code.mov(rcx, rsi)?;
    code.lea(rdx, ptr(rsp + 64))?;
    code.add_instruction(Instruction::with1(
        Code::Call_rm64,
        relative(address(imports, "GetWindowThreadProcessId")?),
    )?)?;
    code.cmp(dword_ptr(rsp + 64), edi)?;
    code.je(next)?;
    code.mov(rcx, rsi)?;
    code.lea(rdx, ptr(rsp + 32))?;
    code.mov(r8d, i32::try_from(WINDOW.len() + 2)?)?;
    code.add_instruction(Instruction::with1(
        Code::Call_rm64,
        relative(address(imports, "GetWindowTextW")?),
    )?)?;
    code.cmp(eax, i32::try_from(WINDOW.len())?)?;
    code.jne(next)?;
    code.movzx(eax, word_ptr(rsp + 32 + (WINDOW.len() as i32 - 1) * 2))?;
    code.cmp(eax, i32::from(b'w'))?;
    code.je(prefix)?;
    code.sub(eax, i32::from(b'A'))?;
    code.cmp(eax, i32::from(b'Z' - b'A'))?;
    code.ja(next)?;
    code.set_label(&mut prefix)?;
    code.mov(r10, rsi)?;
    code.mov(r11, rdi)?;
    code.lea(rsi, ptr(rsp + 32))?;
    code.add_instruction(Instruction::with2(
        Code::Lea_r64_m,
        Register::RDI,
        relative(address(symbols, WINDOW)?),
    )?)?;
    code.mov(ecx, u32::try_from(WINDOW.len() - 1)?)?;
    code.repe().cmpsw()?;
    code.mov(rsi, r10)?;
    code.mov(rdi, r11)?;
    code.jne(next)?;
    code.jmp(found)?;
    let mut bytes = code.assemble(begin)?;
    let length = usize::try_from(end - begin)?;
    if bytes.len() > length {
        return Err("原消息窗口查找代码的空间不足".into());
    }
    bytes.resize(length, 0x90);
    let offset = image.offset(begin)?;
    let mut edits = vec![Edit {
        range: offset..offset + length,
        bytes,
    }];
    for state in image.exception_states(function.start)? {
        if (begin..end).contains(&state.instruction) && state.state != -1 {
            edits.push(Edit {
                range: state.offset + 4..state.offset + 8,
                bytes: (-1i32).to_le_bytes().to_vec(),
            });
        }
    }
    Ok(edits)
}

fn prepare(
    image: &Image<'_>,
    symbols: &Symbols,
    found: &BTreeMap<&str, Range<u64>>,
    references: &References,
    progress: &Progress,
) -> Result<Vec<Edit>> {
    let step = progress.activity("准备共存数据");
    let constructor = image.instructions(&found[LOCKED])?;
    let objects: Vec<_> = constructor
        .iter()
        .filter(|instruction| {
            instruction.code() == Code::Mov_rm64_r64
                && instruction.is_ip_rel_memory_operand()
                && instruction.op1_register() == Register::RAX
        })
        .map(Instruction::ip_rel_memory_address)
        .filter(|object| {
            [16, 24].iter().all(|&offset| {
                constructor.iter().any(|instruction| {
                    instruction.code() == Code::Mov_rm64_imm32
                        && instruction.is_ip_rel_memory_operand()
                        && instruction.ip_rel_memory_address() == object + offset
                        && if offset == 16 {
                            instruction.immediate32() == LOCKED.len() as u32
                        } else {
                            instruction.immediate32() >= LOCKED.len() as u32
                        }
                })
            })
        })
        .collect();
    let [locked] = objects[..] else {
        return Err("无法唯一定位锁定配置键对象".into());
    };
    step.finish(format!("{LOCKED}；RVA 0x{:08X}", locked - image.base(),));
    let imports = image.imports()?;
    let step = progress.activity("准备目录身份初始化");
    let mut edits = initialize(image, &found[INIT], symbols, locked, &imports, references)?;
    step.finish(format!(
        "{INIT}；RVA 0x{:08X}",
        found[INIT].start - image.base()
    ));
    let step = progress.activity("准备实例间唤起");
    edits.extend(forward(image, &found[OTHER], symbols, &imports)?);
    step.finish(format!(
        "{OTHER}；RVA 0x{:08X}",
        found[OTHER].start - image.base()
    ));
    Ok(edits)
}
