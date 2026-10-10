# UIA

微信的无障碍配置更新会经过 `mmui::accessible::util::UpdateAccessibleEnable`。该函数读取 `accessibility_enable_scheme`，综合配置与辅助技术状态后调用一个独立写入函数。

写入函数的语义为：

```text
mov byte ptr [rip + displacement], cl
ret
```

目标字节在原始文件中为 `1`。Qt 控件查询入口读取这个字节；值为零时返回空接口。补丁将写入函数的首字节改为 `ret`，使开关沿用文件中的启用初值。

定位过程：

1. 在 PE 节中寻找配置键 `accessibility_enable_scheme`。
2. 按异常展开表给出的函数范围解码 x64 指令，找到引用配置键的函数。
3. 从该函数的直接调用和跳转目标中识别字节写入器。
4. 根据 RIP 相对寻址计算开关位置，并根据 PE 节映射取得写入函数的文件位置。

函数地址和数据位移由目标文件计算。Binary Ninja 的函数名称、调用关系及反编译结果用于研究；发布工具通过 PE 解析和指令解码完成定位。

## 参考

- [Qt 无障碍接口](https://github.com/qt/qtbase/blob/5.15/src/gui/accessible/qaccessible.cpp)
- [object](https://github.com/gimli-rs/object)
- [iced-x86](https://github.com/icedland/iced)
