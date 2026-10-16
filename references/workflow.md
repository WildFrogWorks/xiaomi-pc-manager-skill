# 候选入口与已知样本操作说明

## 通用入口：先接收，不做版本白名单判定

使用 Python 3.10+ 从 Skill 根目录运行，只读取用户文件，不执行或解包：

```text
python scripts/inspect_candidate.py --source "<用户提供的实际安装包路径>"
```

可用 `--report "<尚不存在的报告路径>"` 保存结果。输出的指纹用于证据追踪，不要求匹配历史版本；`version_gate_applied` 为 `false`，`patch_ready` 为 `false` 表示需要继续分析机型分支，不能据此宣称补丁已就绪。未知格式/架构也只是待分析状态，不是版本不支持的结论。目录包用静态工具查看内部文件，不传给只接收普通文件的探测器。

若指纹正好命中现有 `profiles/5.8.1.130.json`，并且目标为 Windows x64，可使用下面的固定快捷流程。否则在同一任务内继续 [未知构建与平台适配](adapting-builds.md)。**下面的命令、`/S`、路径和核心文件哈希仅属于已知样本，不是通用跨平台命令。**

## 已知样本快捷流程：Windows x64 / 5.8.1.130

以下命令从 Skill 根目录执行。先把示例变量替换为用户提供的实际路径；路径不是下载地址。原包、副本和工作目录都应位于 Skill 源码目录之外。所有阶段使用同一份已识别原包。

```powershell
$sourceInstaller = 'D:\Downloads\XiaomiPCManager_5.8.1.130.exe'
$workDirectory = 'D:\XiaomiCompatWork'
$preparedInstaller = Join-Path $workDirectory 'XiaomiPCManager_5.8.1.130.compat.exe'
```

`D:` 只是示例，尊重用户现有目录与磁盘偏好。确认路径、空间与依赖后创建工作目录。使用普通本地目录，建议 NTFS；脚本拒绝符号链接、目录联接及源包/输出/报告路径冲突。Python 辅助脚本只使用标准库；不要为此安装 REA 或 Ghidra。Windows 上的签名检查由 PowerShell 辅助脚本完成。

## 1. 识别原包与 Windows 基线

```powershell
python scripts/prepare_installer.py inspect --source "$sourceInstaller"
powershell.exe -NoProfile -File scripts/Invoke-CompatibilityWorkflow.ps1 -Action Inspect -WorkDirectory "$workDirectory" -SourceInstaller "$sourceInstaller"
```

每次命令都要检查退出码和结果。先通过 Python 的精确样本检查，再由 Windows 检查官方原包签名并记录基线；两者均不运行目标。Python 命令可以加 `--report` 写入一个**尚不存在**的 JSON 报告路径；重复运行时用新的报告文件名，不覆盖原报告。

报告不含账号、序列号或完整源路径。源包不匹配时停止使用此固定快捷脚本，并在当前任务内转入 [新样本适配](adapting-builds.md)，不修改常量或忽略校验。输出冲突、链接路径或计划外差异是文件操作问题，应先解决，不能通过未知版本路线绕过这些检查。

检查原包签名、机器是否适合这套工具、现有小米组件及相关进程、服务/任务/驱动状态、空间和无法完成的检查。基线和状态文件只留在该工作目录，不作为 GitHub 发布内容。只读枚举可能受权限影响，不能把查询失败当作「不存在」。

`Inspect` 不覆盖现有基线。同一次任务后续直接复核这份基线，不重复执行；更换电脑/用户、基线超过 24 小时或系统已有变化时，应使用新的独立工作目录重做检查。

## 2. 生成与核对兼容副本

```powershell
python scripts/prepare_installer.py prepare --source "$sourceInstaller" --output "$preparedInstaller"
python scripts/prepare_installer.py verify --source "$sourceInstaller" --output "$preparedInstaller"
```

`prepare` 只生成文件，不运行目标。即使副本已存在，也必须重新验证；不能仅凭文件存在而跳过。需要报告时传入新的 `--report` 文件名。源包、副本和报告不能相互覆盖。

向用户说明：副本来自哪一个精确原包，原签名失效，真正安装使用 `/S`，会部署/更新相关服务与虚拟驱动；没有已验证的自定义程序安装目录参数。若当前会话已有明确授权，不重复询问。若用户仅授权静态准备，到此交付副本与报告。

## 3. 已获授权后安装

```powershell
powershell.exe -NoProfile -File scripts/Invoke-CompatibilityWorkflow.ps1 -Action Install -WorkDirectory "$workDirectory" -PreparedInstaller "$preparedInstaller" -InstallationAuthorized
```

`-InstallationAuthorized` 必须建立在当前用户真实授权上；下载 Skill 不等于授权修改系统。脚本在安装前再次检查精确副本，使用系统 UAC 机制发起安装。用户本人处理系统提示；不能自动点击确认或设置安全例外。不要添加 `-ExecutionPolicy Bypass` 或关闭防护来让命令通过。

不要同时启动多个安装器，也不要在第一次仍运行或结果不明时重试。安装失败先保存状态；没有新的诊断依据不重复安装。

## 4. 只读核对与人工验收

```powershell
powershell.exe -NoProfile -File scripts/Invoke-CompatibilityWorkflow.ps1 -Action Verify -WorkDirectory "$workDirectory"
```

如果实际客户端目录不同，可加 `-InstalledDirectory` 指向需要只读核对的目录。此参数只是验证路径，不改变安装目的地。五个核心文件的预期哈希来自本版本证据；不同版本不能按本版本核对后宣称成功。

安装器退出成功不代表用户功能已经通过。允许运行后打开主界面，按用户实际设备填写如下验收表，并注明「用户确认」「脚本校验」或「尚无证据」。本 Skill 不自动记录用户桌面、账号窗口或剪贴板。

| 检查 | 如何验证 | 结果 |
| --- | --- | --- |
| 原包与兼容副本 | 完整哈希、差异、原文件保持不变 | 待填写 |
| 原包签名 / 安装后核心签名 | Windows 验证；兼容副本本身预期失去原签名有效性 | 待填写 |
| 安装完成 | 退出状态、实际落地组件与安装登记分别核对 | 待填写 |
| 机型门槛 | 是否仍被机型拒绝，结合原拒绝路径证据判断；只证明安装成功时保留因果缺口 | 待填写 |
| 客户端启动 | 主界面实际可进入，不以文件存在代替启动验收 | 待填写 |
| 服务与任务 | 检查成功与否、状态、版本分别记录 | 待填写 |
| 本人账号重登 | 用户自行退出、重新登录并确认 | 待填写 |
| 手机投屏与鼠标 | 用户确认画面、交互 | 待填写 |
| 电脑 → 手机文件 | 经用户同意发送无敏感测试文件，手机确认收到 | 待填写 |
| 手机 → 电脑文件 | 用户选择无敏感测试文件，电脑确认收到 | 待填写 |
| 双向剪贴板 | 用户用两个不同测试字符串逐向验证 | 待填写 |
| 平板键鼠共享 / 电视投屏 | 有设备且在用户测试范围时分别验收 | 未测试，除非确有证据 |
| 更新 | 分清版本查询、下载、安装，不合并推断 | 未测试，除非确有证据 |

## 退出与交付

将本地报告和结果交给用户，说明哪些操作已执行、哪些需要用户配合、哪些被系统阻止。不要请求密码、验证码、账号令牌或全量日志；不要自动上传任何诊断文件。若需清理大体积兼容副本，先确认用户不再需要，并只清理该任务明确创建的文件。
