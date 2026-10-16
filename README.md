# 小米电脑管家兼容 Skill

把一次已经完成的兼容安装整理为可重复、可核验的 agent 操作流程。用户提供官方 EXE，Skill 校验样本、生成安装器兼容副本、记录安装前状态，并在获得安装授权后执行安装和验收。

**当前仅支持小米电脑管家 5.8.1.130 的一个精确构建。** 这是社区工具，与小米无隶属关系。仓库不包含小米安装包、程序、驱动、账号资料或原始运行日志。

Portable agent instructions and deterministic helpers for one verified Xiaomi PC Manager installer build. Local Windows execution is required for installation. No proprietary binaries are distributed.

## 能做什么

| 步骤 | 自动化程度 |
| --- | --- |
| 识别支持的原始安装包 | 完整 SHA-256、大小、指令校验；不凭文件名猜测 |
| 生成兼容副本 | 原文件不变，检查新文件 SHA-256 和全部字节差异 |
| 安装前检查 | 留存相关组件、服务、驱动、任务与空间的本地基线 |
| 安装 | 当前用户允许后执行；UAC 或系统安全提示由本人处理 |
| 安装后核对 | 核对五个原版核心文件及 Windows 上的签名/服务状态 |
| 功能验收 | agent 引导，用户登录真实账号并配合手机确认 |

修改发生在**安装器文件**，只改变静默安装中的机型资格分支。安装之后使用原版客户端核心组件。它不是常驻注入工具，也不模拟账号登录。

## 支持范围

| 项目 | 要求 |
| --- | --- |
| 安装包版本 | 5.8.1.130 |
| 大小 | 766,644,624 字节 |
| 原始 SHA-256 | `d812cf30805d172474eb33b2f97f37129593f9d50f09d4224f73d530a2cb40e9` |
| 兼容副本 SHA-256 | `a7d35102dc1abdb5e8a5e45ba43c6a6b22f5b30cd9c456799a5bfea65f210e34` |
| 工具 | Python 3.10+（仅标准库）；安装阶段需 64 位 Windows 与 64 位 PowerShell 5.1+ |
| 输出位置 | 本地普通目录，建议 NTFS；拒绝符号链接/目录联接和已有文件覆盖 |
| agent | 支持 Skill 文件或能遵循本地 `SKILL.md`，并具备本地文件/命令能力 |

校验不通过会停止；不能用改文件名、关校验或直接套偏移的方式支持另一个构建。修改会使安装器原有 Authenticode 签名失效。不要关闭系统防护；系统若拒绝执行，应停止并报告。

## 安装 Skill

当前版本为 `0.1.0`。项目仓库：[WildFrogWorks/xiaomi-pc-manager-skill](https://github.com/WildFrogWorks/xiaomi-pc-manager-skill)。

**从 GitHub 安装：**将下面的请求复制给支持 GitHub Skill 安装、具备本地文件和命令能力的 agent：

> 请从 https://github.com/WildFrogWorks/xiaomi-pc-manager-skill 安装 Skill。Skill 位于仓库根目录，路径为 `.`，技能名称为 `xiaomi-pc-manager-compat-skill`。保留完整目录中的脚本、版本清单和引用说明，阅读 `SKILL.md` 后按当前 agent 的要求完成加载。本次只安装 Skill，不运行小米安装器或小米程序；后续由我提供官方 EXE 和工作目录，再开始识别和准备。

不同 agent 的技能安装命令和加载方式可能不同；如果不支持直接从 GitHub 安装，可以下载该仓库 ZIP 或克隆仓库，再按下面的本地方式使用。安装 Skill 本身不等于授权安装小米软件。

**从本地包使用：**解压后将整个 `xiaomi-pc-manager-compat-skill` 文件夹交给 agent，告诉它先阅读其中的 `SKILL.md`。若 agent 支持技能目录，也可以将这个完整文件夹放到它所配置的技能目录，按该产品要求重新加载。不要只复制 `SKILL.md`，脚本、版本清单和引用说明需要一同保留。

给支持本地 Skill 的 agent 的示例请求：

> 使用本地的 xiaomi-pc-manager-compat-skill。安装包在我提供的路径，输出到我指定的工作目录。先完成识别和兼容副本校验，报告安装将改变哪些组件；准备阶段不要运行小米程序。

准备完成后，如确实要安装：

> 允许在当前电脑安装并运行验证。使用刚才校验过的副本；账号由我本人登录。请继续核对核心组件，并引导我测试手机投屏、双向互传和双向剪贴板。

## 使用与验证

- [SKILL.md](SKILL.md)：agent 执行入口。
- [操作说明](references/workflow.md)：参数化命令、只读检查与安装步骤。
- [版本证据](references/compatibility-evidence.md)：究竟修改了什么，以及哪些功能实际验证过。
- [恢复与更新](references/recovery-and-updates.md)：服务等待、卸载边界、新版本适配要求。
- [测试说明](tests/README.md)：不执行小米程序的脚本测试。

已在一台原先安装过小米服务的非小米 Windows 11 主机上验证：本人账号退出后重新登录、手机投屏和鼠标控制、双向文件互传、双向剪贴板。未完成干净系统、多机型、平板键鼠共享、电视投屏、完整虚拟音视频、长期会话和新版自动升级验证。安装会涉及服务和虚拟驱动；基线记录不是完整系统回滚。

## 维护与发布

本仓库仅发布原创脚本、说明和精简的版本校验资料；MIT 许可不授予任何小米软件的权利。新增版本应独立分析和验收，再增加精确的版本支持。提交问题时仅提供去除个人信息的版本、哈希、错误类别与必要状态，勿上传安装包、账号数据、序列号或完整日志。
