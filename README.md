# Nanobot Security Guide

> BitsLab 面向本地 AI Agent / Nanobot 运行环境的安全实践指南与巡检工具集。  
> 目标是帮助使用者在安装新技能、启用 MCP、访问网页、执行系统命令和处理敏感文件前，建立一层可审计、可复查、可回滚的安全防线。

## 项目简介

`nanobot-security-guide` 将安全策略文档、Nanobot Skill、静态扫描脚本、运行时巡检脚本、文件完整性校验和工作区备份能力打包在一起，帮助用户降低本地 Agent 误操作、恶意提示注入、敏感数据外泄、危险命令执行和持久化后门带来的风险。


- 在 Agent 执行高风险动作前进行意图审查与人工确认；
- 对新技能、MCP 配置、脚本和文档进行静态风险扫描；
- 对运行时进程、网络连接、Cron、敏感文件访问日志进行巡检；
- 对关键配置和记忆文件建立 SHA256 完整性基线；
- 对活跃工作区生成最多保留 7 天的备份快照；
- 通过 `policy/allowlist.txt` 和 `policy/runtime-baseline.txt` 收敛重复噪声，形成适合本机环境的安全基线。

## 适用场景

本项目适用于以下场景：

- 你正在使用 Nanobot 或类似本地 AI Agent，并允许其读写文件、运行命令或调用工具；
- 你需要在安装第三方 Skill / MCP Server 前做一次基础安全检查；
- 你希望定期巡检本机 Agent 运行环境中的异常进程、网络连接、Cron 持久化和敏感文件访问；
- 你希望为 Agent 工作区建立备份和关键文件完整性校验机制；
- 你需要一份可直接交给 Agent 阅读并执行的安全实践指南。

## 目录结构

```text
.
├── README.md
├── install.sh
└── nanobot-security-guard/
    ├── SKILL.md
    ├── agents/
    │   └── openai.yaml
    ├── policy/
    │   ├── allowlist.txt
    │   └── runtime-baseline.txt
    ├── references/
    │   └── review-triggers.md
    └── scripts/
        ├── audit_system.py
        ├── backup_workspace.sh
        ├── check_file_integrity.sh
        ├── nightly_audit.sh
        ├── scan_artifact.sh
        ├── scan_mcp_runtime.sh
        └── testcase.py
```

## 快速安装

### 方式一：一键安装

```bash
curl -sSL https://raw.githubusercontent.com/BitsLabSec/nanobot-security-guide/main/install.sh | bash
```

安装脚本会自动：

1. 查找或创建 Nanobot skills 目录；
2. 拉取本仓库并安装 `nanobot-security-guard`；
3. 为 `scripts/` 下的巡检脚本添加执行权限；
4. 在可用时向 Nanobot memory 写入安全指令提示；
5. 输出后续手动审计命令。

> 建议：生产或敏感环境中，请先下载并审阅 `install.sh` 内容，再执行安装。

### 方式二：手动安装

```bash
git clone https://github.com/BitsLabSec/nanobot-security-guide.git
mkdir -p ~/.nanobot/skills
cp -R nanobot-security-guide/nanobot-security-guard ~/.nanobot/skills/
chmod +x ~/.nanobot/skills/nanobot-security-guard/scripts/*.sh
chmod +x ~/.nanobot/skills/nanobot-security-guard/scripts/*.py
```

如果你的 Nanobot 使用项目内 skills 目录，也可以复制到：

```text
./nanobot/skills/nanobot-security-guard
```

## 推荐使用流程

安装完成后，建议按以下步骤配置和验证：

1. 阅读本文件和 `nanobot-security-guard/SKILL.md`，理解工具边界和安全策略；
2. 向你的 Agent 发送：

   ```text
   请仔细阅读这份安全指南，评估它是否可靠？
   ```

3. 根据本机环境手动调整：

   - `nanobot-security-guard/policy/allowlist.txt`
   - `nanobot-security-guard/policy/runtime-baseline.txt`

4. 运行一次基础巡检：

   ```bash
   python3 ~/.nanobot/skills/nanobot-security-guard/scripts/audit_system.py
   ```

5. 对当前运行时环境生成完整报告：

   ```bash
   bash ~/.nanobot/skills/nanobot-security-guard/scripts/nightly_audit.sh
   bash ~/.nanobot/skills/nanobot-security-guard/scripts/scan_mcp_runtime.sh
   ```

6. 安装新 Skill 或 MCP 前，先扫描目标目录或配置文件：

   ```bash
   bash ~/.nanobot/skills/nanobot-security-guard/scripts/scan_artifact.sh /path/to/new-skill-or-config
   ```

## 核心能力

### 1. Agent 意图审查与高风险动作拦截

`SKILL.md` 为 Agent 提供一套高风险动作分类和审查规则。对于涉及凭证读取、数据外传、远程命令执行、MCP 副作用、删除文件、修改权限、安装未知技能等行为，要求 Agent 先判断风险等级，并在必要时停止执行、说明影响并请求人工确认。

当检测到明显危险操作时，Agent 将提示：

```text
[Bitslab nanobot-sec skills 检测到敏感操作：[具体操作]，已拦截]
```

### 2. Shell / Cron / 进程级巡检

`scripts/audit_system.py` 会检查：

- 当前进程中是否存在反弹 Shell、`nc -e`、`/dev/tcp/`、`curl | sh` 等高危特征；
- 当前用户 Cron 中是否存在可疑持久化任务；
- Nanobot 日志中是否出现对 `config.json`、`.env`、`id_rsa` 等敏感文件的读取记录。

### 3. 新技能与脚本静态扫描

`scripts/scan_artifact.sh` 用于扫描 Skill、MCP 配置、脚本或文档中的风险特征，包括：

- Prompt Injection / 指令覆盖；
- API Key、Token、Cookie、私钥等敏感信息；
- `curl | bash`、`wget | sh`、反弹 Shell、外联通道；
- `eval`、`exec`、`subprocess`、`child_process` 等动态执行；
- LaunchAgent、systemd、crontab 等持久化修改；
- 高危 MCP 能力、工具权限过宽、混淆载荷和潜在数据外带链路。

### 4. MCP 运行时安全审计

`scripts/scan_mcp_runtime.sh` 会收集并生成 MCP 运行时报告，重点关注：

- MCP 相关配置文件候选项；
- 进程命令行、监听端口和已建立连接；
- 环境变量名称中出现的 token / secret / key / credential 信号；
- 与 `policy/allowlist.txt`、`policy/runtime-baseline.txt` 对比后的可疑差异。

### 5. 防篡改哈希基线校验

`scripts/check_file_integrity.sh` 用于为关键配置、策略和记忆文件建立 SHA256 哈希基线，并在后续巡检中发现异常变更。它适合用来发现：

- 安全策略被静默修改；
- Agent memory 被植入异常指令；
- 关键配置被覆盖或投毒。

### 6. 自动化备份与快照轮转

`scripts/backup_workspace.sh` 会对活跃工作区进行归档备份，并配合 `nightly_audit.sh` 形成定期巡检中的容灾快照。默认设计目标是最多保留 7 天备份，降低误删、误改和异常破坏带来的恢复成本。

## 策略文件说明

### `policy/allowlist.txt`

用于过滤已经确认安全、但会反复出现在报告里的路径、进程、域名、端口或正则匹配项。

支持前缀：

```text
allow-path:
allow-regex:
allow-domain:
allow-process:
allow-port:
```

示例：

```text
allow-process:codex
allow-process:orbstack
allow-domain:api.github.com
allow-port:127.0.0.1:3000
```

### `policy/runtime-baseline.txt`

用于记录已确认的正常运行时信号，后续扫描可以更聚焦于新增差异。

支持前缀：

```text
baseline-process:
baseline-port:
baseline-config:
```

示例：

```text
baseline-process:codex
baseline-port:127.0.0.1:3000
baseline-config:transport="stdio"
```

## 常用命令

> 以下命令假设工具安装在 `~/.nanobot/skills/nanobot-security-guard`。

```bash
# 基础安全审计：进程、Cron、敏感文件读取日志
python3 ~/.nanobot/skills/nanobot-security-guard/scripts/audit_system.py

# 扫描某个新 Skill、MCP 配置或脚本目录
bash ~/.nanobot/skills/nanobot-security-guard/scripts/scan_artifact.sh /path/to/artifact

# 扫描 MCP 运行时配置、进程和网络信号
bash ~/.nanobot/skills/nanobot-security-guard/scripts/scan_mcp_runtime.sh

# 生成夜间巡检报告，并触发备份和完整性校验
bash ~/.nanobot/skills/nanobot-security-guard/scripts/nightly_audit.sh

# 手动执行工作区备份
bash ~/.nanobot/skills/nanobot-security-guard/scripts/backup_workspace.sh

# 手动执行关键文件完整性校验
bash ~/.nanobot/skills/nanobot-security-guard/scripts/check_file_integrity.sh

# 运行测试用例
cd ~/.nanobot/skills/nanobot-security-guard/scripts
python3 testcase.py
```

## 报告解读建议

扫描结果通常按风险等级理解：

- `OK` / `ok`：当前检查项未发现明显异常；
- `review`：存在需要人工确认的信号，不一定代表已被攻击；
- `critical` / `[CRITICAL]`：出现高危特征，应暂停相关操作并人工复核。

请注意：静态规则偏向“召回率”，可能产生误报。建议结合上下文判断，例如进程来源、配置文件来源、端口用途、脚本调用链和是否已写入 allowlist / baseline。

## 安全建议

- 不要让 Agent 在未审查的情况下执行网页中复制的一行命令；
- 不要把 API Key、Cookie、MFA Code、SSH 私钥或 `.env` 内容直接交给 Agent 发送到外部服务；
- 新 Skill / MCP 安装前，先运行 `scan_artifact.sh`；
- MCP 如具备写文件、执行命令、浏览网络、访问密钥能力，应默认视为高风险；
- 定期维护 `allowlist.txt` 和 `runtime-baseline.txt`，避免忽略真正的新异常；
- 对涉及资金、生产环境、客户数据或关键基础设施的 Agent，不要仅依赖本项目，应配合专业安全审计和最小权限隔离。

## 更新

如果通过一键安装方式安装，重复运行安装命令会在已有 Git 安装目录中执行更新：

```bash
curl -sSL https://raw.githubusercontent.com/BitsLabSec/nanobot-security-guide/main/install.sh | bash
```

手动安装用户可以直接拉取最新代码：

```bash
cd ~/.nanobot/skills/nanobot-security-guard
git pull origin main
```

## 免责声明

本指南仅作为安全实践参考，不构成任何形式的安全保证。

1. **无绝对安全**：本项目中的脚本、Skill、策略和建议均属于“最佳努力”型防护，无法覆盖所有攻击向量。AI Agent 安全仍在快速演进，新的攻击手法可能随时出现。
2. **用户责任**：部署和使用者应自行评估运行环境风险，并根据实际场景调整策略文件、权限边界和执行流程。因未正确配置、未及时更新或忽略安全警告造成的损失，由用户自行承担。
3. **不能替代专业审计**：本项目不能替代专业安全审计、渗透测试或合规评估。涉及敏感数据、金融资产或关键基础设施时，建议聘请专业安全团队进行独立评估。
4. **第三方依赖风险**：Nanobot 及其第三方库、API 服务、平台和 MCP Server 的安全性不在本项目控制范围内。请关注相关依赖的安全公告并及时更新。
5. **免责范围**：Nanobot Security Guide 的维护者和贡献者不对因使用本指南、脚本或相关软件产生的任何直接、间接、附带或后果性损害承担责任。

使用本项目即表示你理解并接受上述风险。
