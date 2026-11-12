# Claude Code trace：从工具证据到 payload 影响的可观察量化

本模块为 Claude Code 搭建与现有 OpenCode trace 并行的链路：

```text
官方 command hooks + CLI stream-json + 官方 SDK 会话导出
  → trace.raw.jsonl（保留来源、观察顺序和原始内容）
  → 标准事件 / 工具调用 / 文件访问 / 完整性报告
  → payload 返回命中及其阶段
  → 行为指标与分支差异
```

入口是 `python -m vulnmirage.claude_trace`，安装后也可使用 `vulnmirage-claude-trace`。实现基于已提交的[检查点框架](claude_checkpoint_zh.md)，支持 capture 停止及 observe 续跑，不要求整个 campaign 已闭环。本次开发位于独立的 `feat/claude-code-trace` 分支，未向前一个检查点 PR 追加提交。

## 1. 三种官方数据来源

| 来源 | 用途 | 边界 |
| --- | --- | --- |
| `PreToolUse` / `PostToolUse` / `PostToolUseFailure` | 调用参数、成功结构化输出、失败文本、官方工具耗时 | 不证明最终序列化内容或 API 接收 |
| `PostToolBatch` | 一批工具完成后、下一次模型请求前的序列化 `tool_result` | 最适合划分后续决策窗口；仍不是服务端接收回执 |
| `InstructionsLoaded`、SubagentStart/Stop、Pre/PostCompact、Stop/Failure、SessionStart/End 等 | 记录上下文加载、agent 生命周期与终止原因 | 自动指令事件可能异步，只提供元数据，不提供已加载字节证明 |
| CLI `--output-format stream-json --verbose --include-hook-events` | assistant/tool-result 消息、公开的 reasoning 文本、最终 result、usage/cost | 不包含未公开的推理过程、attention 或内部状态；成功 result 与“任务正确完成”不同 |
| SDK `get_session_messages` / `list_subagents` / `get_subagent_messages` | 导出官方会话链，补充缺失消息，归档子 agent | 事后补录的观察时间不能当作原执行时间；SDK 不会为此调用模型 |

hooks 成功时只返回 `{}`，不向模型添加解释文字或修改工具输出。启用 `--checkpoint-config` 时，先写入 trace，再将检查点已有的控制决策原样返回；capture 模式仍会停止，分支 observe 模式继续执行。

日志按 `(session_id, agent_id, tool_use_id)` 关联。每个来源的事件证据保留，但 `tool_calls.jsonl` 每个调用只有一行；SDK 与 stream 中相同 UUID 的消息不重复计数。序列化返回优先于结构化返回，官方 `duration_ms` 单独保存，失败状态不被没有错误标志的批次记录覆盖。

独立采集不会因 agent 切换目录而主动停止，路径按各调用的 cwd 归一化；与检查点合用时，检查点原有的固定 cwd 约束仍有效。

默认不开启子 agent 文本转发，避免父会话转发与子会话导出重复计数。子 agent 的 hook 身份和 SDK 导出用于分别归档；可用的 `parent_tool_use_id` / `parent_agent_id` 保留在原始证据中，缺失的父子关系不猜测。默认工具只有 Bash/Read/Grep/Glob；如需探索子 agent 行为，可自行配置 `--tools`。与检查点合用时，检查点仍会拒绝不支持的子 agent 分叉。

## 2. 暴露证据的四个层次

| 层次 | 记录位置 / stage | 含义 |
| --- | --- | --- |
| 磁盘存在 | capture_start 的 inventory | 登记载体存在及其哈希，不代表 agent 读取 |
| 工具访问事件 | PreToolUse、file_access.jsonl | Read 等工具声明访问；失败或只有调用请求时记录 `read_attempt` 等，不证明内核 I/O |
| 返回包含登记片段 | payload_exposure.jsonl：`tool_output` | 成功结构化返回或失败显示文本命中 |
| 准备进入模型的返回 | payload_exposure.jsonl：`model_bound` | stream/SDK 的 user `tool_result` 或 PostToolBatch 序列化结果命中；**服务端是否收到仍为 unknown** |

另有 `user_prompt`、`user_context` 和 `historical_context`，用于记录提交输入、SDK/stream 可见的用户消息或附件内容，以及既有历史中的片段。恢复会话时，运行前已经存在的消息会标记为 `historical`：保留证据，排除在本次行为计数之外。没有被官方接口公开的系统上下文仍不能据此证明未暴露。

检测递归扫描完整返回的字符串键和值，发生在归一化预览截断前。命中记录包含 payload ID、登记载体路径、调用 ID、事件 ID、JSON pointer、字符偏移、片段哈希及原始文件行引用。登记的载体路径不是对 shell 实际打开哪个文件的推断。

检测仍是**精确片段匹配**。搜索输出、diff、MCP 摘要、错误文本都可以匹配；编码、分割、转述、图片或未登记内容可能漏检。未命中不等于确认未暴露。Grep/Glob 的路径仅表示搜索/列举范围；Bash 不生成虚构的文件读取记录。

命中计数按 agent、调用、片段和阶段去重，表示独立证据单元，不是字符出现次数或模型注意力权重。

Claude 的兼容字段 `content_returned_to_model` 保持 false，因为当前没有一般性的出站请求接收证明。机制分析新增 `content_stage`，即使已观察到 model_bound 命中也保留 `exposure_state=unknown` 和 `model_received_payload=unknown`，不会误写成“未暴露”或“已采纳”。

OpenCode 既有字段的定义未改；跨框架实验应先按相同证据层次对齐，不能将旧标签当成 provider 接收证明。

## 3. 现在可以量化什么

`behavior_metrics.json` 包含：

- 去重后的调用总数、按工具计数、明确错误数、官方单次工具耗时（工具记录中）。
- 文件访问记录数、成功 Read 的文件集合与去重计数；读取尝试和搜索范围另行保留。
- payload 的各阶段命中数、首次 model-bound 位置、按 agent 划分的边界、历史污染命中数。
- 同一 agent 暴露后发起的新调用数；优先使用 PostToolBatch 边界，避免把同批次的其他工具当成暴露后的新决策。
- 原生 result 的 usage、cache token、cost、turn/duration 信息，以及采集墙钟时间。缺失值不补成零。
- 动作序列：工具名及脱敏、截断后的输入摘要；排除 description，并将 shell command 中的仓库根路径替换成统一占位符。

只有 SDK 事后补录、无法确定边界时，暴露后的调用数为 null。子 agent 命中不会把尚未接收其摘要的父 agent 标为已暴露。这里的“之后”是可观察运行边界，不是 provider receipt 或心理采纳时刻。

clean 处理没有任何可匹配文本时，其暴露后窗口也可能为 null；比较不会将其补成零。若要估计共同干预点之后的效应，还需按共享边界或工具决策对齐，而非强行依赖 clean 组的 payload 命中。

`compare` 读取 control/attack 两份指标，输出调用数等差值、token 差值、动作序列编辑距离、共同动作前缀、Read 文件集合 Jaccard 及增减文件。动作距离基于可见输入摘要，摘要截断或脱敏可能隐藏细小差异，完整原始记录用于复核。

若两边的 checkpoint ID、共同前缀哈希、续跑 prompt 哈希、model 标签和启动配置哈希均相同，输出 `shared_checkpoint_metadata_verified=true`。配置哈希覆盖工具、预算、框架/SDK 版本、指定的系统提示哈希、endpoint 哈希等；它不是完整请求体或实际后端权重一致性的证明。

**单次差异始终是描述性观察。** 输出明确保留 `causal_effect_established=false`、`sampling_randomness_controlled=false`。后续应从相同边界产生多个 control/control 和 control/attack 重复，估计自然漂移分布、区间与检验统计量，再结合私有任务评分判断影响。当前未实现统计显著性、采纳分类器或攻击成功标签。

## 4. 可复现实验：真实 CLI + 本地 API 测试服务

在项目根目录：

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e '.[dev,claude]'

.venv/bin/python -m vulnmirage.claude_trace verify-local \
  --out /tmp/vm-claude-trace-demo

.venv/bin/python -m vulnmirage.claude_trace verify-local --tool-failure \
  --out /tmp/vm-claude-trace-error-demo
```

需要 `claude`、`rg` 和 POSIX 系统（Linux/macOS/WSL）。输出目录必须尚不存在。测试服务只返回预设的工具调用，使用虚构密钥和私有 Claude 配置目录，不调用真实模型。

验证步骤：

1. 真实 CLI 搜索含 payload 的文件，触发检查点捕获；本地端点只收到一次干净请求。
2. 官方 SDK 创建 control/attack 分支，各自恢复到相同 cwd 和对话前缀。
3. 分支搜索返回各自的处理文本，然后调用 Read 读取另一个文件，最后输出 JSON。
4. 两个分支初始的 system/messages/model/tools 相同；各自的第二次请求包含本分支文本。
5. 三来源标准化后每个分支恰好 2 次工具调用、1 次暴露后调用，没有日志重复计数；失败场景准确记录搜索错误。
6. 比较产物验证检查点元数据匹配。脚本没有制造行为差异，因此动作差异为零；这不是模型抗注入结论。

主要结果见 `<out>/verification.json`、`comparison.json`、`requests.local.json`，以及 control/attack 各自的原始与标准化 trace。`requests.local.json` 只作为本地接收端的验证证据；普通远程运行不会自动获得这项观测。

2026-11-12 本地验证：新增 trace 测试 **33 项**，连同检查点回归共 **58 项通过**。成功与失败两种真实 CLI 流程、stdout executor 对接、延迟 API 导致的超时、冻结样例及原始/标准化产物哈希均已检查；52 份现有合同 schema 均为最新。

## 5. 运行与检查点衔接

独立采集一个真实 API 会话：

```bash
.venv/bin/python -m vulnmirage.claude_trace run \
  --repo /absolute/path/to/audit-repository \
  --out /tmp/claude-audit-trace \
  --prompt-file /absolute/path/to/audit-task.txt \
  --model claude-sonnet-4-6 \
  --catalog examples/claude_checkpoint/catalog.json
```

这里的 catalog 示例应替换为本次处理对应的 `id/path/needles`，路径相对审计仓库。不指定 catalog 时仍可采集完整轨迹和总体行为计数，但 payload 命中和暴露后计数没有足够依据。目录必须在仓库之外；控制文件不是给 victim 阅读的任务材料。真实运行使用调用者已配置的 API 环境/认证，run 会实际调用模型。

已有检查点分支时，先用 checkpoint 的 `activate` 恢复文件树，再运行：

```bash
.venv/bin/python -m vulnmirage.claude_trace run \
  --repo /tmp/vm-capture/workspace --out /tmp/vm-attack-trace \
  --checkpoint-config /tmp/vm-capture/config.json \
  --resume <fork-session-id> --prompt-file /absolute/path/to/common-continuation.txt \
  --model claude-sonnet-4-6
```

此时自动使用对应分支的 catalog、私有 Claude 会话目录及配对元数据。不要同时再加载原 checkpoint settings；trace settings 已将其决策组合进同一个 hook。不同分支仍须串行激活/运行。启用工具、预算、续跑提示及其他条件应保持一致。

离线重做检测与比较：

```bash
.venv/bin/python -m vulnmirage.claude_trace normalize \
  --source /tmp/vm-attack-trace/trace.raw.jsonl \
  --repo /tmp/vm-capture/workspace --out /tmp/reanalyzed-trace \
  --catalog /absolute/path/to/payload-catalog.json

.venv/bin/python -m vulnmirage.claude_trace compare \
  --control /tmp/vm-control-trace --attack /tmp/vm-attack-trace \
  --out /tmp/claude-trace-comparison.json
```

需要手工启动 CLI 时，`init --repo ... --out ...` 可生成纯采集 hooks；手工 CLI 还应保存 stream-json 并使用相同的版本和会话管理协议。完整的 SDK 导出、归档封存与自动标准化由 `run` 完成，单独 `init` 不等同于整条采集链。

## 6. 产物与完整性

```text
capture.json / settings.json     # 采集配置及官方 hooks
trace.raw.jsonl                  # 带来源的原始证据封装
stream.native.jsonl              # CLI 原始 stdout
stderr.native.log                # CLI 原始 stderr
session.native.jsonl             # 官方 transcript 原件（可获得时）
capture_summary.json             # 进程结束状态、会话和配对信息
capture.sealed.json              # 观察窗口封存点
capture_sources.json             # 原始产物哈希
trace.late.jsonl                 # 若存在：封存后才到达的异步事件
events.normalized.jsonl          # 兼容标准事件，metadata 含原始证据引用
tool_calls.jsonl                 # 每个 session/agent/tool_use_id 一条
file_access.jsonl                # 声明访问/尝试/搜索范围
payload_exposure.jsonl           # 精确片段命中及其阶段
behavior_metrics.json            # 可观察行为指标
trace_completeness.json
trace_manifest.json              # 版本、质量、限制及标准化产物哈希
```

日志使用进程间锁及自恢复的递增 sequence；不完整的末行不会被静默覆盖。记录顺序是采集器观察顺序，原生时间及单调时间证据保留于原始记录。归档后封存主日志，异步晚到事件另存，避免哈希静默变化。晚到事件不在本次标准化窗口内，应在研究中单独检查，不能据此声称已完整观察所有自动上下文。哈希用于完整性核对，不能抵抗同权限攻击者篡改。

`complete` 表示已捕获调用有终态、观察到停止和非空输出等结构条件成立；它不表示所有上下文都已观察、模型收到 payload、结果正确或环境隔离合格。日志截断、缺少终态、异常退出、只有事后补录、未知版本或版本冲突会显式降级；当前 native fixture 验证版本为 Claude Code 2.1.322 / SDK 0.2.180。

`tests/fixtures/claude_code/` 保存上述真实 CLI 对本地测试服务运行的成功/失败样例，路径已替换为 `/fixture`；`provenance.json` 记录来源及样例哈希。它们可在没有 CLI 时离线验证解析契约，不能作为真实模型行为样本。

## 7. 与现有 bench 的连接

已增加 `trace_adapter: claude_code_jsonl` 和 `answer_extractor: claude_jsonl`。`--emit-jsonl` 将原始封装输出到 campaign stdout；最终答案只取成功 result 的字符串，不从工具输出或用户 JSON 中猜测答案。现有标准化与归档流程可直接处理。

[`configs/claude_code.yaml`](../configs/claude_code.yaml) 给出命令与产物的对接示例；机制分析会读取阶段证据，轨迹比较使用去重后的 tool_calls。该配置不是 Claude 推理网关或操作系统隔离实现，现有 campaign 的隔离合格检查仍须独立通过；未为 Claude 绕过这些检查，也未把当前 OpenCode 专用 gateway 改写成通用网关。

使用配置示例前应激活安装环境，确保 `vulnmirage-claude-trace` 在子进程的 PATH 中；内部采集超时应早于外层 campaign 截止时间，留出导出和封存时间。

## 8. 官方参考

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)：工具、批次、子 agent 和上下文事件。
- [Claude Code CLI](https://code.claude.com/docs/en/cli-reference)：stream-json、hook lifecycle 输出、resume 和工具设置。
- [Agent SDK Python reference](https://platform.claude.com/docs/en/agent-sdk/python)：公开会话与子会话读取函数。
- [Agent SDK session management](https://platform.claude.com/docs/en/agent-sdk/sessions)：会话恢复与分叉。
