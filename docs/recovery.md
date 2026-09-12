# 授权自动恢复

恢复执行器不会重放原请求。恢复结果分别报告 `transport_available`、`admission_allowed`
和 `workflow_resume_allowed`；原 `timed_out_unknown` 保持不变。恢复记录、授权及监控状态
保存在指定工作区的 `tmp/virtuoso_bridge/recovery/<profile>/`，不进入 Git。

## 动作和默认值

| 动作 | 默认 | 条件 |
|---|---|---|
| `connect` | 允许 | 只恢复原配置的隧道，不 staging |
| `proven_read_only` | 允许 | 两次稳定的完整终态证明，同身份健康检查 |
| `proven_not_dispatched` | 允许 | 精确匹配的 `pre_dispatch_proof`，证明未送入 CIW |
| `proven_mutating` | 关闭 | 单独授权；仅解除通道隔离，业务仍暂停 |
| `daemon_restart` | 关闭 | 单独授权且显式触发；空闲、独占、固定已部署版本 |
| `daemon_relaunch` | 关闭 | 单独授权；旧 daemon 确实退出、原 CIW 存活、无未知工作 |

生命周期入口需要激活支持 `recovery_mailbox_version=1` 的 SKILL。
第一版的重新启动仅支持 GUI 和 daemon 在同一主机的 Linux 拓扑；控制端支持 Windows。
控制平面使用目标主机的 Python 3，通过 stdin 传入固定的控制程序，避免 EDA 启动脚本重解析 `-c`。

授权绑定当前工作区、profile、配置、CIW 启动身份、DISPLAY、daemon epoch 和部署摘要，
最长 8 小时。自身恢复且验证通过的新 epoch 可以继承剩余授权；外部换代或更换部署不能继承。
普通受保护重启会保存验证回执，恢复器只认可请求 ID、摘要和原 epoch 匹配的生命周期记录。
历史未知业务请求、缺少回执的旧重启记录仍会阻止自动重建，不能仅因现在健康而忽略。

## CLI

以下每条命令都要指定 `--workspace <绝对工作区路径> -p <profile>`；可加 `--json` 获取外层 envelope。

```text
recovery policy status
recovery policy grant --actions connect,proven_read_only,proven_not_dispatched,daemon_relaunch --hours 8 --reason "允许本会话恢复已退出的 daemon"
recovery policy revoke
recovery inspect
recovery run --timeout 60
recovery run --action daemon_restart --timeout 60
recovery watch --interval 10 --timeout 60
recovery stop
```

`grant` 创建授权本身不执行恢复，也不启动监控。动作列表替换此前授权；如需保留默认动作，
请将它们一并列出。`revoke` 立即写入本地撤销记录，并使目标 CIW 尚未执行的意图失效；
已经发出的动作仍继续收集回执。撤销记录不会被旧执行器的授权写回覆盖。

`run` 默认预算 60 秒，最大 60 秒。诊断和建连各最多尝试 3 次，失败后等待 1、2 秒；
身份、配置、认证和主机密钥错误不重试。生命周期每次事故至多发出一次，
15 分钟内两次失败后停止重建。所有 SSH 子步骤共用本次恢复的剩余预算。

监控正常时每 10 秒读取进程和账本，不发送 CIW eval；连续 3 次异常才调用相同执行器。
没有本工作区 quarantine 时，也识别账本中的 `timed_out_pending` 和 `late_waiting_operator`，
分别报告待完成和需要处理的请求；正常运行中的请求通过 `activity=running` 区分。
此类阻塞仅收集状态并提示原请求待处理，不因它自动发送新的业务请求或重启动作。
同一故障被拒绝或结果未知后，等待故障、授权或 epoch 变化再尝试；也可以显式 `run`。
只在结果有变化时写 `notice.json` 和 `watch.log`，不发送外部消息。
`stop` 停止监控，正在验证的恢复不伪装成已取消；需要同时撤销权限时另执行 `policy revoke`。

## 证明、意图和人工出口

隔离解除采用先保存原始隔离 JSON、再删除隔离文件的顺序。证明或存储出错时保留隔离。
旧请求已有完整证明但 daemon 已退出时，只有同时拥有证明动作和 `daemon_relaunch` 权限，
才能先恢复固定版本，再复核原证明及新身份；不会将新会话健康当作旧请求完成证明。

`pending.json` 在生命周期动作发出前持久化。执行器退出或回执丢失后，下一次 `run`
只观察同一意图；不会再次发出启动命令。目标主机另有每个 CIW 的原子 claim，阻止其他
工作区重复恢复同一个会话。未解决的意图会阻止项目包装层继续提交 eval/load 等业务请求。

人工检查会话和原任务、确认当前 epoch 后，可以明确承认尚未确认的生命周期结果：

```text
recovery resolve --recovery-id <pending 中的 ID> --expected-epoch <当前 epoch> --reason "人工检查结论" --acknowledge-unknown
```

该入口撤销旧授权，要求匹配的空闲 CIW；尚未过期的目标意图不能释放。它归档人工决定，
不改写原结果、不重放请求，也不解除另一个业务请求的隔离。业务未知结果仍使用项目现有的
`reconcile/recover/resume-session` 出口。CIW 更换或还有其他未知工作时继续拒绝。

本功能不终止 Virtuoso，不保存或丢弃用户 cellView，不点击任意弹窗。
PID 存在但心跳失效、CIW 被阻塞时停止并保留证据。健康检查不证明版图、PDK DRC/LVS 或业务步骤正确。
