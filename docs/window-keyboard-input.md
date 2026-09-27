# 窗口键盘输入

`window-input` 支持 `text`、`key`，使用 XTest 发送实际键盘事件。
不通过 SKILL 赋值，不执行输入文本，也不自动重放失败请求。

```bash
virtuoso-bridge window-input 0x123 --expect-title 'Exact window title' --action text --text='net_A<3>' --dry-run
virtuoso-bridge window-input 0x123 --expect-title 'Exact window title' --action text --text='net_A<3>' --allow-live
virtuoso-bridge window-input 0x123 --expect-title 'Exact window title' --action key --key Ctrl+A --allow-live
virtuoso-bridge window-input 0x123 --expect-title 'Exact window title' --action key --key Tab --allow-live
```

- 先从 `list-windows` 获取当前 child ID，点击所需输入框，再发送键盘操作。
- 键盘操作要求完整标题精确匹配，焦点已处于目标窗口或其子窗口中；不会抢焦点。
  窗口内具体输入框仍由调用方通过点击和截图确认，窗口焦点检查不等于字段身份检查。
- 每次请求重新发现窗口、检查映射状态及身份；每个字符/组合键前检查焦点和键盘状态。
- `text` 接受 1–256 个可打印 ASCII 字符；不接受换行、Tab、中文或控制字符。
  不使用剪贴板或修改全局键盘映射。当前布局不能表达的字符在发送前整批拒绝。
- `key` 接受 Tab、Enter/Return、Esc/Escape、Backspace、Delete、方向键、Home、End、Space、
  单个字母/数字；可加 Ctrl、Shift、Alt，例如 `Shift+Tab`、`Ctrl+A`、`Ctrl+C`、`Ctrl+V`。
  字母按键名称不区分大小写；需要大写字符时用 `text` 或 `Shift+A`。
- 键盘操作不接受鼠标坐标。检测到按键被按住、CapsLock 或其他活动修饰键时拒绝；NumLock 除外。
- `--dry-run` 检查窗口、焦点、键盘状态及字符映射，但不发送事件，也不移动焦点。
- 失败时尽力释放本次注入的键；部分发送或传输结果不明时报告 `completion=unknown`。
  `retry_safe=false` 表示调用方不得自动重放，需先读取界面状态。
- `sent`/`events_sent` 只证明发送；`verified` 是窗口后置条件结果，不证明应用接受了文本。
  应通过表单读回、截图或应用日志确认效果。焦点检查不能完全消除并发用户操作的竞态，
  自动输入期间应串行使用同一桌面。

该功能按需上传 X11 辅助脚本，不要求重启 Virtuoso 或 Bridge daemon。
