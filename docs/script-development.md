# SKILL 脚本开发

## 读取现场及核对执行目标

```text
virtuoso-bridge context -p v231 --limit 50 --output context.json
virtuoso-bridge eval "YourEntry()" -p v231 --operation-class mutating --expected-context context.json
virtuoso-bridge load YourScript.il -p v231 --expected-context context.json
```

`context` 返回 CIW/daemon 身份、窗口、显示和编辑 cellView、层次路径、编辑到窗口坐标的
三个基准点、网格、DBU、技术库、修改状态以及限量选择摘要。没有编辑窗口时返回空现场。
选择摘要默认最多 50 个，上限 500 个；`truncated=true` 的现场不能作为修改授权依据。

`--expected-context` 在同一 SKILL 请求中先重新读取并比较现场，再执行代码。
窗口、目标、层次、选择摘要或修改状态变化会拒绝执行。它是现场核对，
不能替代具体工具对全部几何、网络或外部状态的重新验证，也不提供通用数据库回滚。

Python 对应接口为 `client.editor_context()`、`client.execute_guarded(code, context)`；
现有 `snapshot(kind="layout")` 和 `snapshot(kind="schematic")` 也提供现场数据。

## 加载固定内容与查询版本

每次 `load` 将本地入口文件捕获到唯一、独占创建的制品路径，保持文件名、扩展名、
内容和行号。相同文件名和多个客户端不再共享可覆盖的上传目标。
`--expected-sha256 HASH` 可检查捕获内容是否仍是调用方预期版本。

```text
virtuoso-bridge load YourScript.il -p v231
virtuoso-bridge loaded-scripts -p v231 --output loaded.json
```

结果的 `metadata.script_load` 包含摘要、源路径、制品路径、路径映射、依赖观察、时间和请求信息。
错误中的制品路径通过 `source_map` 回到本地文件；不修改脚本中的文件路径或 CIW 工作目录。
脚本依据自身文件位置延迟加载同目录辅助脚本时，使用现有声明格式
`; Dependency: sibling Helper.il`。加载器递归捕获声明的同目录文件，保留相邻路径和内容，
并在 `captured_files` 中记录摘要；缺失依赖会在发送 SKILL 前失败，最多捕获 64 个文件。
`TrimRoutingStubs.il` 已有的声明直接适用。其他外部资源应使用明确的资源根路径。
普通嵌套 `load()` 继续按 CIW 规则解析，静态识别到的依赖摘要只描述读取时的文件，
不证明运行时实际加载版本；动态加载不会被猜测为已固定依赖。

版本查询读取本机此连接端点的受管记录，并核对当前 daemon epoch。
当前版本按 CIW 在执行加载前写入的 `load_id` 标记选择，不使用客户端时间推断执行顺序。
旧加载没有标记、标记无法匹配本地回执时，显示 `load-order-unverified`；历史时间只用于展示。
`loaded` 表示入口 load 返回成功且项目包装层确认对应 CDS.log 增量通过；
直接 Python/CLI 加载仅记录 `load-returned`，日志仍需调用方检查。
失败标记 `failed-may-be-partial`，完成未知标记 `completion-unknown`；
无法归属 epoch 的新加载会使该文件的当前版本显示为 `epoch-unattributed-load`。
外部加载、其他机器的记录和任意函数重定义不在此查询的证明范围内。

记录保存在本地 runtime state 的 `script-loads` 中，制品使用本地 runtime tmp 或远端
Bridge 工作目录。记录和制品不提交 Git；有未完成请求时不得清理相关制品。

## 显式 cellView 运行

```text
virtuoso-bridge load YourScript.il -p v231 --lib MyLib --cell MyCell --view layout
```

该模式在同一次请求内打开目标，并将 `cv` 动态绑定到它。默认不保存；显式 `--save`
只在脚本成功且绑定目标未变化时保存。`--require-window` 还要求当前编辑窗口与目标一致。
无窗口脚本应使用传入的 `cv`；直接查询 `geGetEditCellView()` 的脚本仍依赖 UI，
应选择需要匹配窗口的模式。任意脚本自身的保存或修改行为仍由该脚本负责。

Python 的 `run_il_file(..., open_window=False)` 使用相同的目标保护。
开发加载只接受 `r/a`，替换或新建数据库使用已有显式 create API。
`run_il_file(..., mode="r")` 的窗口和数据库打开阶段都使用只读模式，不能与 `save=True`
组合。已有窗口的实际模式不同则拒绝，不自动切换模式或处理未保存设计。

Layout/Schematic/Symbol 编辑上下文只在保存返回 `t` 后正常退出。
目标不匹配、目标丢失或 `dbSave` 返回 `nil` 会报错，并保留尚未保存的内存修改。
`LayoutEditor.close()` 在保存成功后关闭目标；保存失败时不会继续关闭或重放修改。

## 布线清理

```python
from virtuoso_bridge.virtuoso.layout import layout_clear_routing

scope = dict(lib="MyLib", cell="MyCell", lpps=[("M1", "drawing")])
context = client.editor_context()
preview = client.execute_skill(layout_clear_routing(**scope), operation_class="read_only")
# Inspect preview before choosing Apply.
result = client.execute_skill(
    layout_clear_routing(**scope, apply=True, expected_context=context),
    operation_class="mutating",
)
```

必须明确库、cell 和 LPP，默认只处理选择集中的 path/pathSeg，并保留 pin 图形。
需要 rect/polygon 或全 cell 范围时显式指定 `types`、`selected_only=False`，可再按 `nets` 过滤。
没有匹配的编辑目标时拒绝执行，不搜索其他窗口。默认预览，Apply 不自动保存；`save=True`
仅用于明确需要保存的目标。预览的候选数不构成冻结的几何计划，Apply 按同一过滤范围重新选取。

原先的“全部 shapes 清空”行为移到 `layout_clear_all_shapes()`，实际删除同时要求
`confirm_all=True` 和完整 `expected_context`。旧的无参数 `layout_clear_routing()` 调用现在会拒绝，
调用方必须明确范围。
