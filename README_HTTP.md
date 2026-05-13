
## 文件说明

| 文件 | 放在哪 | 作用 |
|------|--------|------|
| `INP.py` | 虚拟机 IDA Pro plugins 目录 | 导出反编译结果到本地目录 |
| `inp_http_server.py` | 虚拟机（任意目录） | 把导出目录通过 HTTP 暴露出来 |
| `inp_mcp_server_http.py` | 宿主机（任意目录） | MCP Server，通过 HTTP 请求虚拟机数据，供 Claude Code 调用 |

---

## 整体架构

```
虚拟机 (IDA Pro)
────────────────────────────────────────────
  INP.py
    ↓ 导出 .c / .asm / strings.txt / ...
  target_export_for_ai/
    ↑ 读取文件
  inp_http_server.py  →  HTTP :18080
────────────────────────────────────────────
             ↑ HTTP 请求 (VM_IP:18080)
────────────────────────────────────────────
  宿主机
  inp_mcp_server_http.py
    ↑ stdio MCP 协议
  Claude Code
────────────────────────────────────────────
```

---

## 第一步：虚拟机 — 安装 INP.py 并导出

1. 把 `INP.py` 放入 IDA Pro plugins 目录：
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - Linux:   `~/.idapro/plugins/`

2. 打开 IDA Pro，加载目标二进制（exe / ELF / deb 解包后的文件）

3. 菜单 **Edit → Plugins → IDA Export for AI** 执行导出
   - 导出目录示例：`C:\analysis\target.exe_export_for_ai`

---

## 第二步：虚拟机 — 启动 HTTP 服务器

```cmd
# Windows 虚拟机（CMD 或 PowerShell）
python inp_http_server.py ^
  --export-dir "C:\analysis\target.exe_export_for_ai" ^
  --port 18080 ^
  --token mysecret

# Linux 虚拟机
python3 inp_http_server.py \
  --export-dir ~/analysis/target_export_for_ai \
  --port 18080 \
  --token mysecret
```

**验证服务器正常**（在宿主机浏览器或 curl 访问）：
```
http://VM_IP:18080/ping
http://VM_IP:18080/overview
```

> 如果虚拟机防火墙拦截，Windows 执行：
> `netsh advfirewall firewall add rule name="INP HTTP" dir=in action=allow protocol=TCP localport=18080`

---

## 第三步：宿主机 — 配置 Claude Code 使用 MCP

在逆向分析项目目录创建 `.mcp.json`：

```json
{
  "mcpServers": {
    "ida-inp": {
      "command": "python",
      "args": [
        "/path/to/inp_mcp_server_http.py",
        "--server", "http://192.168.x.x:18080",
        "--token", "mysecret"
      ]
    }
  }
}
```

> macOS/Linux 宿主机示例：
> ```json
> "args": ["/Users/you/tools/inp_mcp_server_http.py", "--server", "http://192.168.80.128:18080", "--token", "mysecret"]
> ```

---

## 第四步：在 Claude Code 里使用

打开 Claude Code，进入含 `.mcp.json` 的项目目录：

```
# 先测试连通性
ping

# 看看导出了什么
list_overview

# 搜索加密相关函数
search_functions: {"query": "crypt"}

# 读取某个函数的伪代码
read_function: {"address": "401A20"}

# 查找敏感字符串
read_strings: {"filter": "password"}

# 查看导入了哪些 API
read_imports: {"filter": "socket"}

# 读取内存 hexdump
list_memory_chunks
read_memory_chunk: {"address": "401000"}
```

---

## HTTP API 端点（供调试）

| 端点 | 说明 |
|------|------|
| `GET /ping` | 连通性测试 |
| `GET /overview` | 导出目录统计 |
| `GET /list?dir=decompile` | 列出子目录文件 |
| `GET /file?path=decompile/401000.c` | 读取文件内容（支持 offset/length 分页）|
| `GET /search?q=crypto&type=functions` | 搜索（type: functions/strings/imports/all）|

所有请求支持 `Authorization: Bearer <token>` 或 `?token=<token>` 鉴权。

---

