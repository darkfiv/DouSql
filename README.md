[![GitHub release (latest by date)](https://img.shields.io/github/v/release/darkfiv/DouSql?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/darkfiv/DouSql?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/stargazers)
[![GitHub downloads](https://img.shields.io/github/downloads/darkfiv/DouSql/total?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/releases)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2024.6+-orange?style=flat-square&logo=portswigger)](https://portswigger.net/burp)


## 插件简介

**DouSql** 是基于Xia Sql二次开发的高度自定义化SQL注入检测插件，专为安全研究人员和渗透测试工程师打造。

### 🌍 多语言支持
插件支持中文/英文双语言界面，可根据系统语言自动选择或手动切换：
- **自动检测**：中文系统默认显示中文界面，其他系统默认显示英文界面
- **手动切换**：在配置面板的"语言设置/Language"标签页中可随时切换语言
- **完整覆盖**：所有界面元素（按钮、标签、菜单、配置面板等）均支持双语言切换
- **即时生效**：切换语言后立即更新界面，无需重启插件


## 主要功能
<img width="3012" height="1628" alt="image" src="https://github.com/user-attachments/assets/936e5d1b-9103-40b3-8286-cc91d60eb4ca" />
<img width="2992" height="1602" alt="image" src="https://github.com/user-attachments/assets/94cc3688-22af-4d64-b5bb-47e1970bf07b" />


### 核心检测功能
- **多种SQL注入检测**：支持报错注入、时间盲注、布尔盲注等多种检测方式
- **智能payload管理**：内置7个payload组，包含Mysql、Mssql、Oracle等。
- **实时响应分析**：自动分析响应长度、时间、状态码等关键指标
- **全面的报错信息识别**：内置33种数据库和框架的错误信息模式，支持MySQL、Oracle、PostgreSQL、SQL Server、SQLite等
- **增强JSON处理**：使用Burp Suite内置API处理复杂嵌套JSON结构，支持任意深度的对象、数组和混合数据类型


### 高级配置选项
- **参数过滤系统**：支持白名单/黑名单模式，精确控制测试范围
- **响应过滤系统**：在payload测试过程中过滤无效响应，支持状态码、响应头、响应体内容、响应大小等多种过滤条件，支持AND/OR逻辑组合
- **URL黑名单过滤**：可配置黑名单URL，跳过不需要测试的路径
- **静态文件过滤**：自动跳过图片、样式、脚本等静态资源文件（支持30+种文件类型）
- **响应时间阈值**：可自定义时间盲注检测阈值
- **长度差异阈值**：可配置响应长度差异检测敏感度
- **自定义延时发包**：支持固定延时和随机延时，可配置延时区间（默认1-5秒）
- **自定义追加参数**：支持为请求自动追加多个指定参数，兼容URL、POST、JSON等格式
- **智能参数测试控制**：追加参数可选择是否参与payload测试，提供灵活的测试策略

### 最新功能亮点
- **完全修复中文参数编码问题**：支持UTF-8、GBK、GB2312等多种编码格式
- **智能编码检测与修复**：自动识别并修复参数传递过程中的编码损坏
- **增强JSON处理能力**：完美支持复杂嵌套JSON结构的中文参数
- **优化默认payload**：更新18个高质量SQL注入检测payload
- **payload管理优化**：分离保存和加载功能，操作更直观
- **自定义延时发包**：支持三种延时模式，可配置固定或随机延时，避免WAF检测
- **智能追加参数**：支持URL、POST、JSON三种格式的多参数自动追加，每个参数可独立控制测试开关

### 用户界面特性
- **双面板设计**：左侧显示扫描结果，右侧显示参数测试详情
- **多语言界面**：支持中文/英文双语言，可根据系统自动选择或手动切换
- **实时状态更新**：支持报错标记(err)、时间超时标记(time)、长度差异标记(diff)等状态显示
- **停止测试功能**：右键点击扫描结果中的URL，可选择停止该URL的测试
- **删除测试结果**：右键点击扫描结果，可删除单个结果；清空所有结果可使用控制面板的"清空列表"按钮
- **配置持久化**：所有配置自动保存，重启后自动恢复
- **Windows系统优化**：针对Windows系统进行UI布局优化，确保所有按钮和组件完整显示

### 工具集成
- **智能右键菜单**：支持payload组选择、停止测试、删除结果等多种操作
- **选择性监控**：默认只监控Proxy和Repeater的流量，需要手动启用对应的监控选项
- **自动检测**：通过右键菜单发送的请求会自动进行检测
- **多格式参数支持**：支持URL参数、POST参数、JSON参数、XML参数、Cookie参数等
- **灵活测试策略**：可根据不同场景选择合适的payload组，如盲注场景使用blind-injection-fuzz组，登录场景使用login-password-injection-fuzz组，WAF绕过使用union-select-bypass组

### 监控模式说明
- **Proxy监控**：启用后自动检测通过Proxy的所有HTTP流量
- **Repeater监控**：启用后自动检测Repeater发送的请求
- **Scanner/Intruder**：默认不自动监控，可通过右键菜单手动发送到插件
- **右键发送**：所有工具都支持通过右键菜单发送请求到插件进行检测
  - **使用当前组**：使用插件界面当前选中的payload组进行测试
  - **指定payload组**：可选择特定的payload组（如default、blind-injection-fuzz、login-password-injection-fuzz、union-select-bypass等）进行针对性测试

### 配置目录位置

**默认配置目录（推荐）：**
```bash
# Windows
C:\Users\[用户名]\dousql\

# macOS
/Users/[用户名]/dousql/

# Linux  
/home/[用户名]/dousql/
```

**配置文件结构：**
```
~/dousql/
├── xia_SQL_diy_payload_default.ini                    # default payload配置
├── xia_SQL_payload_orderby.ini                        # order测试组payload配置
├── xia_SQL_payload_blind-injection-fuzz.ini           # 盲注专用payload配置
├── xia_SQL_payload_login-password-injection-fuzz.ini  # 登录绕过payload配置
├── xia_SQL_payload_mssql-payloads-fuzz.ini            # MSSQL专用payload配置
├── xia_SQL_payload_oracle-payloads-fuzz.ini           # Oracle专用payload配置
├── xia_SQL_payload_union-select-bypass.ini            # UNION绕过payload配置
├── xia_SQL_diy_error_default.ini                      # 自定义报错关键字
├── xia_SQL_response_time_threshold.ini                # 响应时间阈值配置
├── xia_SQL_length_diff_threshold.ini                  # 长度差异阈值配置
├── xia_SQL_blacklist_urls.ini                         # 黑名单URL配置
├── xia_SQL_whitelist.ini                              # 白名单参数配置
├── xia_SQL_blacklist.ini                              # 黑名单参数配置
└── xia_SQL_param_filter_mode.ini                      # 参数过滤模式配置
```

**特殊情况（jar包同级）：**
```
/path/to/extensions/
├── DouSql-6.jar          # 插件jar包
└── dousql/                   # 配置文件目录
    ├── xia_SQL_diy_payload.ini
    ├── xia_SQL_payload_timebased.ini
    └── ...
```

**配置目录检测日志示例：**
```
ProtectionDomain路径: /var/folders/.../tmp/burp.../20
使用用户主目录: /Users/username
hello DouSQL!
你好 欢迎使用 DouSQL!
version:3.0. (Montoya API)
jar包目录: /Users/username
配置文件目录: /Users/username/dousql
```

## 快速开始

### 方式一：直接下载
从 [Releases](https://github.com/darkfiv/DouSql/releases) 页面下载最新版本的jar文件

### 方式二：从源码编译
```bash
git clone https://github.com/darkfiv/DouSql.git
cd DouSql
mvn clean package
```

### 加载到Burp Suite
1. 打开Burp Suite
2. 进入 Extensions → Installed
3. 点击 Add 按钮
4. 选择编译生成的jar文件
5. 插件加载成功后，会在标签页看到"DouSQL"

## 使用方法

### 编译插件

**环境要求：**
- Java 11+
- Maven 3.x

**编译步骤：**
```bash
# 克隆项目
git clone https://github.com/darkfiv/DouSql.git
cd DouSql

# 编译打包
mvn clean package

# 编译完成后，jar文件位于：
# target/DouSql-3.0.8.jar
```

### 安装使用

1. 将编译生成的jar文件加载到Burp Suite
2. 在Extensions标签页中找到"DouSQL"插件
3. 配置相关检测参数和阈值
4. 通过右键菜单或监控模式发送请求进行检测
5. 查看扫描结果和参数测试详情

## 结果标记说明

### 检测结果标记
- **ERR!** - 响应中匹配到报错信息，表示疑似存在SQL注入漏洞
- **time > N** - 响应时间大于配置的时间阈值（N秒），表示疑似存在时间盲注
- **diff: ±N** - 响应长度与原始响应差异超过阈值，可能存在布尔盲注
- **✔ ==> ?** - 特殊payload响应长度变化，可能存在逻辑漏洞

### 状态标记
- **start** - 正在测试中
- **start [time]** - 正在测试中，已发现时间异常
- **start [err]** - 正在测试中，已发现报错信息
- **start [diff]** - 正在测试中，已发现长度差异
- **end!** - 测试完成
- **end! [time]** - 测试完成且发现时间异常（优先级最高）
- **end! [err]** - 测试完成且发现报错信息（优先级第二）
- **end! [diff]** - 测试完成且发现长度差异（优先级第三）
- **已停止** - 用户手动停止测试

**优先级说明**：当同时存在多种异常时，按照 **time > err > diff** 的优先级显示状态标记。
- 如果检测到时间延迟（time），只显示 `time`
- 如果检测到错误信息（err）和长度差异（diff），显示 `err+diff`
- 如果只检测到长度差异（diff），显示 `diff`
- 测试结束时（end!），会显示所有检测到的异常类型，如 `end! TIME ERR DIFF`

## 使用技巧

### 1. 根据应用场景配置payload组

插件内置了7个专业的payload组，涵盖各种SQL注入场景：

#### 内置Payload组说明
- **default**（21个payload）：通用SQL注入检测，包含时间盲注、布尔盲注、报错注入等常见payload
- **order测试组**（3个payload）：专门用于ORDER BY子句的注入测试
- **blind-injection-fuzz**（42个payload）：盲注专用字典，包含MySQL、MSSQL、PostgreSQL的sleep/waitfor/benchmark等时间盲注payload
- **login-password-injection-fuzz**（73个payload）：登录绕过专用字典，包含各种认证绕过和万能密码payload
- **mssql-payloads-fuzz**（14个payload）：MSSQL数据库专用payload，包含xp_cmdshell、waitfor等特性
- **oracle-payloads-fuzz**（8个payload）：Oracle数据库专用payload，包含utl_http、utl_inaddr等特性
- **union-select-bypass**（30个payload）：UNION注入绕过字典，包含各种WAF绕过技巧

#### 使用建议
- **快速扫描**：使用`default`组进行初步检测
- **深度测试**：根据目标数据库类型选择对应的专用组（mssql/oracle）
- **登录场景**：使用`login-password-injection-fuzz`组测试登录表单
- **盲注场景**：使用`blind-injection-fuzz`组进行时间盲注测试
- **WAF绕过**：使用`union-select-bypass`组尝试绕过防护
- **自定义场景**：创建专门的payload组，针对特定应用优化

### 2. 合理配置参数过滤
- **无过滤模式**：测试所有检测到的参数，适合全面扫描
- **白名单模式**：只测试配置的关键参数（如id、username、password等）
- **黑名单模式**：排除配置的无关参数（如token、timestamp、csrf_token等）
- **独立存储**：白名单和黑名单参数分别保存，切换模式时不会丢失配置
- **提高效率**：避免测试大量无意义参数，专注于可能存在漏洞的参数

### 3. 设置黑名单URL
- 排除静态资源路径（如`/static/*`、`*.css`、`*.js`、`*.jpg`、`*.png`等）
- 排除管理后台路径（如`/admin/*`）
- 排除API文档路径（如`/swagger/*`、`/api-docs/*`）

### 4. 静态文件自动过滤
插件会自动跳过以下类型的静态文件：
- **图片文件**：jpg, jpeg, png, gif, bmp, tiff, tif, webp, svg, ico
- **样式和脚本**：css, js
- **字体文件**：woff, woff2, ttf, eot, otf
- **媒体文件**：mp3, mp4, avi, mov, wmv, flv, mkv
- **压缩文件**：zip, rar, 7z, tar, gz
- **文档文件**：pdf

### 5. 调整检测阈值
- **响应时间阈值**：根据目标服务器性能调整（建议2-5秒）
- **长度差异阈值**：根据应用响应特点调整（建议50-200字节）

### 6. 灵活使用右键菜单
- **快速测试**：选择"使用当前组"进行快速测试，使用插件界面当前选中的payload组
- **精确测试**：根据测试场景选择特定payload组：
  - **default组**：通用SQL注入检测，适合快速扫描
  - **order测试组**：ORDER BY注入测试
  - **blind-injection-fuzz组**：时间盲注深度测试
  - **login-password-injection-fuzz组**：登录表单绕过测试
  - **mssql-payloads-fuzz组**：MSSQL数据库专项测试
  - **oracle-payloads-fuzz组**：Oracle数据库专项测试
  - **union-select-bypass组**：UNION注入WAF绕过
  - **自定义组**：根据目标特点创建的专门payload组
- **测试策略**：可以先用default组进行快速扫描，发现可疑点后再用专门的payload组深入测试

### 7. 停止测试功能
- **紧急停止**：当目标服务器异常或需要立即停止测试时，右键点击扫描结果中的URL
- **选择性停止**：只停止选中的特定URL测试，不影响其他URL的测试进程
- **智能提示**：菜单会显示当前测试状态，已完成的测试无法停止
- **安全停止**：正在进行的payload测试会在当前完成后停止，避免请求中断

### 9. 响应过滤配置使用
- **启用过滤**：在配置面板的"响应过滤配置"标签页中启用响应过滤功能
- **过滤条件类型**：
  - **状态码过滤**：根据HTTP状态码过滤（如跳过404、500等错误响应）
  - **响应头过滤**：根据特定响应头的值过滤（如Content-Type、Server等）
  - **响应体内容过滤**：根据响应体中的关键字过滤（如跳过包含"error"的响应）
  - **响应大小过滤**：根据响应体大小过滤（如跳过过小或过大的响应）
- **比较操作符**：支持等于、不等于、包含、不包含、大于、小于等多种比较方式
- **逻辑组合**：支持AND（所有条件都满足）和OR（任一条件满足）两种逻辑模式
- **实际应用**：
  - 跳过错误页面：状态码不等于200
  - 跳过空响应：响应大小大于10字节
  - 跳过特定内容：响应体不包含"success"
  - 组合条件：状态码等于200 AND 响应体包含"data"

### 10. 语言切换使用
- **自动检测**：插件会根据系统语言自动选择界面语言（中文系统显示中文，其他系统显示英文）
- **手动切换**：在配置面板找到"语言设置/Language"标签页
- **即时生效**：选择语言后点击"Switch Language/切换语言"按钮，选择"Update Now/立即更新"即可立即生效
- **完整覆盖**：所有界面元素都会切换，包括按钮、标签、菜单、配置面板等
- **国际化友好**：支持国际用户使用，提供专业的英文界面

### 11. 删除测试结果
- **删除单个结果**：右键点击扫描结果中的URL，选择"删除测试结果"
- **清空所有结果**：使用控制面板的"清空列表"按钮，一次性清理所有测试数据
- **确认机制**：删除前会显示确认对话框，防止误操作
- **完整清理**：删除操作会清理所有相关数据，包括payload测试结果
- **实时更新**：删除后立即刷新界面，保持数据一致性
- **适用场景**：清理误报结果、删除无关测试、整理测试列表、重新开始测试

## 重要提示

⚠️ **关于默认Payload**：
- 默认payload为作者日常SRC、渗透测试所用的通用payload
- 师傅们需要根据自己的实际场景去优化、添加POC
- 建议针对不同目标创建专门的payload组
- 可以根据目标技术栈（如Java、PHP、.NET等）定制payload


## 系统要求

**运行环境：**
- Burp Suite Professional 2024.6+
- Java 11+
- 支持Windows、macOS、Linux操作系统

**编译环境：**
- Java 11+
- Maven 3.x

## 开发环境

- Java版本：Java 11
- Burp Suite版本：2024.8.2
- 构建工具：Maven 3.x
- API框架：Montoya API (Burp Suite官方扩展API)

## 更新记录

### 最新版本 V3.0.9 (2026-03-19)
- **修复原有数字型-1、-0逻辑丢失的问题**：识别为数字型参数，追加-1、-0测试逻辑
- **修复参数测试不全的问题**
- **默认时间阀门值由2秒更新为5秒**
- **修复无效请求展示问题、请求去重问题**

**详细更新记录请查看 [CHANGELOG.md](CHANGELOG.md)**

## 交流群
交流群二维码老过期，有需要的师傅可关注安全鸭公众号，联系作者，私聊进群。

## 免责声明

本工具仅供安全测试和教育目的使用，使用者应遵守相关法律法规，不得用于非法用途。开发者不承担因误用本工具造成的任何责任。


