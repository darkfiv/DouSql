# DouSql V3.0.2 - Burp Suite SQL注入检测插件

## 插件简介

基于Xia Sql 二次开发，感谢前辈铺路。
修复多个不足/bug，满足安全仔的日常渗透神器。

## 主要功能

### 核心检测功能
- **多种SQL注入检测**：支持报错注入、时间盲注、布尔盲注等多种检测方式
- **智能payload管理**：内置多种payload组，支持自定义payload配置
- **丰富的默认字典**：包含17种常用SQL注入payload，涵盖时间盲注、布尔盲注、报错注入等
- **实时响应分析**：自动分析响应长度、时间、状态码等关键指标
- **全面的报错信息识别**：内置33种数据库和框架的错误信息模式，支持MySQL、Oracle、PostgreSQL、SQL Server、SQLite等

### 高级配置选项
- **参数过滤系统**：支持白名单/黑名单模式，精确控制测试范围
- **URL黑名单过滤**：可配置黑名单URL，跳过不需要测试的路径
- **响应时间阈值**：可自定义时间盲注检测阈值
- **长度差异阈值**：可配置响应长度差异检测敏感度
- **HTTP方法过滤**：仅对GET/POST请求进行检测，提高效率

### 用户界面特性
- **双面板设计**：左侧显示扫描结果，右侧显示参数测试详情
- **实时状态更新**：支持报错标记(err)、时间超时标记(time)等状态显示
- **配置持久化**：所有配置自动保存，重启后自动恢复
- **跨平台兼容**：支持Windows、macOS、Linux等多种操作系统

### 工具集成
- **多工具支持**：支持从Scanner、Proxy、Repeater、Intruder发送请求
- **右键菜单集成**：可通过右键菜单快速发送请求到插件
- **监控模式**：支持实时监控Proxy和Repeater的流量

## 配置文件说明

插件配置文件统一存储在用户主目录的 `DouSQL/xia-sql/` 目录下：

- `xia_SQL_diy_payload.ini` - 默认payload配置
- `xia_SQL_payload_[组名].ini` - 自定义payload组配置
- `xia_SQL_diy_error.ini` - 自定义报错关键字
- `xia_SQL_response_time_threshold.ini` - 响应时间阈值配置
- `xia_SQL_length_diff_threshold.ini` - 长度差异阈值配置
- `xia_SQL_blacklist_urls.ini` - 黑名单URL配置
- `xia_SQL_whitelist.ini` - 白名单参数配置
- `xia_SQL_blacklist.ini` - 黑名单参数配置
- `xia_SQL_param_filter_mode.ini` - 参数过滤模式配置

**配置文件位置示例：**
```
# Windows
C:\Users\[用户名]\DouSQL\xia-sql\

# macOS/Linux  
/Users/[用户名]/DouSQL/xia-sql/
/home/[用户名]/DouSQL/xia-sql/
```

**目录结构：**
```
~/DouSQL/
└── xia-sql/
    ├── xia_SQL_diy_payload.ini
    ├── xia_SQL_payload_timebased.ini
    ├── xia_SQL_diy_error.ini
    └── ...
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
# target/DouSql-3.0.2.jar
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
- **end!** - 测试完成
- **end! [err]** - 测试完成且发现报错信息
- **end! [time]** - 测试完成且发现时间异常

## 使用技巧

### 1. 根据应用场景配置payload组
- **时间盲注场景**：使用`timebased`组，包含各种延时payload
- **报错注入场景**：使用`orderby`组，包含报错类payload
- **自定义场景**：创建专门的payload组，针对特定应用优化

### 2. 合理配置参数过滤
- **白名单模式**：只测试关键参数（如id、username、password等）
- **黑名单模式**：排除无关参数（如token、timestamp等）
- **提高效率**：避免测试大量无意义参数

### 3. 设置黑名单URL
- 排除静态资源路径（如`/static/*`、`*.css`、`*.js`）
- 排除管理后台路径（如`/admin/*`）
- 排除API文档路径（如`/swagger/*`、`/api-docs/*`）

### 4. 调整检测阈值
- **响应时间阈值**：根据目标服务器性能调整（建议2-5秒）
- **长度差异阈值**：根据应用响应特点调整（建议50-200字节）

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

### V3.0.2 (2025-12-28)
- 优化配置文件路径，配置文件现在存储在jar包同级的`xia-sql/`目录下
- 扩展默认payload字典，新增多种SQL注入检测payload（共17种）
- 扩展默认报错信息字典，支持多种数据库和框架的错误信息识别（共33种）
- 代码开源

### V3.0.1 (2025-12-26)
- 修复工具来源判断逻辑错误导致的无限循环测试问题
- 修复响应时间检测优先级问题，确保超时请求正确显示"time > N"标记
- 优化监听条件判断，避免未启用监听时错误处理toolFlag=0的请求

### V3.0.0 (2025-12-25)
- 基于Montoya API重构，提升稳定性和兼容性
- 新增payload分组管理功能，支持多种测试场景
- 优化用户界面布局，改进左右分割面板设计
- 新增参数过滤系统，支持白名单/黑名单模式
- 新增黑名单URL过滤功能，支持通配符匹配
- 新增自定义报错信息检测功能
- 新增响应时间阈值和长度差异阈值配置
- 优化时间盲注检测逻辑，支持全payload类型时间检测
- 新增配置文件统一管理，所有配置持久化保存
- 修复跨平台兼容性问题，确保Windows/macOS下界面正常显示
- 新增HTTP方法过滤，仅检测GET/POST请求
- 优化错误检测优先级，报错信息优先于其他变化标记
- 新增状态栏时间超时标记，完善检测结果展示
- 修复多线程并发问题，提升插件稳定性



## 免责声明

本工具仅供安全测试和教育目的使用，使用者应遵守相关法律法规，不得用于非法用途。开发者不承担因误用本工具造成的任何责任。
