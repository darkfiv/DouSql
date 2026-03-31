[![GitHub release (latest by date)](https://img.shields.io/github/v/release/darkfiv/DouSql?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/darkfiv/DouSql?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/stargazers)
[![GitHub downloads](https://img.shields.io/github/downloads/darkfiv/DouSql/total?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/releases)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2024.6+-orange?style=flat-square&logo=portswigger)](https://portswigger.net/burp)

## 插件简介

**DouSql** 是基于 Xia Sql 二次开发的 Burp Suite SQL 注入辅助检测插件，面向安全研究人员与渗透测试工程师，强调：

- 更灵活的 payload 管理
- 更直观的结果展示
- 更丰富的高级配置
- 更适合日常实战的联动能力

## 最近更新

- 新增 **SQLMap 联动测试**：参数详情右键可一键发送到 SQLMap
- 新增 **SQLMap 配置页**：支持路径、默认参数、输出目录配置
- 新增 **SQLMap 实时输出窗口**：可直接在插件内查看运行日志
- 新增 **漏洞结果颜色标记**：布尔 / 报错 / 时间盲注可视化更直观
- 修复 **延时发包、追加参数、响应过滤** 配置无法持久化的问题

详细变更见 [CHANGELOG.md](/Users/mac/Desktop/tools/code/workspace/java_workspace/xiasqlPlus/CHANGELOG.md)。

## 主要功能

### 核心检测

- 支持 **报错注入、时间盲注、布尔盲注**
- 支持 **URL、POST、JSON、Cookie** 等常见参数类型
- 内置多组 payload，可针对不同场景选择测试策略
- 自动分析响应长度、时间、状态码、错误关键字

### 高级配置

- 参数白名单 / 黑名单过滤
- 响应过滤条件配置，支持 AND / OR 逻辑
- URL 黑名单过滤
- 响应时间阈值与长度差异阈值配置
- 延时发包配置
- 自定义追加参数与“是否参与 payload 测试”控制
- 中英文双语言界面

### 界面与体验

- 左侧展示扫描结果，右侧展示参数测试详情
- 命中漏洞的扫描结果整行高亮
- 参数详情按类型着色：
  - `diff`：绿色
  - `ERR!`：黄色
  - `time`：红色
- 支持右键暂停、删除、重测、发送到 SQLMap

### SQLMap 联动

- 参数详情右键可直接发送到 SQLMap
- 自动导出 **原始请求包**，避免把带 payload 的测试请求传给 SQLMap
- 支持配置：
  - `sqlmap.py` / 可执行文件路径
  - Python 路径
  - 默认运行参数
  - 输出目录
- 默认模板：

```text
-r {requestFile} -p {parameter} --batch --level 3 --risk 3 --ignore-stdin --output-dir={outputDir}
```

## 界面预览

<img width="3012" height="1628" alt="image" src="https://github.com/user-attachments/assets/936e5d1b-9103-40b3-8286-cc91d60eb4ca" />
<img width="2992" height="1602" alt="image" src="https://github.com/user-attachments/assets/94cc3688-22af-4d64-b5bb-47e1970bf07b" />

## 快速开始

### 下载

从 [Releases](https://github.com/darkfiv/DouSql/releases) 下载最新 jar 文件。

### 编译

环境要求：

- Java 11+
- Maven 3.x

```bash
git clone https://github.com/darkfiv/DouSql.git
cd DouSql
mvn clean package
```

### 加载到 Burp Suite

1. 打开 Burp Suite
2. 进入 `Extensions -> Installed`
3. 点击 `Add`
4. 选择编译后的 jar 文件
5. 加载成功后会看到 `DouSQL` 标签页

## 使用方式

### 常规检测

1. 通过右键菜单把请求发送到 DouSql，或开启 Proxy / Repeater 监听
2. 在结果区查看扫描状态与参数测试详情
3. 根据 `ERR! / time / diff` 判断可疑参数

### 推荐使用流程

1. 用 `default` 组做快速扫描
2. 对可疑点切换更有针对性的 payload 组深入测试
3. 对高价值参数右键发送到 SQLMap 做进一步验证

## 结果说明

### 参数详情标记

- `ERR!`：命中报错注入特征
- `time > N`：命中时间盲注特征
- `diff +/-N`：响应长度差异明显，可能存在布尔注入

### 扫描状态

- `start`：正在测试
- `diff`：发现长度差异
- `err`：发现报错特征
- `time`：发现时间异常
- `end! TIME ERR DIFF`：测试完成，并汇总命中类型

优先级：`time > err > diff`

## 配置目录

默认配置目录：

```bash
# Windows
C:\Users\[用户名]\dousql\

# macOS
/Users/[用户名]/dousql/

# Linux
/home/[用户名]/dousql/
```

主要配置文件：

```text
~/dousql/
├── xia_SQL_diy_payload_default.ini
├── xia_SQL_diy_error.ini
├── xia_SQL_time_threshold.ini
├── xia_SQL_length_diff_threshold.ini
├── xia_SQL_blacklist_urls.ini
├── xia_SQL_whitelist.ini
├── xia_SQL_blacklist.ini
├── xia_SQL_param_filter_mode.ini
├── xia_SQL_delay_config.ini
├── xia_SQL_append_params_enabled.ini
├── xia_SQL_append_params.ini
├── xia_SQL_append_params_testable.ini
├── response_filter.properties
└── xia_SQL_sqlmap_config.ini
```

## README 可以怎么继续优化

如果后面还想继续收缩文档，推荐这样拆：

- `README.md`：保留项目简介、核心能力、快速开始、配置目录、SQLMap 联动
- `CHANGELOG.md`：放所有版本更新
- `docs/usage.md`：放详细使用教程
- `docs/configuration.md`：放各配置项说明
- `docs/sqlmap.md`：放 SQLMap 联动细节与排错

这样首页更适合新用户快速理解，详细内容也不会丢。

## 免责声明

本工具仅供安全测试与学习研究使用。请确保你对目标拥有合法授权，使用者需自行遵守所在地法律法规，开发者不对任何误用或损害负责。
