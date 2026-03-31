package utils;

import burp.IBurpExtenderCallbacks;
import java.util.HashMap;
import java.util.Map;
import java.util.Locale;

/**
 * 国际化管理器
 * 支持中英文切换
 */
public class I18nManager {
    private final IBurpExtenderCallbacks callbacks;
    private Locale currentLocale;
    private Map<String, String> messages;
    
    // 支持的语言
    public enum Language {
        CHINESE("zh", "中文"),
        ENGLISH("en", "English");
        
        private final String code;
        private final String displayName;
        
        Language(String code, String displayName) {
            this.code = code;
            this.displayName = displayName;
        }
        
        public String getCode() { return code; }
        public String getDisplayName() { return displayName; }
    }
    
    public I18nManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        // 根据系统语言自动选择默认语言
        this.currentLocale = getSystemDefaultLocale();
        loadMessages();
        callbacks.printOutput("I18n initialized with locale: " + currentLocale + " (" + getCurrentLanguage().getDisplayName() + ")");
    }
    
    /**
     * 获取系统默认语言环境
     */
    private Locale getSystemDefaultLocale() {
        Locale systemLocale = Locale.getDefault();
        String language = systemLocale.getLanguage();
        
        // 如果系统语言是中文相关，使用中文
        if ("zh".equals(language) || "cn".equals(language)) {
            return Locale.CHINESE;
        }
        // 否则使用英文
        else {
            return Locale.ENGLISH;
        }
    }
    
    /**
     * 切换语言
     */
    public void switchLanguage(Language language) {
        switch (language) {
            case CHINESE:
                this.currentLocale = Locale.CHINESE;
                break;
            case ENGLISH:
                this.currentLocale = Locale.ENGLISH;
                break;
        }
        loadMessages();
        callbacks.printOutput("Language switched to: " + language.getDisplayName());
    }
    
    /**
     * 获取当前语言
     */
    public Language getCurrentLanguage() {
        if (currentLocale.equals(Locale.ENGLISH)) {
            return Language.ENGLISH;
        }
        return Language.CHINESE;
    }
    
    /**
     * 获取本地化文本
     */
    public String getText(String key) {
        return messages.getOrDefault(key, key);
    }
    
    /**
     * 获取本地化文本（带参数）
     */
    public String getText(String key, Object... args) {
        String template = messages.getOrDefault(key, key);
        return String.format(template, args);
    }
    
    /**
     * 加载消息资源
     */
    private void loadMessages() {
        messages = new HashMap<>();
        
        if (currentLocale.equals(Locale.ENGLISH)) {
            loadEnglishMessages();
        } else {
            loadChineseMessages();
        }
    }
    
    /**
     * 加载中文消息
     */
    private void loadChineseMessages() {
        // UI 标题和标签
        messages.put("plugin.title", "DouSQL-安全鸭专属【魔改版本】｜Author By：DarkFi5");
        messages.put("tab.title", "DouSQL");
        
        // 控制面板
        messages.put("control.panel", "控制面板");
        messages.put("control.enable.plugin", "启动插件");
        messages.put("control.monitor.repeater", "监控Repeater");
        messages.put("control.monitor.proxy", "监控Proxy");
        messages.put("control.process.numbers", "值是数字则进行-1、-0");
        messages.put("control.test.cookie", "测试Cookie");
        messages.put("control.clear.list", "清空列表");
        messages.put("control.whitelist.hint", "如果需要多个域名加白请用,隔开");
        messages.put("control.whitelist.placeholder", "填写白名单域名");
        messages.put("control.whitelist.enable", "启动白名单");
        
        // 表格标题
        messages.put("table.scan.results", "扫描结果");
        messages.put("table.payload.details", "参数测试详情");
        messages.put("table.column.id", "ID");
        messages.put("table.column.url", "URL");
        messages.put("table.column.state", "状态");
        messages.put("table.column.params", "参数数");
        messages.put("table.column.time", "时间");
        messages.put("table.column.param", "参数");
        messages.put("table.column.payload", "Payload");
        messages.put("table.column.change", "变化");
        messages.put("table.column.length", "长度");
        messages.put("table.column.response.time", "响应时间");
        messages.put("table.column.status", "状态码");
        
        // HTTP编辑器
        messages.put("editor.request", "Request");
        messages.put("editor.response", "Response");
        
        // 配置标签页
        messages.put("config.custom.sql", "自定义SQL语句");
        messages.put("config.param.filter", "参数过滤配置");
        messages.put("config.response.filter", "响应过滤配置");
        messages.put("config.custom.error", "自定义报错信息");
        messages.put("config.time.threshold", "时间阈值配置");
        messages.put("config.length.diff", "长度差异配置");
        messages.put("config.url.blacklist", "黑名单URL过滤");
        messages.put("config.delay", "延时发包配置");
        messages.put("config.append.params", "追加参数配置");
        messages.put("config.advanced", "高级配置");
        messages.put("config.language", "语言设置");
        
        // 右键菜单
        messages.put("menu.pause.test", "暂停测试");
        messages.put("menu.resume.test", "恢复测试");
        messages.put("menu.delete.test", "删除测试请求");
        messages.put("menu.pause.all", "暂停所有扫描");
        messages.put("menu.delete.payload", "删除此payload测试结果");
        messages.put("menu.retest.payload", "重新测试此payload");
        messages.put("menu.send.to.dousql.current", "发送到 DouSQL (当前组)");
        messages.put("menu.send.to.dousql.select", "发送到 DouSQL (选择组)");
        
        // 消息和提示
        messages.put("message.scan.paused", "扫描已暂停，跳过payload测试");
        messages.put("message.scan.resumed", "扫描已恢复");
        messages.put("message.requests.paused", "已暂停 %d 个当前请求的扫描");
        messages.put("message.new.requests.normal", "后续的新请求将正常进行测试");
        messages.put("message.single.resume.hint", "可以通过右键单个请求来恢复特定请求的扫描");
        
        // 对话框标题
        messages.put("dialog.scan.control", "扫描控制");
        messages.put("dialog.confirm", "确认");
        messages.put("dialog.error", "错误");
        messages.put("dialog.success", "成功");
        messages.put("dialog.warning", "警告");
        messages.put("dialog.info", "提示");
        
        // 按钮
        messages.put("button.ok", "确定");
        messages.put("button.cancel", "取消");
        messages.put("button.save", "保存");
        messages.put("button.load", "加载");
        messages.put("button.reset", "重置");
        messages.put("button.add", "添加");
        messages.put("button.edit", "编辑");
        messages.put("button.delete", "删除");
        
        // 配置面板按钮和标签
        messages.put("button.new.group", "新建");
        messages.put("button.rename.group", "重命名");
        messages.put("button.delete.group", "删除");
        messages.put("button.save.payload", "保存payload");
        messages.put("button.reload.payload", "重新加载payload");
        messages.put("button.reset.payload.default", "重置为默认");
        messages.put("button.reset.default", "重置为默认");
        messages.put("button.save.error.config", "保存报错信息配置");
        messages.put("button.save.time.config", "保存时间阈值配置");
        messages.put("button.save.length.config", "保存长度差异配置");
        messages.put("button.save.param.config", "保存参数配置");
        messages.put("button.save.blacklist.config", "保存黑名单配置");
        messages.put("button.clear.append.params", "清除配置并禁用");
        messages.put("button.apply.delay.config", "应用延时配置（本次会话）");
        messages.put("button.open.config.dir", "打开配置目录");
        messages.put("button.reload.all.config", "重新加载所有配置");
        messages.put("button.add.condition", "添加条件");
        messages.put("button.edit.condition", "编辑条件");
        messages.put("button.delete.condition", "删除条件");
        messages.put("button.save.config", "保存配置");
        
        // 标签文本
        messages.put("label.config.file.hint", "修改payload后点击保存，切换组时点击重新加载（配置文件：%s）");
        messages.put("label.test.group", "测试组:");
        messages.put("label.error.keywords", "报错关键字配置 (每行一个关键字或正则表达式)");
        messages.put("label.response.time.threshold", "响应时间阈值(毫秒):");
        messages.put("label.request.timeout", "请求超时时间(毫秒):");
        messages.put("label.length.diff.threshold", "长度差异阈值(字节):");
        messages.put("label.param.list", "参数列表 (每行一个参数名)");
        messages.put("label.append.params", "参数列表 (格式: key:value，一行一个):");
        messages.put("label.test.switch", "选择参与payload测试的参数:");
        messages.put("label.append.params.hint", "<html><i>请在左侧输入参数，右侧会自动生成对应的测试选项</i></html>");
        messages.put("label.fixed.delay", "固定延时时间(毫秒):");
        messages.put("label.random.delay.min", "随机延时最小值(毫秒):");
        messages.put("label.random.delay.max", "随机延时最大值(毫秒):");
        messages.put("label.config.directory", "配置目录:");
        messages.put("label.condition.type", "条件类型:");
        messages.put("label.header.name", "响应头名称:");
        messages.put("label.compare.operation", "比较操作:");
        messages.put("label.compare.value", "比较值:");
        
        // 复选框文本
        messages.put("checkbox.custom.payload", "自定义payload");
        messages.put("checkbox.url.encode.spaces", "空格替换为+");
        messages.put("checkbox.empty.param.values", "参数值置空");
        messages.put("checkbox.enable.custom.error", "启用自定义报错信息（配置文件：%s）");
        messages.put("checkbox.enable.append.params", "启用自定义追加参数（启用即生效）");
        messages.put("checkbox.enable.response.filter", "启用响应过滤");
        messages.put("checkbox.enable.condition", "启用此条件");
        messages.put("checkbox.param.test", "%s (值: %s)");
        
        // 边框标题
        messages.put("border.append.params.config", "追加参数配置");
        messages.put("border.test.switch", "测试开关");
        
        // 语言设置
        messages.put("language.chinese", "中文");
        messages.put("language.english", "English");
        messages.put("language.switch.success", "语言切换成功！请关闭并重新打开 DouSQL 标签页以查看完整的语言切换效果。");
        
        // 响应过滤相关
        messages.put("checkbox.enable.response.filter", "启用响应过滤");
        messages.put("label.condition.type", "条件类型:");
        messages.put("label.header.name", "响应头名称:");
        messages.put("label.compare.operation", "比较操作:");
        messages.put("label.compare.value", "比较值:");
        messages.put("checkbox.enable.condition", "启用此条件");
        
        // 占位符文本
        messages.put("placeholder.new.group.name", "新组名");
        
        // 过滤模式
        messages.put("filter.mode.none", "无过滤 (所有参数测试)");
        messages.put("filter.mode.whitelist", "白名单模式 (只测试配置参数)");
        messages.put("filter.mode.blacklist", "黑名单模式 (跳过配置参数)");
        
        // 延时模式
        messages.put("delay.mode.none", "无延时 (立即发送)");
        messages.put("delay.mode.fixed", "固定延时");
        messages.put("delay.mode.random", "随机延时");
    }
    
    /**
     * 加载英文消息
     */
    private void loadEnglishMessages() {
        // UI titles and labels
        messages.put("plugin.title", "DouSQL - Security Duck [Modified] | By: DarkFi5");
        messages.put("tab.title", "DouSQL");
        
        // Control panel
        messages.put("control.panel", "Control Panel");
        messages.put("control.enable.plugin", "Enable Plugin");
        messages.put("control.monitor.repeater", "Monitor Repeater");
        messages.put("control.monitor.proxy", "Monitor Proxy");
        messages.put("control.process.numbers", "Process numbers (-1, -0)");
        messages.put("control.test.cookie", "Test Cookie");
        messages.put("control.clear.list", "Clear List");
        messages.put("control.whitelist.hint", "Use comma to separate domains");
        messages.put("control.whitelist.placeholder", "Enter whitelist domains");
        messages.put("control.whitelist.enable", "Enable Whitelist");
        
        // Table headers
        messages.put("table.scan.results", "Scan Results");
        messages.put("table.payload.details", "Parameter Test Details");
        messages.put("table.column.id", "ID");
        messages.put("table.column.url", "URL");
        messages.put("table.column.state", "State");
        messages.put("table.column.params", "Params");
        messages.put("table.column.time", "Time");
        messages.put("table.column.param", "Parameter");
        messages.put("table.column.payload", "Payload");
        messages.put("table.column.change", "Change");
        messages.put("table.column.length", "Length");
        messages.put("table.column.response.time", "Response Time");
        messages.put("table.column.status", "Status Code");
        
        // HTTP editors
        messages.put("editor.request", "Request");
        messages.put("editor.response", "Response");
        
        // Configuration tabs
        messages.put("config.custom.sql", "Custom SQL");
        messages.put("config.param.filter", "Param Filter");
        messages.put("config.response.filter", "Response Filter");
        messages.put("config.custom.error", "Custom Errors");
        messages.put("config.time.threshold", "Time Threshold");
        messages.put("config.length.diff", "Length Diff");
        messages.put("config.url.blacklist", "URL Blacklist");
        messages.put("config.delay", "Delay Config");
        messages.put("config.append.params", "Append Params");
        messages.put("config.advanced", "Advanced");
        messages.put("config.language", "Language");
        
        // Context menu
        messages.put("menu.pause.test", "Pause Test");
        messages.put("menu.resume.test", "Resume Test");
        messages.put("menu.delete.test", "Delete Test");
        messages.put("menu.pause.all", "Pause All");
        messages.put("menu.delete.payload", "Delete Result");
        messages.put("menu.retest.payload", "Retest Payload");
        messages.put("menu.send.to.dousql.current", "Send to DouSQL (Current Group)");
        messages.put("menu.send.to.dousql.select", "Send to DouSQL (Select Group)");
        
        // Messages and hints
        messages.put("message.scan.paused", "Scan paused, skipping payload test");
        messages.put("message.scan.resumed", "Scan resumed");
        messages.put("message.requests.paused", "Paused %d current requests");
        messages.put("message.new.requests.normal", "New requests will be tested normally");
        messages.put("message.single.resume.hint", "You can resume specific requests by right-clicking individual requests");
        
        // Dialog titles
        messages.put("dialog.scan.control", "Scan Control");
        messages.put("dialog.confirm", "Confirm");
        messages.put("dialog.error", "Error");
        messages.put("dialog.success", "Success");
        messages.put("dialog.warning", "Warning");
        messages.put("dialog.info", "Information");
        
        // Buttons
        messages.put("button.ok", "OK");
        messages.put("button.cancel", "Cancel");
        messages.put("button.save", "Save");
        messages.put("button.load", "Load");
        messages.put("button.reset", "Reset");
        messages.put("button.add", "Add");
        messages.put("button.edit", "Edit");
        messages.put("button.delete", "Delete");
        
        // Config panel buttons and labels
        messages.put("button.new.group", "New");
        messages.put("button.rename.group", "Rename");
        messages.put("button.delete.group", "Delete");
        messages.put("button.save.payload", "Save Payload");
        messages.put("button.reload.payload", "Reload Payload");
        messages.put("button.reset.payload.default", "Reset to Default");
        messages.put("button.reset.default", "Reset to Default");
        messages.put("button.save.error.config", "Save Error Config");
        messages.put("button.save.time.config", "Save Time Config");
        messages.put("button.save.length.config", "Save Length Config");
        messages.put("button.save.param.config", "Save Param Config");
        messages.put("button.save.blacklist.config", "Save Blacklist Config");
        messages.put("button.clear.append.params", "Clear & Disable");
        messages.put("button.apply.delay.config", "Apply Delay Config (Session)");
        messages.put("button.open.config.dir", "Open Config Dir");
        messages.put("button.reload.all.config", "Reload All Config");
        messages.put("button.add.condition", "Add Condition");
        messages.put("button.edit.condition", "Edit Condition");
        messages.put("button.delete.condition", "Delete Condition");
        messages.put("button.save.config", "Save Config");
        
        // Label texts
        messages.put("label.config.file.hint", "Save after modifying payload, reload when switching groups (Config file: %s)");
        messages.put("label.test.group", "Test Group:");
        messages.put("label.error.keywords", "Error Keywords Config (one keyword or regex per line)");
        messages.put("label.response.time.threshold", "Response Time Threshold (ms):");
        messages.put("label.request.timeout", "Request Timeout (ms):");
        messages.put("label.length.diff.threshold", "Length Diff Threshold (bytes):");
        messages.put("label.param.list", "Parameter List (one parameter name per line)");
        messages.put("label.append.params", "Parameter List (format: key:value, one per line):");
        messages.put("label.test.switch", "Select parameters for payload testing:");
        messages.put("label.append.params.hint", "<html><i>Enter parameters on the left, test options will be generated on the right</i></html>");
        messages.put("label.fixed.delay", "Fixed Delay Time (ms):");
        messages.put("label.random.delay.min", "Random Delay Min (ms):");
        messages.put("label.random.delay.max", "Random Delay Max (ms):");
        messages.put("label.config.directory", "Config Directory:");
        messages.put("label.condition.type", "Condition Type:");
        messages.put("label.header.name", "Header Name:");
        messages.put("label.compare.operation", "Compare Operation:");
        messages.put("label.compare.value", "Compare Value:");
        
        // Checkbox texts
        messages.put("checkbox.custom.payload", "Custom Payload");
        messages.put("checkbox.url.encode.spaces", "Spaces to +");
        messages.put("checkbox.empty.param.values", "Empty Param Values");
        messages.put("checkbox.enable.custom.error", "Enable Custom Error Messages (Config file: %s)");
        messages.put("checkbox.enable.append.params", "Enable Custom Append Parameters (Takes effect immediately)");
        messages.put("checkbox.enable.response.filter", "Enable Response Filter");
        messages.put("checkbox.enable.condition", "Enable This Condition");
        messages.put("checkbox.param.test", "%s (value: %s)");
        
        // Border titles
        messages.put("border.append.params.config", "Append Parameters Config");
        messages.put("border.test.switch", "Test Switch");
        
        // 语言设置
        messages.put("language.chinese", "中文");
        messages.put("language.english", "English");
        messages.put("language.switch.success", "Language switched successfully! Please close and reopen the DouSQL tab to see the complete language change.");
        
        // Response filter related
        messages.put("checkbox.enable.response.filter", "Enable Response Filter");
        messages.put("label.condition.type", "Condition Type:");
        messages.put("label.header.name", "Header Name:");
        messages.put("label.compare.operation", "Compare Operation:");
        messages.put("label.compare.value", "Compare Value:");
        messages.put("checkbox.enable.condition", "Enable This Condition");
        
        // Placeholder texts
        messages.put("placeholder.new.group.name", "New Group Name");
        
        // Filter modes
        messages.put("filter.mode.none", "No Filter (Test All Parameters)");
        messages.put("filter.mode.whitelist", "Whitelist Mode (Test Only Configured Parameters)");
        messages.put("filter.mode.blacklist", "Blacklist Mode (Skip Configured Parameters)");
        
        // Delay modes
        messages.put("delay.mode.none", "No Delay (Send Immediately)");
        messages.put("delay.mode.fixed", "Fixed Delay");
        messages.put("delay.mode.random", "Random Delay");
    }
}
