package burp;

import ui.DouSqlUI;
import config.DouSqlConfig;
import utils.HttpUtils;
import utils.PayloadUtils;
import utils.UrlUtils;
import utils.I18nManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DouSQL Burp扩展主类
 * 参照RVScan实现，使用Legacy Burp API解决render渲染问题
 */
public class BurpExtender implements IBurpExtender, IScannerCheck, IContextMenuFactory, IHttpListener {

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public DouSqlUI ui;
    public DouSqlConfig config;
    public I18nManager i18n; // 国际化管理器
    
    // 核心工具类
    public HttpUtils httpUtils;
    public PayloadUtils payloadUtils;
    public UrlUtils urlUtils;
    
    // 扩展信息
    public static final String EXTENSION_NAME = "DouSQL-AnQuanYa";
    public static final String VERSION = "3.0.9";
    
    // 配置变量
    public volatile boolean isEnabled = true;
    public volatile boolean monitorRepeater = false;
    public volatile boolean monitorProxy = false;
    public volatile boolean testCookie = false;
    public volatile boolean processNumbers = true;
    
    // 扫描控制变量
    public volatile boolean scanningPaused = false;
    public Set<String> pausedRequests = ConcurrentHashMap.newKeySet(); // 存储被暂停的请求MD5
    
    // 自定义payload配置变量
    public volatile boolean customPayloadEnabled = false; // 自定义payload开关
    public volatile boolean urlEncodeSpaces = true; // 空格替换为+开关
    public volatile boolean emptyParameterValues = false; // 参数值置空开关
    
    // 白名单配置
    public volatile boolean whitelistEnabled = false;
    public String whitelistDomains = "";
    
    // 线程安全的数据存储
    public Set<String> processedUrls = ConcurrentHashMap.newKeySet();
    public Set<String> processedRequestFingerprints = ConcurrentHashMap.newKeySet();
    public Map<String, Integer> originalResponseLengths = new ConcurrentHashMap<>();
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // 设置扩展名称
        callbacks.setExtensionName(EXTENSION_NAME);
        
        // 初始化工具类
        initializeUtils();
        
        // 初始化配置
        initializeConfig();
        
        // 创建UI
        SwingUtilities.invokeLater(this::initializeUI);
        
        // 注册扫描器和上下文菜单
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);
        
        // 输出启动信息
        callbacks.printOutput("===========================================");
        callbacks.printOutput("=====    DouSQL v" + VERSION + " 启动成功        =====");
        callbacks.printOutput("=====    Author: DarkFi5 | 安全鸭      =====");
        callbacks.printOutput("===========================================");
        
       
    }
   
             
    
    /**
     * 初始化工具类
     */
    private void initializeUtils() {
        this.i18n = new I18nManager(callbacks); // 首先初始化国际化管理器
        this.httpUtils = new HttpUtils(this);
        this.payloadUtils = new PayloadUtils(this);
        this.urlUtils = new UrlUtils(this);
    }
    
    /**
     * 初始化配置
     */
    private void initializeConfig() {
        this.config = new DouSqlConfig(this);
        config.loadAllConfigs();
    }
    
    /**
     * 初始化UI
     */
    private void initializeUI() {
        try {
            //callbacks.printOutput("开始创建UI对象...");
            this.ui = new DouSqlUI(this);
            //callbacks.printOutput("UI对象创建完成，准备注册标签页...");
            
            // 确保UI完全初始化后再注册标签页
            SwingUtilities.invokeLater(() -> {
                try {
                    callbacks.addSuiteTab(ui);
                    //callbacks.printOutput("标签页注册完成 - 应该能看到DouSQL标签页了");
                } catch (Exception e) {
                    //callbacks.printError("标签页注册失败: " + e.getMessage());
                    e.printStackTrace();
                }
            });
            
            //callbacks.printOutput("UI初始化完成");
        } catch (Exception e) {
            //callbacks.printError("UI初始化失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // 被动扫描逻辑 - 保留但不使用，主要逻辑在processHttpMessage中
        return null;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        
        if (!isEnabled) {
            callbacks.printOutput("插件未启用，跳过HTTP消息处理");
            return;
        }
        
        // 检查工具标识 - 根据配置监听不同的工具
        int targetFlags = 0;
        if (monitorRepeater) targetFlags |= IBurpExtenderCallbacks.TOOL_REPEATER;
        if (monitorProxy) targetFlags |= IBurpExtenderCallbacks.TOOL_PROXY;
        
        // 如果没有启用任何监听，则不处理
        if (targetFlags == 0) {
            return;
        }
        
        // 检查是否是目标工具的流量
        if ((toolFlag & targetFlags) == 0) {
            return;
        }
        
        // 只处理响应
        if (!messageIsRequest) {
            // callbacks.printOutput("=== HTTP消息处理 ===");
            // callbacks.printOutput("工具标识: " + toolFlag + " (" + callbacks.getToolName(toolFlag) + ")");
            // callbacks.printOutput("URL: " + helpers.analyzeRequest(messageInfo).getUrl());
            
            // 在新线程中处理，避免阻塞Burp
            Thread thread = new Thread(() -> {
                try {
                    httpUtils.processHttpRequest(messageInfo, toolFlag);
                } catch (Exception ex) {
                   // callbacks.printError("HTTP消息处理失败: " + ex.getMessage());
                    ex.printStackTrace();
                }
            });
            thread.start();
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // 主动扫描 - 暂不实现
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        // 获取选中的请求
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages == null || selectedMessages.length == 0) {
            return menuItems;
        }
        
        // 创建菜单项
        JMenuItem sendToDouSql = new JMenuItem(i18n.getText("menu.send.to.dousql.current"));
        sendToDouSql.addActionListener(new SendToDouSqlAction(selectedMessages, null));
        menuItems.add(sendToDouSql);
        
        // 添加payload组选择菜单
        if (payloadUtils.getPayloadGroups().size() > 1) {
            JMenu payloadGroupMenu = new JMenu(i18n.getText("menu.send.to.dousql.select"));
            for (String group : payloadUtils.getPayloadGroups()) {
                JMenuItem groupItem = new JMenuItem(group);
                groupItem.addActionListener(new SendToDouSqlAction(selectedMessages, group));
                payloadGroupMenu.add(groupItem);
            }
            menuItems.add(payloadGroupMenu);
        }
        
        return menuItems;
    }
    
    /**
     * 检查是否在白名单中
     */
    private boolean isInWhitelist(IHttpRequestResponse requestResponse) {
        if (!whitelistEnabled || whitelistDomains.isEmpty()) {
            return true;
        }
        
        try {
            String host = helpers.analyzeRequest(requestResponse).getUrl().getHost();
            String[] domains = whitelistDomains.split(",");
            
            for (String domain : domains) {
                domain = domain.trim().replace(".", "\\.").replace("*", ".*");
                if (host.matches(domain)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return true; // 出错时允许通过
        }
    }
    
    /**
     * 右键菜单动作类
     */
    private class SendToDouSqlAction implements ActionListener {
        private final IHttpRequestResponse[] messages;
        private final String payloadGroup;
        
        public SendToDouSqlAction(IHttpRequestResponse[] messages, String payloadGroup) {
            this.messages = messages;
            this.payloadGroup = payloadGroup;
        }
        
        @Override
        public void actionPerformed(ActionEvent e) {
            // callbacks.printOutput("=== 右键菜单动作执行 ===");
            // callbacks.printOutput("处理 " + messages.length + " 个请求");
            // callbacks.printOutput("目标Payload组: " + (payloadGroup != null ? payloadGroup : "当前组"));
            
            // 在新线程中处理，避免阻塞UI
            Thread processingThread = new Thread(() -> {
                for (int i = 0; i < messages.length; i++) {
                    IHttpRequestResponse message = messages[i];
                 //   callbacks.printOutput("处理第 " + (i + 1) + " 个请求");
                    
                    try {
                        // 编码修复
                        IHttpRequestResponse fixedMessage = httpUtils.fixEncodingIssues(message);
                        
                        // 处理请求
                        if (payloadGroup != null) {
                           // callbacks.printOutput("使用指定组处理: " + payloadGroup);
                            httpUtils.processWithPayloadGroup(fixedMessage, payloadGroup);
                        } else {
                          //  callbacks.printOutput("使用当前组处理");
                            httpUtils.processHttpRequest(fixedMessage, 1024);
                        }
                        
                        //callbacks.printOutput("第 " + (i + 1) + " 个请求处理完成");
                    } catch (Exception ex) {
                        callbacks.printError("处理右键发送请求失败 [" + (i + 1) + "]: " + ex.getMessage());
                        ex.printStackTrace();
                    }
                }
                
               // callbacks.printOutput("=== 右键菜单动作执行完成 ===");
            });
            
            processingThread.setName("DouSQL-RightClick-Processing");
            processingThread.start();
        }
    }
}
