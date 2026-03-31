package ui;

import burp.*;
import config.DouSqlConfig;
import utils.LogEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * DouSQL UI界面类
 * 参照RVScan的Tags.java实现，使用Legacy API解决render问题
 */
public class DouSqlUI implements ITab, IMessageEditorController {
    
    private final BurpExtender burpExtender;
    private final IBurpExtenderCallbacks callbacks;
    
    // UI组件
    private JSplitPane mainSplitPane;
    private JTabbedPane mainTabs;
    
    // 表格相关
    public JTable scanResultsTable;
    public JTable payloadDetailsTable;
    public ScanResultsTableModel scanResultsModel;
    public PayloadDetailsTableModel payloadDetailsModel;
    
    // HTTP编辑器 - 使用Legacy API
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private IHttpRequestResponse currentDisplayedItem;
    
    // 数据存储
    public final List<LogEntry> scanResults = Collections.synchronizedList(new ArrayList<>());
    public final List<LogEntry> payloadDetails = Collections.synchronizedList(new ArrayList<>());
    
    // 当前选中的扫描结果MD5，用于过滤payload详情显示
    private String currentSelectedScanMd5 = null;

    // 行高亮颜色
    private static final Color HIGHLIGHT_SCAN_VULNERABLE = new Color(255, 228, 228);
    private static final Color HIGHLIGHT_PAYLOAD_BOOL = new Color(232, 245, 233);
    private static final Color HIGHLIGHT_PAYLOAD_ERR = new Color(255, 249, 196);
    private static final Color HIGHLIGHT_PAYLOAD_TIME = new Color(255, 228, 228);
    
    // 控制面板组件
    private JCheckBox enablePluginCheckBox;
    private JCheckBox monitorRepeaterCheckBox;
    private JCheckBox monitorProxyCheckBox;
    private JCheckBox testCookieCheckBox;
    private JCheckBox processNumbersCheckBox;
    
    private JTextField whitelistTextField;
    private JButton whitelistButton;
    private JButton clearListButton;
    private JButton loadPayloadButton;
    
    // 配置面板
    private JTabbedPane configTabs;
    
    public DouSqlUI(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.callbacks;
        
        //callbacks.printOutput("DouSqlUI构造函数开始...");
        
        // 直接在当前线程中初始化UI，而不是异步
        initializeUI();
        
        //callbacks.printOutput("DouSqlUI构造函数完成");
    }
    
    /**
     * 初始化UI - 按照原始三层布局结构
     */
    private void initializeUI() {
        try {
            //callbacks.printOutput("开始初始化UI组件...");
            
            // 创建主分割面板 - 第一层：左右分割（内容区域 + 控制面板）
            mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            //callbacks.printOutput("主分割面板创建完成");
            
            // 创建表格区域 - 左右分割（扫描结果表格 + Payload详情表格）
            JSplitPane tablesSplitPane = createTablesPanel();
            //callbacks.printOutput("表格区域创建完成");
            
            // 创建HTTP编辑器面板
            JSplitPane httpEditorsSplitPane = createHttpEditorsPanel();
            //callbacks.printOutput("HTTP编辑器创建完成");
            
            // 第二层：splitPanes - 左侧内容区域的上下分割（表格区域 + HTTP编辑器）
            JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            splitPanes.setTopComponent(tablesSplitPane);
            splitPanes.setBottomComponent(httpEditorsSplitPane);
            splitPanes.setDividerLocation(400);
            splitPanes.setResizeWeight(0.6);
            //callbacks.printOutput("左侧内容区域分割面板创建完成");
            
            // 创建控制面板
            JPanel controlPanel = createControlPanel();
            //callbacks.printOutput("控制面板创建完成");
            
            // 创建配置标签页
            JTabbedPane configTabs = createConfigTabs();
            //callbacks.printOutput("配置标签页创建完成");
            
            // 第三层：splitPanes2 - 右侧面板的上下分割（控制面板 + 配置标签页）
            JSplitPane splitPanes2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            splitPanes2.setTopComponent(controlPanel);
            splitPanes2.setBottomComponent(configTabs);
            splitPanes2.setDividerLocation(280);
            splitPanes2.setResizeWeight(0.0);
            //callbacks.printOutput("右侧面板分割面板创建完成");
            
            // 第一层：主分割面板 - 左右分割（主内容区域 + 右侧面板）
            mainSplitPane.setLeftComponent(splitPanes);
            mainSplitPane.setRightComponent(splitPanes2);
            mainSplitPane.setDividerLocation(1000);
            mainSplitPane.setResizeWeight(0.75);
            //callbacks.printOutput("主分割面板配置完成");
            
            // 应用主题
            callbacks.customizeUiComponent(mainSplitPane);
            callbacks.customizeUiComponent(splitPanes);
            callbacks.customizeUiComponent(splitPanes2);
            callbacks.customizeUiComponent(tablesSplitPane);
            callbacks.customizeUiComponent(httpEditorsSplitPane);
            //callbacks.printOutput("主题应用完成");
            
            //callbacks.printOutput("DouSQL UI组件初始化完成 - 使用原始三层布局结构");
            
        } catch (Exception e) {
            callbacks.printError("UI初始化失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 创建左侧面板（表格+HTTP编辑器）
     */
    private Component createLeftPanel() {
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        
        // 上部：表格区域
        leftSplitPane.setTopComponent(createTablesPanel());
        
        // 下部：HTTP编辑器
        leftSplitPane.setBottomComponent(createHttpEditorsPanel());
        
        leftSplitPane.setDividerLocation(400);
        leftSplitPane.setResizeWeight(0.6);
        
        return leftSplitPane;
    }
    
    /**
     * 创建表格面板 - 按照原始布局结构，添加3.0.6版本的右键菜单功能
     */
    private JSplitPane createTablesPanel() {
        JSplitPane tablesSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 左侧：扫描结果表格
        scanResultsModel = new ScanResultsTableModel();
        scanResultsTable = new ScanResultsTable(scanResultsModel);
        
        // 添加3.0.6版本的右键菜单功能 - 扫描结果表格
        addScanResultsContextMenu(scanResultsTable);
        
        JScrollPane scanResultsScrollPane = new JScrollPane(scanResultsTable);
        
        JPanel scanResultsPanel = new JPanel(new BorderLayout());
        scanResultsPanel.setBorder(BorderFactory.createTitledBorder(burpExtender.i18n.getText("table.scan.results")));
        scanResultsPanel.add(scanResultsScrollPane, BorderLayout.CENTER);
        
        // 右侧：Payload详情表格
        payloadDetailsModel = new PayloadDetailsTableModel();
        payloadDetailsTable = new PayloadDetailsTable(payloadDetailsModel);
        
        // 添加3.0.6版本的右键菜单功能 - Payload详情表格
        addPayloadDetailsContextMenu(payloadDetailsTable);
        
        JScrollPane payloadDetailsScrollPane = new JScrollPane(payloadDetailsTable);
        
        JPanel payloadDetailsPanel = new JPanel(new BorderLayout());
        payloadDetailsPanel.setBorder(BorderFactory.createTitledBorder(burpExtender.i18n.getText("table.payload.details")));
        payloadDetailsPanel.add(payloadDetailsScrollPane, BorderLayout.CENTER);
        
        tablesSplitPane.setLeftComponent(scanResultsPanel);
        tablesSplitPane.setRightComponent(payloadDetailsPanel);
        tablesSplitPane.setDividerLocation(0.5);
        tablesSplitPane.setResizeWeight(0.5);
        
        return tablesSplitPane;
    }
    
    /**
     * 创建HTTP编辑器面板 - 按照原始布局结构使用Legacy API
     */
    private JSplitPane createHttpEditorsPanel() {
        JSplitPane editorsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 创建请求编辑器 - 使用Legacy API
        requestEditor = callbacks.createMessageEditor(this, false);
        
        // 创建响应编辑器 - 使用Legacy API
        responseEditor = callbacks.createMessageEditor(this, false);
        
        // 按照原始方式：使用带标题的面板而不是JTabbedPane
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder(burpExtender.i18n.getText("editor.request")));
        requestPanel.add(requestEditor.getComponent(), BorderLayout.CENTER);
        
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder(burpExtender.i18n.getText("editor.response")));
        responsePanel.add(responseEditor.getComponent(), BorderLayout.CENTER);
        
        editorsSplitPane.setLeftComponent(requestPanel);
        editorsSplitPane.setRightComponent(responsePanel);
        editorsSplitPane.setDividerLocation(0.5);
        editorsSplitPane.setResizeWeight(0.5);
        
        //callbacks.printOutput("HTTP编辑器创建完成 - 使用Legacy API和原始布局");
        
        // 测试HTTP编辑器功能
        testHttpEditors();
        
        return editorsSplitPane;
    }
    
    /**
     * 创建右侧控制面板
     */
    private Component createRightPanel() {
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        
        // 上部：控制面板
        rightSplitPane.setTopComponent(createControlPanel());
        
        // 下部：配置标签页
        rightSplitPane.setBottomComponent(createConfigTabs());
        
        rightSplitPane.setDividerLocation(280);
        rightSplitPane.setResizeWeight(0.0);
        
        return rightSplitPane;
    }
    
    /**
     * 创建控制面板 - 按照原始布局结构，移除payload加载按钮
     */
    private JPanel createControlPanel() {
        JPanel controlPanel = new JPanel(new BorderLayout());
        controlPanel.setBorder(BorderFactory.createTitledBorder(burpExtender.i18n.getText("control.panel")));
        
        // 创建控制选项面板 - 使用GridBagLayout确保跨平台兼容性
        JPanel controlOptionsPanel = new JPanel(new GridBagLayout());
        controlOptionsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(2, 5, 2, 5);
        
        int row = 0;
        
        // 标题
        JLabel titleLabel = new JLabel(burpExtender.i18n.getText("plugin.title"));
        gbc.gridy = row++;
        controlOptionsPanel.add(titleLabel, gbc);
        
        // 注册标题组件
        registerI18nComponent("plugin.title", titleLabel);
        
        // 基本控制复选框组
        enablePluginCheckBox = new JCheckBox(burpExtender.i18n.getText("control.enable.plugin"), true);
        gbc.gridy = row++;
        gbc.insets = new Insets(3, 5, 1, 5);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        controlOptionsPanel.add(enablePluginCheckBox, gbc);
        
        monitorRepeaterCheckBox = new JCheckBox(burpExtender.i18n.getText("control.monitor.repeater"), false);
        gbc.gridy = row++;
        gbc.insets = new Insets(1, 5, 1, 5);
        controlOptionsPanel.add(monitorRepeaterCheckBox, gbc);
        
        monitorProxyCheckBox = new JCheckBox(burpExtender.i18n.getText("control.monitor.proxy"), false);
        gbc.gridy = row++;
        controlOptionsPanel.add(monitorProxyCheckBox, gbc);
        
        processNumbersCheckBox = new JCheckBox(burpExtender.i18n.getText("control.process.numbers"), true);
        gbc.gridy = row++;
        controlOptionsPanel.add(processNumbersCheckBox, gbc);
        
        testCookieCheckBox = new JCheckBox(burpExtender.i18n.getText("control.test.cookie"), false);
        gbc.gridy = row++;
        controlOptionsPanel.add(testCookieCheckBox, gbc);
        
        // 清空列表按钮 - 设置固定尺寸
        clearListButton = new JButton(burpExtender.i18n.getText("control.clear.list"));
        clearListButton.setPreferredSize(new Dimension(140, 25)); // 增加宽度以适应英文
        clearListButton.setMinimumSize(new Dimension(140, 25));
        clearListButton.setMaximumSize(new Dimension(140, 25));
        gbc.gridy = row++;
        gbc.insets = new Insets(8, 5, 3, 5);
        controlOptionsPanel.add(clearListButton, gbc);
        
        // 白名单配置区域
        JLabel whitelistLabel = new JLabel(burpExtender.i18n.getText("control.whitelist.hint"));
        gbc.gridy = row++;
        gbc.insets = new Insets(5, 5, 2, 5);
        controlOptionsPanel.add(whitelistLabel, gbc);
        
        // 注册白名单提示标签
        registerI18nComponent("control.whitelist.hint", whitelistLabel);
        
        whitelistTextField = new JTextField(burpExtender.i18n.getText("control.whitelist.placeholder"));
        whitelistTextField.setPreferredSize(new Dimension(220, 25));
        whitelistTextField.setMinimumSize(new Dimension(180, 25));
        whitelistTextField.setMaximumSize(new Dimension(300, 25));
        whitelistTextField.setBorder(BorderFactory.createLoweredBevelBorder());
        gbc.gridy = row++;
        gbc.insets = new Insets(2, 5, 2, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        controlOptionsPanel.add(whitelistTextField, gbc);
        
        whitelistButton = new JButton(burpExtender.i18n.getText("control.whitelist.enable"));
        whitelistButton.setPreferredSize(new Dimension(140, 25)); // 增加宽度
        whitelistButton.setMinimumSize(new Dimension(140, 25));
        whitelistButton.setMaximumSize(new Dimension(140, 25));
        gbc.gridy = row++;
        gbc.insets = new Insets(2, 5, 3, 5);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        controlOptionsPanel.add(whitelistButton, gbc);
        
        // 添加弹性空间，但减少权重避免过多空白
        gbc.gridy = row++;
        gbc.weighty = 0.1;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        controlOptionsPanel.add(Box.createVerticalStrut(10), gbc);
        
        controlPanel.add(controlOptionsPanel, BorderLayout.CENTER);
        
        // 设置事件监听器
        setupControlPanelListeners();
        
        return controlPanel;
    }
    
    /**
     * 创建配置标签页 - 恢复完整功能，添加延时发包独立tab
     */
    private JTabbedPane createConfigTabs() {
        configTabs = new JTabbedPane();
        configTabs.setPreferredSize(new Dimension(250, 400));
        configTabs.setMinimumSize(new Dimension(200, 300));
        
        // 创建各个配置面板
        configTabs.addTab(burpExtender.i18n.getText("config.custom.sql"), createCustomSqlPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.param.filter"), createParamFilterPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.response.filter"), createResponseFilterPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.custom.error"), createCustomErrorPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.time.threshold"), createResponseTimePanel());
        configTabs.addTab(burpExtender.i18n.getText("config.length.diff"), createLengthDiffPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.url.blacklist"), createUrlBlacklistPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.delay"), createDelayConfigPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.append.params"), createAppendParamsPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.advanced"), createAdvancedConfigPanel());
        configTabs.addTab("SQLMap", createSqlmapConfigPanel());
        configTabs.addTab(burpExtender.i18n.getText("config.language"), createLanguagePanel());
        
        return configTabs;
    }
    
    /**
     * 创建自定义SQL语句面板 - 按照原始布局，包含payload组管理和加载按钮
     */
    private Component createCustomSqlPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // 顶部控制面板 - 包含组管理和选项
        JPanel topControlPanel = new JPanel();
        topControlPanel.setLayout(new BoxLayout(topControlPanel, BoxLayout.Y_AXIS));
        topControlPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // 配置文件路径说明
        String configPath = burpExtender.config.getConfigDirectory() + "/xia_SQL_diy_payload.ini";
        JLabel configLabel = new JLabel(burpExtender.i18n.getText("label.config.file.hint", configPath));
        configLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        topControlPanel.add(configLabel);
        topControlPanel.add(Box.createVerticalStrut(5));
        
        // 注册需要更新的组件
        registerI18nComponent("label.config.file.hint", configLabel);
        
        // Payload组管理区域
        JPanel groupPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbcGroup = new GridBagConstraints();
        gbcGroup.insets = new Insets(2, 2, 2, 2);
        gbcGroup.anchor = GridBagConstraints.WEST;
        
        JLabel groupLabel = new JLabel(burpExtender.i18n.getText("label.test.group"));
        JComboBox<String> groupComboBox = new JComboBox<>();
        // 加载payload组
        for (String group : burpExtender.payloadUtils.getPayloadGroups()) {
            groupComboBox.addItem(group);
        }
        groupComboBox.setPreferredSize(new Dimension(80, 25));
        
        JTextField newGroupNameField = new JTextField(burpExtender.i18n.getText("placeholder.new.group.name"));
        newGroupNameField.setPreferredSize(new Dimension(80, 25));
        
        // 注册新组名文本框
        registerI18nComponent("placeholder.new.group.name", newGroupNameField);
        
        JButton newGroupButton = new JButton(burpExtender.i18n.getText("button.new.group"));
        JButton renameGroupButton = new JButton(burpExtender.i18n.getText("button.rename.group"));
        JButton deleteGroupButton = new JButton(burpExtender.i18n.getText("button.delete.group"));
        
        // 注册按钮组件
        registerI18nComponent("label.test.group", groupLabel);
        registerI18nComponent("button.new.group", newGroupButton);
        registerI18nComponent("button.rename.group", renameGroupButton);
        registerI18nComponent("button.delete.group", deleteGroupButton);
        
        // 设置按钮大小
        Dimension buttonSize = new Dimension(60, 25);
        newGroupButton.setPreferredSize(buttonSize);
        renameGroupButton.setPreferredSize(new Dimension(70, 25));
        deleteGroupButton.setPreferredSize(buttonSize);
        
        // 第一行：标签和下拉框
        gbcGroup.gridx = 0; gbcGroup.gridy = 0;
        groupPanel.add(groupLabel, gbcGroup);
        gbcGroup.gridx = 1;
        groupPanel.add(groupComboBox, gbcGroup);
        gbcGroup.gridx = 2;
        groupPanel.add(newGroupNameField, gbcGroup);
        
        // 第二行：按钮组
        gbcGroup.gridx = 0; gbcGroup.gridy = 1;
        groupPanel.add(newGroupButton, gbcGroup);
        gbcGroup.gridx = 1;
        groupPanel.add(renameGroupButton, gbcGroup);
        gbcGroup.gridx = 2;
        groupPanel.add(deleteGroupButton, gbcGroup);
        
        groupPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        topControlPanel.add(groupPanel);
        topControlPanel.add(Box.createVerticalStrut(5));
        
        // 自定义payload选项
        JCheckBox customPayloadCheckBox = new JCheckBox(burpExtender.i18n.getText("checkbox.custom.payload"));
        JCheckBox urlEncodeCheckBox = new JCheckBox(burpExtender.i18n.getText("checkbox.url.encode.spaces"), true);
        JCheckBox emptyValueCheckBox = new JCheckBox(burpExtender.i18n.getText("checkbox.empty.param.values"));
        
        // 注册复选框组件
        registerI18nComponent("checkbox.custom.payload", customPayloadCheckBox);
        registerI18nComponent("checkbox.url.encode.spaces", urlEncodeCheckBox);
        registerI18nComponent("checkbox.empty.param.values", emptyValueCheckBox);
        
        customPayloadCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        urlEncodeCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        emptyValueCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        topControlPanel.add(customPayloadCheckBox);
        topControlPanel.add(urlEncodeCheckBox);
        topControlPanel.add(emptyValueCheckBox);
        topControlPanel.add(Box.createVerticalStrut(5));
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JButton savePayloadButton = new JButton(burpExtender.i18n.getText("button.save.payload"));
        JButton loadPayloadButton = new JButton(burpExtender.i18n.getText("button.reload.payload"));
        JButton resetPayloadButton = new JButton(burpExtender.i18n.getText("button.reset.payload.default"));
        
        // 注册按钮组件
        registerI18nComponent("button.save.payload", savePayloadButton);
        registerI18nComponent("button.reload.payload", loadPayloadButton);
        registerI18nComponent("button.reset.payload.default", resetPayloadButton);
        
        savePayloadButton.setPreferredSize(new Dimension(120, 25));
        loadPayloadButton.setPreferredSize(new Dimension(140, 25));
        resetPayloadButton.setPreferredSize(new Dimension(120, 25));
        
        buttonPanel.add(savePayloadButton);
        buttonPanel.add(loadPayloadButton);
        buttonPanel.add(resetPayloadButton);
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        topControlPanel.add(buttonPanel);
        
        // Payload编辑区域
        JTextArea payloadArea = new JTextArea(15, 50);
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadArea.setForeground(Color.BLACK);
        payloadArea.setBackground(Color.LIGHT_GRAY);
        
        // 加载当前组的payload
        StringBuilder sb = new StringBuilder();
        for (String payload : burpExtender.payloadUtils.getCurrentPayloads()) {
            sb.append(payload).append("\n");
        }
        payloadArea.setText(sb.toString());
        
        JScrollPane scrollPane = new JScrollPane(payloadArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Payload列表（每行一个）"));
        
        // 事件监听器
        // 新建组按钮
        newGroupButton.addActionListener(e -> {
            String newGroupName = newGroupNameField.getText().trim();
            String placeholder = burpExtender.i18n.getText("placeholder.new.group.name");
            if (newGroupName.isEmpty() || newGroupName.equals(placeholder)) {
                JOptionPane.showMessageDialog(panel, "请输入有效的组名", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if (burpExtender.payloadUtils.addPayloadGroup(newGroupName)) {
                // 更新下拉框
                groupComboBox.addItem(newGroupName);
                groupComboBox.setSelectedItem(newGroupName);
                
                // 切换到新组
                burpExtender.payloadUtils.switchToGroup(newGroupName);
                
                // 清空payload区域（新组默认为空）
                payloadArea.setText("");
                
                // 清空输入框
                newGroupNameField.setText(burpExtender.i18n.getText("placeholder.new.group.name"));
                
                JOptionPane.showMessageDialog(panel, "成功创建新组: " + newGroupName, "成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(panel, "创建组失败，可能组名已存在", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        // 重命名组按钮
        renameGroupButton.addActionListener(e -> {
            String currentGroup = (String) groupComboBox.getSelectedItem();
            String newGroupName = newGroupNameField.getText().trim();
            String placeholder = burpExtender.i18n.getText("placeholder.new.group.name");
            
            if (currentGroup == null) {
                JOptionPane.showMessageDialog(panel, "请选择要重命名的组", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if (newGroupName.isEmpty() || newGroupName.equals(placeholder)) {
                JOptionPane.showMessageDialog(panel, "请输入有效的新组名", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if (burpExtender.payloadUtils.renamePayloadGroup(currentGroup, newGroupName)) {
                // 更新下拉框
                groupComboBox.removeItem(currentGroup);
                groupComboBox.addItem(newGroupName);
                groupComboBox.setSelectedItem(newGroupName);
                
                // 清空输入框
                newGroupNameField.setText(burpExtender.i18n.getText("placeholder.new.group.name"));
                
                JOptionPane.showMessageDialog(panel, "成功重命名组: " + currentGroup + " -> " + newGroupName, "成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(panel, "重命名失败", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        // 删除组按钮
        deleteGroupButton.addActionListener(e -> {
            String currentGroup = (String) groupComboBox.getSelectedItem();
            
            if (currentGroup == null) {
                JOptionPane.showMessageDialog(panel, "请选择要删除的组", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if ("default".equals(currentGroup)) {
                JOptionPane.showMessageDialog(panel, "不能删除默认组", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            int result = JOptionPane.showConfirmDialog(panel, 
                "确定要删除组 '" + currentGroup + "' 吗？\n删除后该组的所有payload将丢失。", 
                "确认删除", 
                JOptionPane.YES_NO_OPTION, 
                JOptionPane.WARNING_MESSAGE);
            
            if (result == JOptionPane.YES_OPTION) {
                if (burpExtender.payloadUtils.deletePayloadGroup(currentGroup)) {
                    // 从下拉框中移除
                    groupComboBox.removeItem(currentGroup);
                    
                    // 切换到默认组
                    groupComboBox.setSelectedItem("default");
                    burpExtender.payloadUtils.switchToGroup("default");
                    
                    // 重新加载payload显示
                    StringBuilder newSb = new StringBuilder();
                    for (String payload : burpExtender.payloadUtils.getCurrentPayloads()) {
                        newSb.append(payload).append("\n");
                    }
                    payloadArea.setText(newSb.toString());
                    
                    JOptionPane.showMessageDialog(panel, "成功删除组: " + currentGroup, "成功", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(panel, "删除失败", "错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        
        // 组切换事件监听器
        groupComboBox.addActionListener(e -> {
            String selectedGroup = (String) groupComboBox.getSelectedItem();
            if (selectedGroup != null && !selectedGroup.equals(burpExtender.payloadUtils.getCurrentGroup())) {
                callbacks.printOutput("正在切换到payload组: " + selectedGroup);
                burpExtender.payloadUtils.switchToGroup(selectedGroup);
                
                // 重新加载payload显示
                StringBuilder newSb = new StringBuilder();
                List<String> currentPayloads = burpExtender.payloadUtils.getCurrentPayloads();
                callbacks.printOutput("当前组 '" + selectedGroup + "' 有 " + currentPayloads.size() + " 个payload");
                
                for (String payload : currentPayloads) {
                    newSb.append(payload).append("\n");
                }
                payloadArea.setText(newSb.toString());
                callbacks.printOutput("已切换到payload组: " + selectedGroup + "，payload列表已更新");
            }
        });
        
        customPayloadCheckBox.addItemListener(e -> {
            boolean enabled = customPayloadCheckBox.isSelected();
            burpExtender.customPayloadEnabled = enabled;
            payloadArea.setEditable(enabled);
            if (enabled) {
                payloadArea.setBackground(Color.WHITE);
            } else {
                payloadArea.setBackground(Color.LIGHT_GRAY);
            }
        });
        
        urlEncodeCheckBox.addItemListener(e -> {
            burpExtender.urlEncodeSpaces = urlEncodeCheckBox.isSelected();
            callbacks.printOutput("空格替换为+: " + (burpExtender.urlEncodeSpaces ? "启用" : "禁用"));
        });
        
        emptyValueCheckBox.addItemListener(e -> {
            burpExtender.emptyParameterValues = emptyValueCheckBox.isSelected();
            callbacks.printOutput("参数值置空: " + (burpExtender.emptyParameterValues ? "启用" : "禁用"));
        });
        
        loadPayloadButton.addActionListener(e -> {
            String currentGroup = (String) groupComboBox.getSelectedItem();
            if (currentGroup != null) {
                burpExtender.payloadUtils.switchToGroup(currentGroup);
            }
            burpExtender.payloadUtils.reloadPayloads();
            // 重新加载payload显示
            StringBuilder newSb = new StringBuilder();
            for (String payload : burpExtender.payloadUtils.getCurrentPayloads()) {
                newSb.append(payload).append("\n");
            }
            payloadArea.setText(newSb.toString());
            JOptionPane.showMessageDialog(panel, "Payload已重新加载", "成功", JOptionPane.INFORMATION_MESSAGE);
        });
        
        savePayloadButton.addActionListener(e -> {
            if (!customPayloadCheckBox.isSelected()) {
                JOptionPane.showMessageDialog(panel, "请先勾选'自定义payload'以启用编辑功能", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            String payloadContent = payloadArea.getText();
            if (payloadContent.trim().isEmpty()) {
                JOptionPane.showMessageDialog(panel, "Payload内容不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            try {
                burpExtender.payloadUtils.saveCurrentGroupPayloads(payloadContent);
                JOptionPane.showMessageDialog(panel, "Payload保存成功", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        resetPayloadButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(panel, 
                "确定要重置当前组的payload为默认值吗？\n当前的自定义payload将丢失。", 
                "确认重置", 
                JOptionPane.YES_NO_OPTION, 
                JOptionPane.WARNING_MESSAGE);
            
            if (result == JOptionPane.YES_OPTION) {
                burpExtender.payloadUtils.resetCurrentGroupToDefault();
                
                // 重新加载payload显示
                StringBuilder newSb = new StringBuilder();
                for (String payload : burpExtender.payloadUtils.getCurrentPayloads()) {
                    newSb.append(payload).append("\n");
                }
                payloadArea.setText(newSb.toString());
                
                JOptionPane.showMessageDialog(panel, "已重置为默认payload", "成功", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        panel.add(topControlPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建自定义报错信息面板 - 添加启用复选框和配置文件路径
     */
    private Component createCustomErrorPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 顶部：启用复选框和配置文件路径
        String configPath = burpExtender.config.getConfigDirectory() + "/xia_SQL_diy_error.ini";
        JCheckBox enableCustomErrorCheckBox = new JCheckBox(burpExtender.i18n.getText("checkbox.enable.custom.error", configPath), true);
        enableCustomErrorCheckBox.setPreferredSize(new Dimension(400, 25));
        
        // 注册启用复选框
        registerI18nComponent("checkbox.enable.custom.error", enableCustomErrorCheckBox);
        
        JPanel enablePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enablePanel.add(enableCustomErrorCheckBox);
        
        // 中间：编辑区域
        JPanel errorTextPanel = new JPanel(new BorderLayout());
        errorTextPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        
        JLabel errorLabel = new JLabel(burpExtender.i18n.getText("label.error.keywords"));
        errorLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
        
        // 注册组件
        registerI18nComponent("label.error.keywords", errorLabel);
        
        JTextArea errorKeywordsTextArea = new JTextArea(15, 50);
        errorKeywordsTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        errorKeywordsTextArea.setForeground(Color.BLACK);
        errorKeywordsTextArea.setBackground(Color.WHITE);
        errorKeywordsTextArea.setEditable(true);
        
        // 加载当前错误关键字
        StringBuilder sb = new StringBuilder();
        for (String keyword : burpExtender.config.getErrorKeywords()) {
            sb.append(keyword).append("\n");
        }
        errorKeywordsTextArea.setText(sb.toString());
        
        JScrollPane errorScrollPane = new JScrollPane(errorKeywordsTextArea);
        
        // 底部：保存按钮
        JButton saveErrorBtn = new JButton(burpExtender.i18n.getText("button.save.error.config"));
        saveErrorBtn.setPreferredSize(new Dimension(150, 30));
        
        // 注册按钮
        registerI18nComponent("button.save.error.config", saveErrorBtn);
        
        JPanel errorButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        errorButtonPanel.add(saveErrorBtn);
        
        errorTextPanel.add(errorLabel, BorderLayout.NORTH);
        errorTextPanel.add(errorScrollPane, BorderLayout.CENTER);
        errorTextPanel.add(errorButtonPanel, BorderLayout.SOUTH);
        
        // 事件监听器
        enableCustomErrorCheckBox.addItemListener(e -> {
            boolean enabled = enableCustomErrorCheckBox.isSelected();
            errorKeywordsTextArea.setEditable(enabled);
            saveErrorBtn.setEnabled(enabled);
            if (enabled) {
                errorKeywordsTextArea.setBackground(Color.WHITE);
            } else {
                errorKeywordsTextArea.setBackground(Color.LIGHT_GRAY);
            }
        });
        
        saveErrorBtn.addActionListener(e -> {
            try {
                String errorText = errorKeywordsTextArea.getText().trim();
                List<String> keywords = new ArrayList<>();
                
                if (!errorText.isEmpty()) {
                    String[] lines = errorText.split("\n");
                    for (String line : lines) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            keywords.add(line);
                        }
                    }
                }
                
                burpExtender.config.saveErrorKeywords(keywords);
                
                JOptionPane.showMessageDialog(panel, 
                    "报错信息配置保存成功！\n" +
                    "关键字数量: " + keywords.size() + "条", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
                    
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        panel.add(enablePanel, BorderLayout.NORTH);
        panel.add(errorTextPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建时间阈值配置面板（包含响应时间阈值和请求超时时间）
     */
    private Component createResponseTimePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        int row = 0;
        
        // 响应时间阈值
        gbc.gridx = 0; gbc.gridy = row;
        JLabel responseTimeLabel = new JLabel(burpExtender.i18n.getText("label.response.time.threshold"));
        panel.add(responseTimeLabel, gbc);
        
        JTextField responseTimeField = new JTextField(String.valueOf(burpExtender.config.getResponseTimeThreshold()));
        gbc.gridx = 1; gbc.gridy = row++;
        gbc.weightx = 1.0;
        panel.add(responseTimeField, gbc);
        
        // 请求超时时间
        gbc.gridx = 0; gbc.gridy = row;
        gbc.weightx = 0.0;
        JLabel requestTimeoutLabel = new JLabel(burpExtender.i18n.getText("label.request.timeout"));
        panel.add(requestTimeoutLabel, gbc);
        
        JTextField requestTimeoutField = new JTextField(String.valueOf(burpExtender.config.getRequestTimeout()));
        gbc.gridx = 1; gbc.gridy = row++;
        gbc.weightx = 1.0;
        panel.add(requestTimeoutField, gbc);
        
        // 注册组件
        registerI18nComponent("label.response.time.threshold", responseTimeLabel);
        registerI18nComponent("label.request.timeout", requestTimeoutLabel);
        
        // 说明文本
        JTextArea descArea = new JTextArea(
            "说明：\n\n" +
            "【响应时间阈值】\n" +
            "• 用途：检测时间盲注，当响应时间超过此阈值时标记为TIME\n" +
            "• 默认：5000毫秒(5秒)\n" +
            "• 建议：根据目标服务器性能调整，一般设置为3000-8000毫秒\n" +
            "• 注意：设置过小可能产生误报，设置过大可能遗漏漏洞\n\n" +
            "【请求超时时间】\n" +
            "• 用途：请求超时控制，超过此时间直接丢弃请求\n" +
            "• 默认：30000毫秒(30秒)\n" +
            "• 建议：内网环境10-15秒，外网环境30-60秒\n" +
            "• 注意：超时的请求会被标记为timeout>xx秒\n\n" +
            "【配置建议】\n" +
            "• 请求超时时间应该大于响应时间阈值（建议5倍以上）\n" +
            "• 快速扫描：响应时间1秒，超时5秒\n" +
            "• 慢速目标：响应时间5秒，超时60秒"
        );
        descArea.setEditable(false);
        descArea.setBackground(panel.getBackground());
        descArea.setBorder(BorderFactory.createTitledBorder("使用说明"));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        
        gbc.gridx = 0; gbc.gridy = row++;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(descArea, gbc);
        
        // 保存按钮
        JButton saveButton = new JButton(burpExtender.i18n.getText("button.save.time.config"));
        
        // 注册按钮
        registerI18nComponent("button.save.time.config", saveButton);
        saveButton.addActionListener(e -> {
            try {
                int responseTime = Integer.parseInt(responseTimeField.getText().trim());
                int timeout = Integer.parseInt(requestTimeoutField.getText().trim());
                
                // 验证输入
                if (responseTime < 100) {
                    JOptionPane.showMessageDialog(panel, "响应时间阈值不能小于100毫秒", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (timeout < 1000) {
                    JOptionPane.showMessageDialog(panel, "请求超时时间不能小于1000毫秒", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (timeout <= responseTime) {
                    JOptionPane.showMessageDialog(panel, 
                        "请求超时时间应该大于响应时间阈值\n建议超时时间至少是响应时间阈值的5倍", 
                        "警告", JOptionPane.WARNING_MESSAGE);
                    // 不return，允许保存但给出警告
                }
                
                // 保存配置
                burpExtender.config.saveTimeThresholdConfig(responseTime, timeout);
                
                JOptionPane.showMessageDialog(panel, 
                    "时间阈值配置保存成功！\n" +
                    "响应时间阈值: " + responseTime + "毫秒 (" + (responseTime/1000.0) + "秒)\n" +
                    "请求超时时间: " + timeout + "毫秒 (" + (timeout/1000.0) + "秒)", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(panel, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        gbc.gridy = row++;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(saveButton, gbc);
        
        return new JScrollPane(panel);
    }
    
    /**
     * 创建长度差异配置面板
     */
    private Component createLengthDiffPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        int row = 0;
        
        // 长度差异阈值
        gbc.gridx = 0; gbc.gridy = row;
        JLabel lengthDiffLabel = new JLabel(burpExtender.i18n.getText("label.length.diff.threshold"));
        panel.add(lengthDiffLabel, gbc);
        
        JTextField lengthDiffField = new JTextField(String.valueOf(burpExtender.config.getLengthDiffThreshold()));
        gbc.gridx = 1; gbc.gridy = row++;
        gbc.weightx = 1.0;
        panel.add(lengthDiffField, gbc);
        
        // 注册组件
        registerI18nComponent("label.length.diff.threshold", lengthDiffLabel);
        
        // 说明文本
        JTextArea descArea = new JTextArea(
            "说明：\n" +
            "1. 当payload响应长度与原始响应长度差异超过此阈值时，标记为可能的布尔盲注\n" +
            "2. 建议根据目标页面大小调整\n" +
            "3. 设置过小可能产生误报，设置过大可能遗漏漏洞\n" +
            "4. 对于动态内容较多的页面，可以适当增大阈值\n" +
            "5. 结合多个payload的响应长度变化进行综合判断"
        );
        descArea.setEditable(false);
        descArea.setBackground(panel.getBackground());
        descArea.setBorder(BorderFactory.createTitledBorder("使用说明"));
        
        gbc.gridx = 0; gbc.gridy = row++;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(descArea, gbc);
        
        // 保存按钮
        JButton saveButton = new JButton(burpExtender.i18n.getText("button.save.length.config"));
        
        // 注册按钮
        registerI18nComponent("button.save.length.config", saveButton);
        saveButton.addActionListener(e -> {
            try {
                int lengthDiff = Integer.parseInt(lengthDiffField.getText().trim());
                if (lengthDiff < 0) {
                    JOptionPane.showMessageDialog(panel, "长度差异阈值不能小于0", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                burpExtender.config.setLengthDiffThreshold(lengthDiff);
                burpExtender.config.saveLengthDiffThreshold(lengthDiff);
                JOptionPane.showMessageDialog(panel, "长度差异配置保存成功", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(panel, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        gbc.gridy = row++;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(saveButton, gbc);
        
        return new JScrollPane(panel);
    }
    
    /**
     * 创建参数过滤面板 - 竖向布局，不使用左右分割
     */
    private Component createParamFilterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 过滤模式选择 - 竖向排列
        JPanel modePanel = new JPanel(new GridLayout(3, 1, 5, 5));
        modePanel.setBorder(BorderFactory.createTitledBorder("过滤模式"));
        
        ButtonGroup modeGroup = new ButtonGroup();
        JRadioButton noFilterRadio = new JRadioButton(burpExtender.i18n.getText("filter.mode.none"), burpExtender.config.getParamFilterMode() == 0);
        JRadioButton whitelistRadio = new JRadioButton(burpExtender.i18n.getText("filter.mode.whitelist"), burpExtender.config.getParamFilterMode() == 1);
        JRadioButton blacklistRadio = new JRadioButton(burpExtender.i18n.getText("filter.mode.blacklist"), burpExtender.config.getParamFilterMode() == 2);
        
        // 注册过滤模式选项
        registerI18nComponent("filter.mode.none", noFilterRadio);
        registerI18nComponent("filter.mode.whitelist", whitelistRadio);
        registerI18nComponent("filter.mode.blacklist", blacklistRadio);
        
        modeGroup.add(noFilterRadio);
        modeGroup.add(whitelistRadio);
        modeGroup.add(blacklistRadio);
        
        modePanel.add(noFilterRadio);
        modePanel.add(whitelistRadio);
        modePanel.add(blacklistRadio);
        
        // 参数配置编辑区
        JPanel paramAreaPanel = new JPanel(new BorderLayout());
        JLabel paramListLabel = new JLabel(burpExtender.i18n.getText("label.param.list"));
        paramListLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        
        // 注册组件
        registerI18nComponent("label.param.list", paramListLabel);
        
        JTextArea paramListTextArea = new JTextArea(15, 30);
        paramListTextArea.setForeground(Color.BLACK);
        paramListTextArea.setFont(new Font("宋体", Font.PLAIN, 13));
        paramListTextArea.setBackground(Color.WHITE);
        paramListTextArea.setEditable(true);
        
        // 根据当前模式加载对应的参数列表
        StringBuilder sb = new StringBuilder();
        if (burpExtender.config.getParamFilterMode() == 1) {
            // 白名单模式
            for (String param : burpExtender.config.getWhitelistParams()) {
                sb.append(param).append("\n");
            }
        } else if (burpExtender.config.getParamFilterMode() == 2) {
            // 黑名单模式
            for (String param : burpExtender.config.getBlacklistParams()) {
                sb.append(param).append("\n");
            }
        }
        paramListTextArea.setText(sb.toString());
        
        JScrollPane paramListScrollPane = new JScrollPane(paramListTextArea);
        
        // 按钮区
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        JButton saveParamListBtn = new JButton(burpExtender.i18n.getText("button.save.param.config"));
        
        // 注册按钮
        registerI18nComponent("button.save.param.config", saveParamListBtn);
        
        buttonPanel.add(saveParamListBtn);
        
        paramAreaPanel.add(paramListLabel, BorderLayout.NORTH);
        paramAreaPanel.add(paramListScrollPane, BorderLayout.CENTER);
        paramAreaPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // 模式切换事件监听器
        noFilterRadio.addActionListener(e -> {
            paramListTextArea.setText("");
            paramListTextArea.setEditable(false);
            paramListTextArea.setBackground(Color.LIGHT_GRAY);
        });
        
        whitelistRadio.addActionListener(e -> {
            StringBuilder whiteSb = new StringBuilder();
            for (String param : burpExtender.config.getWhitelistParams()) {
                whiteSb.append(param).append("\n");
            }
            paramListTextArea.setText(whiteSb.toString());
            paramListTextArea.setEditable(true);
            paramListTextArea.setBackground(Color.WHITE);
        });
        
        blacklistRadio.addActionListener(e -> {
            StringBuilder blackSb = new StringBuilder();
            for (String param : burpExtender.config.getBlacklistParams()) {
                blackSb.append(param).append("\n");
            }
            paramListTextArea.setText(blackSb.toString());
            paramListTextArea.setEditable(true);
            paramListTextArea.setBackground(Color.WHITE);
        });
        
        // 保存按钮事件监听器
        saveParamListBtn.addActionListener(e -> {
            // 获取选中的模式
            int mode = 0;
            if (whitelistRadio.isSelected()) mode = 1;
            else if (blacklistRadio.isSelected()) mode = 2;
            
            // 解析参数列表
            String paramText = paramListTextArea.getText().trim();
            List<String> paramList = new ArrayList<>();
            if (!paramText.isEmpty()) {
                String[] lines = paramText.split("\n");
                for (String line : lines) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        paramList.add(line);
                    }
                }
            }
            
            // 根据模式保存到对应的列表，保留另一个列表的现有配置
            List<String> whitelistParams = new ArrayList<>(burpExtender.config.getWhitelistParams());
            List<String> blacklistParams = new ArrayList<>(burpExtender.config.getBlacklistParams());
            
            if (mode == 1) {
                // 保存白名单，保留黑名单
                whitelistParams.clear();
                whitelistParams.addAll(paramList);
            } else if (mode == 2) {
                // 保存黑名单，保留白名单
                blacklistParams.clear();
                blacklistParams.addAll(paramList);
            }
            
            // 保存配置
            try {
                burpExtender.config.saveParamFilterConfig(mode, whitelistParams, blacklistParams);
                
                String modeText = mode == 0 ? "无过滤" : (mode == 1 ? "白名单" : "黑名单");
                JOptionPane.showMessageDialog(panel, 
                    "参数过滤配置保存成功！\n" +
                    "过滤模式: " + modeText + "\n" +
                    "当前编辑参数数量: " + paramList.size() + "个\n" +
                    "白名单参数: " + whitelistParams.size() + "个\n" +
                    "黑名单参数: " + blacklistParams.size() + "个", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, 
                    "保存失败: " + ex.getMessage(), 
                    "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        // 初始化状态
        if (burpExtender.config.getParamFilterMode() == 0) {
            paramListTextArea.setEditable(false);
            paramListTextArea.setBackground(Color.LIGHT_GRAY);
        }
        
        panel.add(modePanel, BorderLayout.NORTH);
        panel.add(paramAreaPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建黑名单URL过滤面板 - 简化按钮，只保留保存和重置，加载现有配置
     */
    private Component createUrlBlacklistPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // 黑名单URL列表
        JTextArea urlArea = new JTextArea(15, 50);
        urlArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        // 加载现有的黑名单配置
        List<String> existingBlacklist = burpExtender.config.getUrlBlacklist();
        StringBuilder initialContent = new StringBuilder();
        initialContent.append("# URL黑名单配置（每行一个，支持通配符）\n");
        initialContent.append("# 示例：\n");
        initialContent.append("# */admin/*\n");
        initialContent.append("# */static/*\n");
        initialContent.append("# *.css\n");
        initialContent.append("# *.js\n");
        initialContent.append("\n");
        
        if (!existingBlacklist.isEmpty()) {
            initialContent.append("# 当前配置的黑名单规则：\n");
            for (String rule : existingBlacklist) {
                initialContent.append(rule).append("\n");
            }
        } else {
            initialContent.append("# 当前没有配置黑名单规则\n");
            initialContent.append("# 请在下方添加需要过滤的URL模式\n");
        }
        
        urlArea.setText(initialContent.toString());
        
        JScrollPane scrollPane = new JScrollPane(urlArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("黑名单URL列表（支持通配符 * 和 ?）"));
        
        // 按钮面板 - 只保留保存和重置按钮
        JPanel buttonPanel = new JPanel(new FlowLayout());
        
        JButton saveButton = new JButton(burpExtender.i18n.getText("button.save.blacklist.config"));
        
        // 注册按钮
        registerI18nComponent("button.save.blacklist.config", saveButton);
        saveButton.addActionListener(e -> {
            try {
                String urlText = urlArea.getText().trim();
                List<String> blacklist = new ArrayList<>();
                
                if (!urlText.isEmpty()) {
                    String[] lines = urlText.split("\n");
                    for (String line : lines) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            blacklist.add(line);
                        }
                    }
                }
                
                burpExtender.config.saveUrlBlacklist(blacklist);
                
                JOptionPane.showMessageDialog(panel, 
                    "URL黑名单配置保存成功！\n" +
                    "黑名单条目: " + blacklist.size() + "条", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
                    
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        JButton resetButton = new JButton(burpExtender.i18n.getText("button.reset.default"));
        
        // 注册按钮
        registerI18nComponent("button.reset.default", resetButton);
        resetButton.addActionListener(e -> {
            urlArea.setText(
                "# URL黑名单配置（每行一个，支持通配符）\n" +
                "# 示例：\n" +
                "*/admin/*\n" +
                "*/static/*\n" +
                "*/assets/*\n" +
                "*/js/*\n" +
                "*/css/*\n" +
                "*/images/*\n"
            );
        });
        
        buttonPanel.add(saveButton);
        buttonPanel.add(resetButton);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建追加参数配置面板 - 改进版本：动态参数映射，启用即保存
     */
    private Component createAppendParamsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        Map<String, String> savedAppendParams = burpExtender.config.getAppendParams();
        Set<String> savedTestableParams = new HashSet<>(burpExtender.config.getTestableAppendParams());
        boolean savedAppendEnabled = burpExtender.config.isAppendParamsEnabled();
        final boolean[] suppressAppendConfigSave = {false};
        
        // 顶部：启用追加参数复选框
        JCheckBox enableAppendParamsCheckBox = new JCheckBox(burpExtender.i18n.getText("checkbox.enable.append.params"), savedAppendEnabled);
        
        // 注册组件
        registerI18nComponent("checkbox.enable.append.params", enableAppendParamsCheckBox);
        JPanel enablePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enablePanel.add(enableAppendParamsCheckBox);
        
        // 主要配置区域 - 左右分割
        JSplitPane configSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        configSplitPane.setResizeWeight(0.6); // 左边占60%
        
        // 左侧：参数配置面板
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder(burpExtender.i18n.getText("border.append.params.config")));
        
        JLabel paramLabel = new JLabel(burpExtender.i18n.getText("label.append.params"));
        
        // 注册组件
        registerI18nComponent("label.append.params", paramLabel);
        leftPanel.add(paramLabel, BorderLayout.NORTH);
        
        JTextArea appendParamsTextArea = new JTextArea(12, 25);
        appendParamsTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        appendParamsTextArea.setBorder(BorderFactory.createLoweredBevelBorder());
        StringBuilder appendParamsInitialText = new StringBuilder();
        appendParamsInitialText.append("# 追加参数配置（格式：key:value，每行一个）\n");
        appendParamsInitialText.append("# 示例：\n");
        appendParamsInitialText.append("# token:abc123\n");
        if (!savedAppendParams.isEmpty()) {
            appendParamsInitialText.append("\n");
            for (Map.Entry<String, String> entry : savedAppendParams.entrySet()) {
                appendParamsInitialText.append(entry.getKey()).append(":").append(entry.getValue()).append("\n");
            }
        }
        appendParamsTextArea.setText(appendParamsInitialText.toString());
        
        JScrollPane leftScrollPane = new JScrollPane(appendParamsTextArea);
        leftScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        leftScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        leftPanel.add(leftScrollPane, BorderLayout.CENTER);
        
        // 右侧：参数测试开关面板
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder(burpExtender.i18n.getText("border.test.switch")));
        
        JLabel testLabel = new JLabel(burpExtender.i18n.getText("label.test.switch"));
        
        // 注册组件
        registerI18nComponent("label.test.switch", testLabel);
        rightPanel.add(testLabel, BorderLayout.NORTH);
        
        // 动态生成的参数勾选框面板
        JPanel paramTestPanel = new JPanel();
        paramTestPanel.setLayout(new BoxLayout(paramTestPanel, BoxLayout.Y_AXIS));
        
        // 初始提示
        JLabel emptyLabel = new JLabel(burpExtender.i18n.getText("label.append.params.hint"));
        
        // 注册组件
        registerI18nComponent("label.append.params.hint", emptyLabel);
        emptyLabel.setBorder(BorderFactory.createEmptyBorder(10, 5, 5, 5));
        paramTestPanel.add(emptyLabel);
        
        JScrollPane rightScrollPane = new JScrollPane(paramTestPanel);
        rightScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        rightScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        rightPanel.add(rightScrollPane, BorderLayout.CENTER);
        
        configSplitPane.setLeftComponent(leftPanel);
        configSplitPane.setRightComponent(rightPanel);
        
        // 底部按钮面板 - 只保留清除按钮
        JPanel appendParamsButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton clearAppendParamsBtn = new JButton(burpExtender.i18n.getText("button.clear.append.params"));
        
        // 注册按钮
        registerI18nComponent("button.clear.append.params", clearAppendParamsBtn);
        clearAppendParamsBtn.setToolTipText("完全清除追加参数配置并禁用功能");
        appendParamsButtonPanel.add(clearAppendParamsBtn);
        
        // 说明文本
        JTextArea helpText = new JTextArea(
            "说明：\n" +
            "1. 启用后，会在每个请求中自动追加指定的参数\n" +
            "2. 支持URL参数、POST参数、JSON参数等格式\n" +
            "3. 参数格式：每行一个参数，使用 key:value 格式\n" +
            "4. 示例：token:abc123、debug:1、test:value\n" +
            "5. 右侧可单独控制每个参数是否参与payload测试\n" +
            "6. 不参与测试时避免重复检测，参与测试时可发现更多漏洞\n" +
            "7. 参数会根据请求格式自动适配添加方式", 6, 30);
        helpText.setEditable(false);
        helpText.setBackground(panel.getBackground());
        helpText.setFont(new Font("宋体", Font.PLAIN, 12));
        helpText.setBorder(BorderFactory.createTitledBorder("使用说明"));
        
        // 保存配置的方法
        Runnable saveCurrentConfig = () -> {
            if (suppressAppendConfigSave[0]) {
                return;
            }

            // 解析参数文本
            String paramText = appendParamsTextArea.getText().trim();
            Map<String, String> currentParams = new HashMap<>();
            
            if (!paramText.isEmpty()) {
                String[] lines = paramText.split("\n");
                for (String line : lines) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            String key = parts[0].trim();
                            String value = parts[1].trim();
                            currentParams.put(key, value);
                        }
                    }
                }
            }
            
            // 获取当前勾选的测试参数
            Set<String> testableParams = new HashSet<>();
            for (Component comp : paramTestPanel.getComponents()) {
                if (comp instanceof JCheckBox) {
                    JCheckBox cb = (JCheckBox) comp;
                    if (cb.isSelected()) {
                        String text = cb.getText();
                        String paramName = text.split(" \\(")[0];
                        testableParams.add(paramName);
                    }
                }
            }

            savedTestableParams.clear();
            savedTestableParams.addAll(testableParams);
            
            burpExtender.config.saveAppendParamsConfig(enableAppendParamsCheckBox.isSelected(), currentParams, testableParams);
            
            callbacks.printOutput("=== UI保存追加参数配置 ===");
            callbacks.printOutput("启用状态: " + enableAppendParamsCheckBox.isSelected());
            callbacks.printOutput("参数数量: " + currentParams.size());
            callbacks.printOutput("可测试参数数量: " + testableParams.size());
            for (String testableParam : testableParams) {
                callbacks.printOutput("可测试参数: " + testableParam);
            }
            callbacks.printOutput("=== UI保存完成 ===");
        };
        
        // 动态参数映射方法
        Runnable updateParameterCheckboxes = () -> {
            Set<String> selectedParams = new HashSet<>();
            for (Component comp : paramTestPanel.getComponents()) {
                if (comp instanceof JCheckBox) {
                    JCheckBox cb = (JCheckBox) comp;
                    if (cb.isSelected()) {
                        String text = cb.getText();
                        selectedParams.add(text.split(" \\(")[0]);
                    }
                }
            }
            if (selectedParams.isEmpty()) {
                selectedParams.addAll(savedTestableParams);
            }

            // 清空现有的复选框
            paramTestPanel.removeAll();
            
            // 解析参数文本
            String currentParamText = appendParamsTextArea.getText().trim();
            Map<String, String> currentParams = new HashMap<>();
            
            if (!currentParamText.isEmpty()) {
                String[] lines = currentParamText.split("\n");
                for (String line : lines) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            String key = parts[0].trim();
                            String value = parts[1].trim();
                            currentParams.put(key, value);
                        }
                    }
                }
            }
            
            if (currentParams.isEmpty()) {
                JLabel noParamsLabel = new JLabel(burpExtender.i18n.getText("label.append.params.hint"));
                noParamsLabel.setBorder(BorderFactory.createEmptyBorder(10, 5, 5, 5));
                paramTestPanel.add(noParamsLabel);
            } else {
                for (Map.Entry<String, String> entry : currentParams.entrySet()) {
                    String paramName = entry.getKey();
                    String paramValue = entry.getValue();
                    JCheckBox paramCheckBox = new JCheckBox(burpExtender.i18n.getText("checkbox.param.test", paramName, paramValue), selectedParams.contains(paramName));
                    paramCheckBox.setToolTipText("勾选后该参数会参与payload测试");
                    paramCheckBox.addItemListener(e -> SwingUtilities.invokeLater(saveCurrentConfig));
                    paramTestPanel.add(paramCheckBox);
                }
            }
            
            paramTestPanel.revalidate();
            paramTestPanel.repaint();
            
            saveCurrentConfig.run();
        };
        
        // 事件监听器
        enableAppendParamsCheckBox.addItemListener(e -> {
            boolean enabled = enableAppendParamsCheckBox.isSelected();
            
            // 根据启用状态控制文本框的可编辑性
            appendParamsTextArea.setEditable(!enabled);
            if (enabled) {
                // 启用时：文本框不可编辑，背景变灰
                appendParamsTextArea.setBackground(Color.LIGHT_GRAY);
                // 保存当前配置
                saveCurrentConfig.run();
            } else {
                // 禁用时：文本框可编辑，背景变白
                appendParamsTextArea.setBackground(Color.WHITE);
                // 保存禁用状态，但保留已有配置内容
                saveCurrentConfig.run();
            }
        });
        
        // 文本变化监听器 - 实时更新参数映射（无论是否启用都更新显示）
        appendParamsTextArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                SwingUtilities.invokeLater(updateParameterCheckboxes);
            }
            
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                SwingUtilities.invokeLater(updateParameterCheckboxes);
            }
            
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                SwingUtilities.invokeLater(updateParameterCheckboxes);
            }
        });
        
        // 清除配置按钮事件
        clearAppendParamsBtn.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(panel, 
                "确定要清除追加参数配置并禁用功能吗？", 
                "确认清除", 
                JOptionPane.YES_NO_OPTION, 
                JOptionPane.WARNING_MESSAGE);
            
            if (result == JOptionPane.YES_OPTION) {
                try {
                    suppressAppendConfigSave[0] = true;
                    // 清除配置
                    burpExtender.config.clearAppendParamsConfig();
                    
                    // 重置UI状态
                    enableAppendParamsCheckBox.setSelected(false);
                    appendParamsTextArea.setText(
                        "# 追加参数配置（格式：key:value，每行一个）\n" +
                        "# 示例：\n" +
                        "# token:abc123\n"
                    );
                    // 清除后恢复可编辑状态
                    appendParamsTextArea.setEditable(true);
                    appendParamsTextArea.setBackground(Color.WHITE);
                    
                    // 清空右侧面板，重新显示初始提示
                    paramTestPanel.removeAll();
                    JLabel resetLabel = new JLabel("<html><i>请在左侧输入参数，右侧会自动生成对应的测试选项</i></html>");
                    resetLabel.setBorder(BorderFactory.createEmptyBorder(10, 5, 5, 5));
                    paramTestPanel.add(resetLabel);
                    paramTestPanel.revalidate();
                    paramTestPanel.repaint();
                    
                    JOptionPane.showMessageDialog(panel, 
                        "追加参数配置已清除并禁用！", 
                        "清除成功", JOptionPane.INFORMATION_MESSAGE);
                        
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel, "清除失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                } finally {
                    suppressAppendConfigSave[0] = false;
                }
            }
        });
        
        appendParamsTextArea.setEditable(!savedAppendEnabled);
        appendParamsTextArea.setBackground(savedAppendEnabled ? Color.LIGHT_GRAY : Color.WHITE);
        
        // 初始化时更新参数映射显示
        SwingUtilities.invokeLater(updateParameterCheckboxes);
        
        panel.add(enablePanel, BorderLayout.NORTH);
        panel.add(configSplitPane, BorderLayout.CENTER);
        
        // 将说明文本和按钮放在最下方
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(appendParamsButtonPanel, BorderLayout.NORTH);
        bottomPanel.add(helpText, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建延时发包配置面板 - 独立的tab
     */
    private Component createDelayConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        int savedDelayMode = burpExtender.config.getDelayMode();
        int savedFixedDelay = burpExtender.config.getFixedDelay();
        int savedRandomDelayMin = burpExtender.config.getRandomDelayMin();
        int savedRandomDelayMax = burpExtender.config.getRandomDelayMax();
        
        // 延时模式选择
        JPanel delayModePanel = new JPanel(new GridLayout(3, 1, 5, 5));
        delayModePanel.setBorder(BorderFactory.createTitledBorder("延时模式"));
        
        ButtonGroup delayModeGroup = new ButtonGroup();
        JRadioButton noDelayRadio = new JRadioButton(burpExtender.i18n.getText("delay.mode.none"), savedDelayMode == 0);
        JRadioButton fixedDelayRadio = new JRadioButton(burpExtender.i18n.getText("delay.mode.fixed"), savedDelayMode == 1);
        JRadioButton randomDelayRadio = new JRadioButton(burpExtender.i18n.getText("delay.mode.random"), savedDelayMode == 2);
        
        // 注册延时模式选项
        registerI18nComponent("delay.mode.none", noDelayRadio);
        registerI18nComponent("delay.mode.fixed", fixedDelayRadio);
        registerI18nComponent("delay.mode.random", randomDelayRadio);
        
        delayModeGroup.add(noDelayRadio);
        delayModeGroup.add(fixedDelayRadio);
        delayModeGroup.add(randomDelayRadio);
        
        delayModePanel.add(noDelayRadio);
        delayModePanel.add(fixedDelayRadio);
        delayModePanel.add(randomDelayRadio);
        
        // 延时配置面板
        JPanel delaySettingsPanel = new JPanel(new GridBagLayout());
        delaySettingsPanel.setBorder(BorderFactory.createTitledBorder("延时设置"));
        GridBagConstraints gbcDelay = new GridBagConstraints();
        gbcDelay.anchor = GridBagConstraints.WEST;
        gbcDelay.insets = new Insets(5, 5, 5, 5);
        
        // 固定延时配置
        gbcDelay.gridx = 0; gbcDelay.gridy = 0;
        JLabel fixedDelayLabel = new JLabel(burpExtender.i18n.getText("label.fixed.delay"));
        delaySettingsPanel.add(fixedDelayLabel, gbcDelay);
        gbcDelay.gridx = 1;
        JTextField fixedDelayField = new JTextField(String.valueOf(savedFixedDelay), 10);
        delaySettingsPanel.add(fixedDelayField, gbcDelay);
        
        // 随机延时配置
        gbcDelay.gridx = 0; gbcDelay.gridy = 1;
        JLabel randomDelayMinLabel = new JLabel(burpExtender.i18n.getText("label.random.delay.min"));
        delaySettingsPanel.add(randomDelayMinLabel, gbcDelay);
        gbcDelay.gridx = 1;
        JTextField randomDelayMinField = new JTextField(String.valueOf(savedRandomDelayMin), 10);
        delaySettingsPanel.add(randomDelayMinField, gbcDelay);
        
        gbcDelay.gridx = 0; gbcDelay.gridy = 2;
        JLabel randomDelayMaxLabel = new JLabel(burpExtender.i18n.getText("label.random.delay.max"));
        delaySettingsPanel.add(randomDelayMaxLabel, gbcDelay);
        gbcDelay.gridx = 1;
        JTextField randomDelayMaxField = new JTextField(String.valueOf(savedRandomDelayMax), 10);
        delaySettingsPanel.add(randomDelayMaxField, gbcDelay);
        
        // 注册组件
        registerI18nComponent("label.fixed.delay", fixedDelayLabel);
        registerI18nComponent("label.random.delay.min", randomDelayMinLabel);
        registerI18nComponent("label.random.delay.max", randomDelayMaxLabel);
        
        // 保存按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton saveDelayConfigBtn = new JButton(burpExtender.i18n.getText("button.apply.delay.config"));
        
        // 注册按钮
        registerI18nComponent("button.apply.delay.config", saveDelayConfigBtn);
        buttonPanel.add(saveDelayConfigBtn);
        
        // 说明文本
        JTextArea helpText = new JTextArea(
            "说明：\n" +
            "1. 无延时：立即发送所有payload请求\n" +
            "2. 固定延时：每个请求之间固定等待指定时间\n" +
            "3. 随机延时：每个请求之间随机等待指定范围内的时间\n" +
            "4. 延时发包可以避免对目标服务器造成过大压力\n" +
            "5. 建议根据目标服务器性能和网络状况调整延时时间"
        );
        helpText.setEditable(false);
        helpText.setBackground(panel.getBackground());
        helpText.setFont(new Font("宋体", Font.PLAIN, 12));
        helpText.setBorder(BorderFactory.createTitledBorder("使用说明"));
        
        // 事件监听器
        noDelayRadio.addActionListener(e -> {
            fixedDelayField.setEnabled(false);
            randomDelayMinField.setEnabled(false);
            randomDelayMaxField.setEnabled(false);
        });
        
        fixedDelayRadio.addActionListener(e -> {
            fixedDelayField.setEnabled(true);
            randomDelayMinField.setEnabled(false);
            randomDelayMaxField.setEnabled(false);
        });
        
        randomDelayRadio.addActionListener(e -> {
            fixedDelayField.setEnabled(false);
            randomDelayMinField.setEnabled(true);
            randomDelayMaxField.setEnabled(true);
        });
        
        saveDelayConfigBtn.addActionListener(e -> {
            try {
                // 获取选中的模式
                int mode = 0;
                if (fixedDelayRadio.isSelected()) mode = 1;
                else if (randomDelayRadio.isSelected()) mode = 2;
                
                // 获取延时值
                int fixed = Integer.parseInt(fixedDelayField.getText().trim());
                int minRandom = Integer.parseInt(randomDelayMinField.getText().trim());
                int maxRandom = Integer.parseInt(randomDelayMaxField.getText().trim());
                
                // 验证输入
                if (fixed < 0 || minRandom < 0 || maxRandom < 0) {
                    JOptionPane.showMessageDialog(panel, "延时时间不能小于0", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                if (minRandom >= maxRandom) {
                    JOptionPane.showMessageDialog(panel, "随机延时最小值必须小于最大值", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                // 设置配置并持久化
                burpExtender.config.setDelayConfig(mode, fixed, minRandom, maxRandom);
                
                String modeText = mode == 0 ? "无延时" : (mode == 1 ? "固定延时" : "随机延时");
                JOptionPane.showMessageDialog(panel, 
                    "延时配置已保存！\n" +
                    "延时模式: " + modeText + "\n" +
                    "固定延时: " + fixed + "ms\n" +
                    "随机延时: " + minRandom + "-" + maxRandom + "ms", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
                    
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(panel, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "应用失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        fixedDelayField.setEnabled(savedDelayMode == 1);
        randomDelayMinField.setEnabled(savedDelayMode == 2);
        randomDelayMaxField.setEnabled(savedDelayMode == 2);
        
        panel.add(delayModePanel, BorderLayout.NORTH);
        panel.add(delaySettingsPanel, BorderLayout.CENTER);
        
        // 将说明文本和按钮放在最下方
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(buttonPanel, BorderLayout.NORTH);
        bottomPanel.add(helpText, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建高级配置面板
     */
    private Component createAdvancedConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        int row = 0;
        
        // 配置目录显示
        gbc.gridx = 0; gbc.gridy = row;
        JLabel configDirLabel = new JLabel(burpExtender.i18n.getText("label.config.directory"));
        panel.add(configDirLabel, gbc);
        
        // 注册组件
        registerI18nComponent("label.config.directory", configDirLabel);
        
        JTextField configDirField = new JTextField(burpExtender.config.getConfigDirectory());
        configDirField.setEditable(false);
        gbc.gridx = 1; gbc.gridy = row++;
        gbc.weightx = 1.0;
        panel.add(configDirField, gbc);
        
        // 打开配置目录按钮
        JButton openDirButton = new JButton(burpExtender.i18n.getText("button.open.config.dir"));
        
        // 注册按钮
        registerI18nComponent("button.open.config.dir", openDirButton);
        openDirButton.addActionListener(e -> {
            try {
                Desktop.getDesktop().open(new java.io.File(burpExtender.config.getConfigDirectory()));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "无法打开目录: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        gbc.gridx = 0; gbc.gridy = row++;
        gbc.gridwidth = 2;
        gbc.weightx = 0.0;
        panel.add(openDirButton, gbc);
        
        // 重新加载配置按钮
        JButton reloadButton = new JButton(burpExtender.i18n.getText("button.reload.all.config"));
        
        // 注册按钮
        registerI18nComponent("button.reload.all.config", reloadButton);
        reloadButton.addActionListener(e -> {
            burpExtender.config.loadAllConfigs();
            JOptionPane.showMessageDialog(panel, "配置重新加载完成", "成功", JOptionPane.INFORMATION_MESSAGE);
        });
        
        gbc.gridy = row++;
        panel.add(reloadButton, gbc);
        
        // 填充剩余空间
        gbc.gridy = row;
        gbc.weighty = 1.0;
        panel.add(new JPanel(), gbc);
        
        return new JScrollPane(panel);
    }

    /**
     * 创建 SQLMap 配置面板
     */
    private Component createSqlmapConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JTextField sqlmapPathField = new JTextField(burpExtender.config.getSqlmapPath(), 28);
        JTextField pythonPathField = new JTextField(burpExtender.config.getSqlmapPythonPath(), 28);
        JTextField outputDirField = new JTextField(burpExtender.config.getSqlmapOutputDirectory(), 28);
        JTextArea defaultOptionsArea = new JTextArea(burpExtender.config.getSqlmapDefaultOptions(), 5, 28);
        defaultOptionsArea.setLineWrap(true);
        defaultOptionsArea.setWrapStyleWord(true);

        int row = 0;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        panel.add(new JLabel("SQLMap 路径"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(sqlmapPathField, gbc);
        gbc.gridx = 2;
        gbc.weightx = 0;
        JButton browseSqlmapButton = new JButton("浏览");
        browseSqlmapButton.addActionListener(e -> chooseFile(sqlmapPathField, false));
        panel.add(browseSqlmapButton, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(new JLabel("Python 路径"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(pythonPathField, gbc);
        gbc.gridx = 2;
        gbc.weightx = 0;
        JButton browsePythonButton = new JButton("浏览");
        browsePythonButton.addActionListener(e -> chooseFile(pythonPathField, false));
        panel.add(browsePythonButton, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(new JLabel("输出目录"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(outputDirField, gbc);
        gbc.gridx = 2;
        gbc.weightx = 0;
        JButton browseOutputButton = new JButton("浏览");
        browseOutputButton.addActionListener(e -> chooseFile(outputDirField, true));
        panel.add(browseOutputButton, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        panel.add(new JLabel("默认命令参数"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        panel.add(new JScrollPane(defaultOptionsArea), gbc);
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.WEST;

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        JTextArea helpText = new JTextArea(
            "占位符说明:\n" +
            "{requestFile} - 临时生成的原始请求文件\n" +
            "{parameter} - 当前详情行对应的参数名\n" +
            "{outputDir} - SQLMap 输出目录\n\n" +
            "推荐默认参数:\n" +
            "-r {requestFile} -p {parameter} --batch --level 3 --risk 3 --ignore-stdin --output-dir={outputDir}"
        );
        helpText.setEditable(false);
        helpText.setBackground(panel.getBackground());
        helpText.setBorder(BorderFactory.createTitledBorder("说明"));
        panel.add(helpText, gbc);
        gbc.gridwidth = 1;

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton saveButton = new JButton("保存 SQLMap 配置");
        JButton resetButton = new JButton("恢复默认");
        saveButton.addActionListener(e -> {
            burpExtender.config.saveSqlmapConfig(
                sqlmapPathField.getText(),
                pythonPathField.getText(),
                defaultOptionsArea.getText(),
                outputDirField.getText()
            );
            JOptionPane.showMessageDialog(panel, "SQLMap 配置已保存", "成功", JOptionPane.INFORMATION_MESSAGE);
        });
        resetButton.addActionListener(e -> {
            sqlmapPathField.setText("sqlmap.py");
            pythonPathField.setText("python3");
            outputDirField.setText(System.getProperty("java.io.tmpdir") + File.separator + "dousql-sqlmap");
            defaultOptionsArea.setText("-r {requestFile} -p {parameter} --batch --level 3 --risk 3 --ignore-stdin --output-dir={outputDir}");
        });
        buttonPanel.add(saveButton);
        buttonPanel.add(resetButton);
        panel.add(buttonPanel, gbc);

        row++;
        gbc.gridy = row;
        gbc.weighty = 1.0;
        panel.add(new JPanel(), gbc);

        return new JScrollPane(panel);
    }

    private void chooseFile(JTextField targetField, boolean directoriesOnly) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(directoriesOnly ? JFileChooser.DIRECTORIES_ONLY : JFileChooser.FILES_ONLY);
        String currentValue = targetField.getText().trim();
        if (!currentValue.isEmpty()) {
            chooser.setSelectedFile(new File(currentValue));
        }
        if (chooser.showOpenDialog(mainSplitPane) == JFileChooser.APPROVE_OPTION) {
            targetField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }
    
    /**
     * 设置控制面板事件监听器
     */
    private void setupControlPanelListeners() {
        enablePluginCheckBox.addItemListener(e -> {
            burpExtender.isEnabled = enablePluginCheckBox.isSelected();
        });
        
        monitorRepeaterCheckBox.addItemListener(e -> {
            burpExtender.monitorRepeater = monitorRepeaterCheckBox.isSelected();
        });
        
        monitorProxyCheckBox.addItemListener(e -> {
            burpExtender.monitorProxy = monitorProxyCheckBox.isSelected();
        });
        
        testCookieCheckBox.addItemListener(e -> {
            burpExtender.testCookie = testCookieCheckBox.isSelected();
        });
        
        processNumbersCheckBox.addItemListener(e -> {
            burpExtender.processNumbers = processNumbersCheckBox.isSelected();
        });
        
        clearListButton.addActionListener(e -> clearAllResults());
        
        whitelistButton.addActionListener(e -> toggleWhitelist());
    }
    
    /**
     * 清空所有结果
     */
    private void clearAllResults() {
        synchronized (scanResults) {
            scanResults.clear();
        }
        synchronized (payloadDetails) {
            payloadDetails.clear();
        }

        burpExtender.processedRequestFingerprints.clear();
        burpExtender.processedUrls.clear();
        burpExtender.originalResponseLengths.clear();
        
        // 清空选中状态
        currentSelectedScanMd5 = null;
        
        scanResultsModel.fireTableDataChanged();
        payloadDetailsModel.fireTableDataChanged();
        
        // 清空编辑器
        requestEditor.setMessage(new byte[0], true);
        responseEditor.setMessage(new byte[0], false);
        
        callbacks.printOutput("所有结果已清空，包括选中状态");
    }
    
    /**
     * 切换白名单状态
     */
    private void toggleWhitelist() {
        if (burpExtender.whitelistEnabled) {
            burpExtender.whitelistEnabled = false;
            whitelistButton.setText("启动白名单");
            whitelistTextField.setEditable(true);
        } else {
            burpExtender.whitelistEnabled = true;
            burpExtender.whitelistDomains = whitelistTextField.getText();
            whitelistButton.setText("关闭白名单");
            whitelistTextField.setEditable(false);
        }
    }
    
    /**
     * 添加扫描结果
     */
    public void addScanResult(LogEntry entry) {
        callbacks.printOutput("=== addScanResult调用 ===");
        callbacks.printOutput("添加扫描结果: " + entry.getUrl());
        
        synchronized (scanResults) {
            scanResults.add(entry);
            callbacks.printOutput("扫描结果列表大小: " + scanResults.size());
            
            SwingUtilities.invokeLater(() -> {
                try {
                    int newRowIndex = scanResults.size() - 1;
                    callbacks.printOutput("触发表格更新，新行索引: " + newRowIndex);
                    scanResultsModel.fireTableRowsInserted(newRowIndex, newRowIndex);
                    callbacks.printOutput("表格更新完成");
                    
                    // 强制刷新表格显示
                    scanResultsTable.revalidate();
                    scanResultsTable.repaint();
                } catch (Exception e) {
                    callbacks.printError("更新扫描结果表格失败: " + e.getMessage());
                    e.printStackTrace();
                }
            });
        }
    }
    
    /**
     * 添加Payload详情
     */
    public void addPayloadDetail(LogEntry entry) {
        // callbacks.printOutput("=== addPayloadDetail调用 ===");
        // callbacks.printOutput("添加Payload详情: " + entry.getParameter() + " -> " + entry.getPayload());
        // callbacks.printOutput("Payload详情MD5: " + entry.getDataMd5());
        // callbacks.printOutput("当前选中的扫描结果MD5: " + currentSelectedScanMd5);
        
        synchronized (payloadDetails) {
            payloadDetails.add(entry);
            //callbacks.printOutput("Payload详情列表大小: " + payloadDetails.size());
            
            SwingUtilities.invokeLater(() -> {
                try {
                    int newRowIndex = payloadDetails.size() - 1;
                   // callbacks.printOutput("触发Payload详情表格更新，新行索引: " + newRowIndex);
                    payloadDetailsModel.fireTableRowsInserted(newRowIndex, newRowIndex);
                   // callbacks.printOutput("Payload详情表格更新完成");
                    
                    // 强制刷新表格显示
                    payloadDetailsTable.revalidate();
                    payloadDetailsTable.repaint();
                } catch (Exception e) {
                    callbacks.printError("更新Payload详情表格失败: " + e.getMessage());
                    e.printStackTrace();
                }
            });
        }
    }
    
    /**
     * 刷新扫描结果表格 - 3.0.7版本新增
     * 用于在更新LogEntry数据后刷新表格显示
     */
    public void refreshScanResultsTable() {
        SwingUtilities.invokeLater(() -> {
            try {
                scanResultsModel.fireTableDataChanged();
                scanResultsTable.revalidate();
                scanResultsTable.repaint();
            } catch (Exception e) {
                callbacks.printError("刷新扫描结果表格失败: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }
    
    // ========== ITab接口实现 ==========
    
    @Override
    public String getTabCaption() {
        return burpExtender.i18n.getText("tab.title");
    }
    
    @Override
    public Component getUiComponent() {
        return mainSplitPane;
    }
    
    // ========== IMessageEditorController接口实现 ==========
    
    @Override
    public byte[] getRequest() {
        return currentDisplayedItem != null ? currentDisplayedItem.getRequest() : new byte[0];
    }
    
    @Override
    public byte[] getResponse() {
        return currentDisplayedItem != null ? currentDisplayedItem.getResponse() : new byte[0];
    }
    
    @Override
    public IHttpService getHttpService() {
        return currentDisplayedItem != null ? currentDisplayedItem.getHttpService() : null;
    }
    
    // ========== 表格模型类 ==========
    
    /**
     * 扫描结果表格模型 - 按照原始xiasql的字段结构
     */
    private class ScanResultsTableModel extends AbstractTableModel {
        private final String[] columnNames = {"#", "来源", "URL", "返回包长度", "状态"};
        
        @Override
        public int getRowCount() {
            int count = scanResults.size();
            return count;
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= scanResults.size()) {
                callbacks.printOutput("警告: 行索引超出范围 " + rowIndex + " >= " + scanResults.size());
                return "";
            }
            
            LogEntry entry = scanResults.get(rowIndex);
            switch (columnIndex) {
                case 0: return entry.getId();
                case 1: return entry.getToolName(); // 来源 - 使用LogEntry的getToolName方法
                case 2: return entry.getUrl();
                case 3: return entry.getResponseLength(); // 返回包长度
                case 4: return entry.getState();
                default: return "";
            }
        }
    }
    
    /**
     * Payload详情表格模型 - 按照原始xiasql的字段结构，支持过滤显示
     */
    private class PayloadDetailsTableModel extends AbstractTableModel {
        private final String[] columnNames = {"参数", "payload", "返回包长度", "变化", "用时", "响应码"};
        
        /**
         * 获取过滤后的payload详情列表
         */
        private List<LogEntry> getFilteredPayloadDetails() {
            if (currentSelectedScanMd5 == null) {
                return payloadDetails; // 如果没有选中任何扫描结果，显示所有详情
            }
            
            List<LogEntry> filtered = new ArrayList<>();
            synchronized (payloadDetails) {
                for (LogEntry detail : payloadDetails) {
                    if (detail.getDataMd5().equals(currentSelectedScanMd5)) {
                        filtered.add(detail);
                    }
                }
            }
            return filtered;
        }
        
        @Override
        public int getRowCount() {
            List<LogEntry> filtered = getFilteredPayloadDetails();
            int count = filtered.size();
            return count;
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            List<LogEntry> filtered = getFilteredPayloadDetails();
            if (rowIndex >= filtered.size()) {
                callbacks.printOutput("警告: Payload详情行索引超出范围 " + rowIndex + " >= " + filtered.size());
                return "";
            }
            
            LogEntry entry = filtered.get(rowIndex);
            switch (columnIndex) {
                case 0: return entry.getParameter();
                case 1: return entry.getPayload();
                case 2: return entry.getResponseLength(); // 返回包长度
                case 3: return entry.getChange();
                case 4: return entry.getResponseTime(); // 用时
                case 5: return entry.getStatusCode(); // 响应码
                default: return "";
            }
        }
    }
    
    /**
     * 扫描结果表格 - 处理选择事件
     */
    private class ScanResultsTable extends JTable {
        public ScanResultsTable(TableModel model) {
            super(model);

            setRowSelectionAllowed(true);
            setColumnSelectionAllowed(false);
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            setSelectionBackground(new Color(255, 236, 179));
            setSelectionForeground(Color.BLACK);
            
            // 设置列宽 - 根据用户要求调整
            if (getColumnModel().getColumnCount() >= 6) {
                // #缩减一半、来源缩减一半，URL可以扩大一些，返回包长度也可以缩减一半，状态栏可以扩大一些，保持url和状态栏大小一致
                getColumnModel().getColumn(0).setPreferredWidth(30);  // # - 缩减一半 (原60)
                getColumnModel().getColumn(1).setPreferredWidth(200); // URL - 扩大
                getColumnModel().getColumn(2).setPreferredWidth(200); // 状态 - 扩大，与URL一致
                getColumnModel().getColumn(3).setPreferredWidth(30);  // 参数 - 保持
                getColumnModel().getColumn(4).setPreferredWidth(80);  // 时间 - 保持
                getColumnModel().getColumn(5).setPreferredWidth(50);  // 来源 - 缩减一半 (原100)
            }
        }

        @Override
        public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
            Component component = super.prepareRenderer(renderer, row, column);
            if (isRowSelected(row)) {
                component.setBackground(getSelectionBackground());
                component.setForeground(getSelectionForeground());
            } else {
                int modelRow = convertRowIndexToModel(row);
                LogEntry entry = (modelRow >= 0 && modelRow < scanResults.size()) ? scanResults.get(modelRow) : null;
                Color rowColor = (entry != null && isVulnerableScanState(entry.getState()))
                    ? HIGHLIGHT_SCAN_VULNERABLE
                    : getBackground();
                component.setBackground(rowColor);
                component.setForeground(getForeground());
            }
            return component;
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            if (row >= 0 && row < scanResults.size()) {
                // 转换为模型行索引（如果有排序）
                int modelRow = convertRowIndexToModel(row);
                if (modelRow >= 0 && modelRow < scanResults.size()) {
                    LogEntry entry = scanResults.get(modelRow);
                    
                    // 更新Payload详情表格
                    updatePayloadDetailsForEntry(entry);
                    
                    // 设置HTTP编辑器内容 - 关键：完全按照RVScan的方式
                    if (entry.getRequestResponse() != null) {
                        currentDisplayedItem = entry.getRequestResponse();
                        
                        // 调试：检查数据是否有效
                        byte[] request = entry.getRequestResponse().getRequest();
                        byte[] response = entry.getRequestResponse().getResponse();
                        
                        // callbacks.printOutput("=== 调试信息 ===");
                        // callbacks.printOutput("Request长度: " + (request != null ? request.length : "null"));
                        // callbacks.printOutput("Response长度: " + (response != null ? response.length : "null"));
                        
                        // if (request != null && request.length > 0) {
                        //     callbacks.printOutput("Request前100字符: " + new String(request, 0, Math.min(100, request.length)));
                        // }
                        
                        // 使用Legacy API设置消息 - 完全按照RVScan的方式
                        requestEditor.setMessage(request != null ? request : new byte[0], true);
                        responseEditor.setMessage(response != null ? response : new byte[0], false);
                        
                        callbacks.printOutput("扫描结果表格: HTTP编辑器数据设置完成");
                    } else {
                        callbacks.printOutput("警告: RequestResponse为null");
                        // 清空编辑器
                        requestEditor.setMessage(new byte[0], true);
                        responseEditor.setMessage(new byte[0], false);
                        currentDisplayedItem = null;
                        callbacks.printOutput("扫描结果表格: 清空HTTP编辑器");
                    }
                }
            }
            // 关键：最后调用父类方法，完全按照RVScan的方式
            super.changeSelection(row, col, toggle, extend);
        }
    }
    
    /**
     * Payload详情表格 - 处理选择事件，支持过滤数据
     */
    private class PayloadDetailsTable extends JTable {
        public PayloadDetailsTable(TableModel model) {
            super(model);
        }

        @Override
        public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
            Component component = super.prepareRenderer(renderer, row, column);
            if (isRowSelected(row)) {
                component.setBackground(getSelectionBackground());
                component.setForeground(getSelectionForeground());
            } else {
                int modelRow = convertRowIndexToModel(row);
                List<LogEntry> filteredDetails = getFilteredPayloadDetails();
                LogEntry entry = (modelRow >= 0 && modelRow < filteredDetails.size()) ? filteredDetails.get(modelRow) : null;
                Color rowColor = getPayloadDetailRowColor(entry);
                component.setBackground(rowColor != null ? rowColor : getBackground());
                component.setForeground(getForeground());
            }
            return component;
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // 获取过滤后的数据
            List<LogEntry> filteredDetails = getFilteredPayloadDetails();
            
            if (row >= 0 && row < filteredDetails.size()) {
                // 转换为模型行索引（如果有排序）
                int modelRow = convertRowIndexToModel(row);
                if (modelRow >= 0 && modelRow < filteredDetails.size()) {
                    LogEntry entry = filteredDetails.get(modelRow);
                    
                    // 设置HTTP编辑器内容 - 关键：完全按照RVScan的方式
                    if (entry.getRequestResponse() != null) {
                        currentDisplayedItem = entry.getRequestResponse();
                        
                        // 使用Legacy API设置消息 - 完全按照RVScan的方式
                        requestEditor.setMessage(entry.getRequestResponse().getRequest(), true);
                        responseEditor.setMessage(entry.getRequestResponse().getResponse(), false);
                        
                        callbacks.printOutput("PayloadTable: HTTP编辑器数据设置完成 (参数: " + entry.getParameter() + ")");
                    } else {
                        // 清空编辑器
                        requestEditor.setMessage(new byte[0], true);
                        responseEditor.setMessage(new byte[0], false);
                        currentDisplayedItem = null;
                        callbacks.printOutput("PayloadTable: 清空HTTP编辑器");
                    }
                }
            }
            // 关键：最后调用父类方法，完全按照RVScan的方式
            super.changeSelection(row, col, toggle, extend);
        }
        
        /**
         * 获取过滤后的payload详情列表 - 与TableModel保持一致
         */
        private List<LogEntry> getFilteredPayloadDetails() {
            if (currentSelectedScanMd5 == null) {
                return payloadDetails; // 如果没有选中任何扫描结果，显示所有详情
            }
            
            List<LogEntry> filtered = new ArrayList<>();
            synchronized (payloadDetails) {
                for (LogEntry detail : payloadDetails) {
                    if (detail.getDataMd5().equals(currentSelectedScanMd5)) {
                        filtered.add(detail);
                    }
                }
            }
            return filtered;
        }
    }
    
    /**
     * 更新指定条目的Payload详情 - 修复版本：不破坏全局数据
     */
    private void updatePayloadDetailsForEntry(LogEntry entry) {
        callbacks.printOutput("=== 更新Payload详情 ===");
        callbacks.printOutput("选中的扫描结果: " + entry.getUrl());
        callbacks.printOutput("MD5标识: " + entry.getDataMd5());
        
        // 保存当前选中的扫描结果MD5，用于过滤显示
        currentSelectedScanMd5 = entry.getDataMd5();
        
        // 统计相关的payload详情数量
        int relatedCount = 0;
        synchronized (payloadDetails) {
            for (LogEntry detail : payloadDetails) {
                if (detail.getDataMd5().equals(entry.getDataMd5())) {
                    relatedCount++;
                }
            }
        }
        
        callbacks.printOutput("找到 " + relatedCount + " 个相关的Payload详情");
        
        // 刷新表格显示 - 表格模型会根据currentSelectedScanMd5过滤数据
        SwingUtilities.invokeLater(() -> {
            payloadDetailsModel.fireTableDataChanged();
            callbacks.printOutput("Payload详情表格已刷新，显示MD5=" + currentSelectedScanMd5 + "的详情");
        });
    }
    
    /**
     * 测试HTTP编辑器功能
     */
    private void testHttpEditors() {
        try {
            // 创建测试请求
            String testRequest = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: DouSQL-Test\r\n\r\n";
            String testResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>";
            
            // 测试设置消息 - 完全按照RVScan的方式
            requestEditor.setMessage(testRequest.getBytes(), true);
            responseEditor.setMessage(testResponse.getBytes(), false);
            
            //callbacks.printOutput("HTTP编辑器功能测试完成 - 编辑器工作正常");
            
            // 清空测试内容
            SwingUtilities.invokeLater(() -> {
                try {
                    Thread.sleep(1000); // 等待1秒让用户看到测试内容
                    requestEditor.setMessage(new byte[0], true);
                    responseEditor.setMessage(new byte[0], false);
                } catch (InterruptedException e) {
                    // 忽略中断异常
                }
            });
            
        } catch (Exception e) {
            callbacks.printError("HTTP编辑器测试失败: " + e.getMessage());
        }
    }

    private boolean isVulnerableScanState(String state) {
        if (state == null || state.trim().isEmpty()) {
            return false;
        }

        String normalized = state.toLowerCase(Locale.ROOT);
        return normalized.contains("time")
                || normalized.contains("err")
                || normalized.contains("diff")
                || normalized.contains("bool");
    }

    private Color getPayloadDetailRowColor(LogEntry entry) {
        if (entry == null) {
            return null;
        }

        String change = entry.getChange();
        if (change == null || change.trim().isEmpty()) {
            return null;
        }

        String normalized = change.toLowerCase(Locale.ROOT);
        if (normalized.contains("time >")) {
            return HIGHLIGHT_PAYLOAD_TIME;
        }
        if (normalized.contains("err!")) {
            return HIGHLIGHT_PAYLOAD_ERR;
        }
        if (normalized.contains("diff")) {
            return HIGHLIGHT_PAYLOAD_BOOL;
        }

        return null;
    }

    private List<LogEntry> getFilteredPayloadDetails() {
        if (currentSelectedScanMd5 == null) {
            return new ArrayList<>(payloadDetails);
        }

        List<LogEntry> filtered = new ArrayList<>();
        synchronized (payloadDetails) {
            for (LogEntry detail : payloadDetails) {
                if (currentSelectedScanMd5.equals(detail.getDataMd5())) {
                    filtered.add(detail);
                }
            }
        }
        return filtered;
    }

    private void sendPayloadToSqlmap(LogEntry entry) {
        callbacks.printOutput("准备发送到 SQLMap: " + (entry != null ? entry.getParameter() : "null"));
        IHttpRequestResponse originalRequestResponse = getOriginalRequestResponseForPayload(entry);
        if (entry == null || originalRequestResponse == null || originalRequestResponse.getRequest() == null) {
            JOptionPane.showMessageDialog(mainSplitPane, "当前记录没有可用的原始请求，无法发送到 SQLMap", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String sqlmapPath = burpExtender.config.getSqlmapPath();
        if (sqlmapPath == null || sqlmapPath.trim().isEmpty()) {
            JOptionPane.showMessageDialog(mainSplitPane, "请先在 SQLMap 配置页设置 SQLMap 路径", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String outputDirPath = burpExtender.config.getSqlmapOutputDirectory();
        File outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        try {
            String safeParam = sanitizeFileName(entry.getParameter().isEmpty() ? "request" : entry.getParameter());
            File requestFile = File.createTempFile("dousql_" + safeParam + "_", ".txt");
            Files.write(requestFile.toPath(), normalizeRequestForSqlmap(originalRequestResponse.getRequest()));

            List<String> commandParts = buildSqlmapCommandParts(entry, requestFile, outputDir);
            String finalCommand = formatCommandForDisplay(commandParts);
            callbacks.printOutput("SQLMap 命令: " + finalCommand);
            if (isWindows()) {
                launchSqlmapInExternalConsole(entry, commandParts, finalCommand, requestFile);
            } else {
                showCommandOutputWindow("SQLMap - " + entry.getParameter(), commandParts, finalCommand, requestFile);
            }
        } catch (Exception e) {
            callbacks.printError("发送到 SQLMap 失败: " + e.getMessage());
            JOptionPane.showMessageDialog(mainSplitPane, "发送到 SQLMap 失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private IHttpRequestResponse getOriginalRequestResponseForPayload(LogEntry payloadEntry) {
        if (payloadEntry == null) {
            return null;
        }

        synchronized (scanResults) {
            for (LogEntry scanEntry : scanResults) {
                if (payloadEntry.getDataMd5().equals(scanEntry.getDataMd5())) {
                    return scanEntry.getRequestResponse();
                }
            }
        }

        return payloadEntry.getRequestResponse();
    }

    private List<String> buildSqlmapCommandParts(LogEntry entry, File requestFile, File outputDir) {
        String options = burpExtender.config.getSqlmapDefaultOptions();
        if (!options.contains("--level")) {
            options = options + " --level 3";
        }
        if (!options.contains("--risk")) {
            options = options + " --risk 3";
        }
        if (!options.contains("--ignore-stdin")) {
            options = options + " --ignore-stdin";
        }
        if (isWindows() && !options.contains("--disable-coloring")) {
            options = options + " --disable-coloring";
        }

        List<String> commandParts = new ArrayList<>();
        String pythonPath = burpExtender.config.getSqlmapPythonPath();
        if (pythonPath == null || pythonPath.trim().isEmpty()) {
            commandParts.add(burpExtender.config.getSqlmapPath());
        } else {
            commandParts.add(pythonPath);
            commandParts.add(burpExtender.config.getSqlmapPath());
        }

        for (String token : splitCommandLine(options)) {
            commandParts.add(token
                .replace("{requestFile}", requestFile.getAbsolutePath())
                .replace("{parameter}", entry.getParameter())
                .replace("{outputDir}", outputDir.getAbsolutePath()));
        }

        return commandParts;
    }

    private String formatCommandForDisplay(List<String> commandParts) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < commandParts.size(); i++) {
            if (i > 0) {
                builder.append(" ");
            }
            builder.append(quoteForDisplay(commandParts.get(i)));
        }
        return builder.toString();
    }

    private void launchSqlmapInExternalConsole(LogEntry entry, List<String> commandParts, String displayCommand, File requestFile) throws IOException {
        String consoleTitle = "DouSQL SQLMap - " + (entry.getParameter() == null || entry.getParameter().trim().isEmpty()
            ? "request"
            : sanitizeFileName(entry.getParameter()));

        List<String> launcher = new ArrayList<>();
        launcher.add("cmd.exe");
        launcher.add("/c");
        launcher.add("start");
        launcher.add("\"" + consoleTitle + "\"");
        launcher.add("cmd.exe");
        launcher.add("/k");
        launcher.add(displayCommand);

        new ProcessBuilder(launcher).start();

        JOptionPane.showMessageDialog(
            mainSplitPane,
            "已在外部 cmd 窗口启动 SQLMap。\n\nrequest file: " + requestFile.getAbsolutePath() + "\n\n关闭该 cmd 窗口即可终止本次测试。",
            "SQLMap 已启动",
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    private void showCommandOutputWindow(String title, List<String> commandParts, String displayCommand, File requestFile) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainSplitPane), title, false);
        dialog.setLayout(new BorderLayout(8, 8));

        JTextArea outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setText("$ " + displayCommand + "\n\n" + "request file: " + requestFile.getAbsolutePath() + "\n\n");

        JScrollPane scrollPane = new JScrollPane(outputArea);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeButton = new JButton("关闭");
        JButton openOutputDirButton = new JButton("打开输出目录");
        buttonPanel.add(openOutputDirButton);
        buttonPanel.add(closeButton);

        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setSize(900, 560);
        dialog.setLocationRelativeTo(mainSplitPane);

        final Process[] processRef = new Process[1];

        openOutputDirButton.addActionListener(e -> {
            try {
                Desktop.getDesktop().open(new File(burpExtender.config.getSqlmapOutputDirectory()));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog, "无法打开输出目录: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        closeButton.addActionListener(e -> {
            if (processRef[0] != null && processRef[0].isAlive()) {
                processRef[0].destroy();
            }
            dialog.dispose();
        });

        dialog.setVisible(true);

        Thread worker = new Thread(() -> {
            Process process = null;
            try {
                ProcessBuilder processBuilder = new ProcessBuilder(commandParts);
                processBuilder.redirectErrorStream(true);
                processRef[0] = processBuilder.start();
                process = processRef[0];
                process.getOutputStream().close();

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String currentLine = line;
                        SwingUtilities.invokeLater(() -> {
                            outputArea.append(currentLine + "\n");
                            outputArea.setCaretPosition(outputArea.getDocument().getLength());
                        });
                    }
                }

                int exitCode = process.waitFor();
                final int finalExitCode = exitCode;
                SwingUtilities.invokeLater(() -> {
                    outputArea.append("\n[process exited] code=" + finalExitCode + "\n");
                    outputArea.setCaretPosition(outputArea.getDocument().getLength());
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    outputArea.append("\n[error] " + ex.getMessage() + "\n");
                    outputArea.setCaretPosition(outputArea.getDocument().getLength());
                });
            } finally {
                if (process != null && process.isAlive()) {
                    process.destroy();
                }
            }
        }, "sqlmap-runner");
        worker.setDaemon(true);
        worker.start();
    }

    private List<String> splitCommandLine(String commandLine) {
        List<String> tokens = new ArrayList<>();
        if (commandLine == null || commandLine.trim().isEmpty()) {
            return tokens;
        }

        StringBuilder current = new StringBuilder();
        boolean inSingleQuotes = false;
        boolean inDoubleQuotes = false;

        for (int i = 0; i < commandLine.length(); i++) {
            char c = commandLine.charAt(i);
            if (c == '\'' && !inDoubleQuotes) {
                inSingleQuotes = !inSingleQuotes;
                continue;
            }
            if (c == '"' && !inSingleQuotes) {
                inDoubleQuotes = !inDoubleQuotes;
                continue;
            }
            if (Character.isWhitespace(c) && !inSingleQuotes && !inDoubleQuotes) {
                if (current.length() > 0) {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
                continue;
            }
            current.append(c);
        }

        if (current.length() > 0) {
            tokens.add(current.toString());
        }

        return tokens;
    }

    private String quoteForDisplay(String value) {
        if (value == null) {
            return "\"\"";
        }
        if (value.isEmpty() || value.matches(".*\\s+.*")) {
            return "\"" + value.replace("\"", "\\\"") + "\"";
        }
        return value;
    }

    private boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private String sanitizeFileName(String name) {
        if (name == null || name.trim().isEmpty()) {
            return "request";
        }
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private byte[] normalizeRequestForSqlmap(byte[] requestBytes) {
        if (requestBytes == null || requestBytes.length == 0) {
            return new byte[0];
        }

        String requestText = new String(requestBytes, StandardCharsets.UTF_8);
        String normalized = requestText.replace("\r\n", "\n").replace('\r', '\n');
        String[] parts = normalized.split("\n\n", 2);
        String headerPart = parts.length > 0 ? parts[0] : normalized;
        String bodyPart = parts.length > 1 ? parts[1] : "";

        String[] headerLines = headerPart.split("\n");
        if (headerLines.length > 0 && headerLines[0].contains("HTTP/2")) {
            headerLines[0] = headerLines[0].replace("HTTP/2", "HTTP/1.1");
        }

        StringBuilder rebuilt = new StringBuilder();
        for (int i = 0; i < headerLines.length; i++) {
            rebuilt.append(headerLines[i].trim()).append("\r\n");
        }
        rebuilt.append("\r\n");
        if (!bodyPart.isEmpty()) {
            rebuilt.append(bodyPart);
        }

        return rebuilt.toString().getBytes(StandardCharsets.UTF_8);
    }
    
    // ========== 其他必要方法 ==========
    
    /**
     * 添加扫描结果表格右键菜单 - 3.0.6版本新增功能
     */
    private void addScanResultsContextMenu(JTable table) {
        JPopupMenu contextMenu = new JPopupMenu();
        
        // 停止/恢复当前请求测试 - 修复per-request pause逻辑
        JMenuItem stopResumeTestItem = new JMenuItem(burpExtender.i18n.getText("menu.pause.test"));
        stopResumeTestItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                if (modelRow >= 0 && modelRow < scanResults.size()) {
                    LogEntry entry = scanResults.get(modelRow);
                    String dataMd5 = entry.getDataMd5();
                    
                    if (burpExtender.pausedRequests.contains(dataMd5)) {
                        // 恢复测试
                        burpExtender.pausedRequests.remove(dataMd5);
                        callbacks.printOutput("已恢复请求测试 (MD5: " + dataMd5 + "): " + entry.getUrl());
                        JOptionPane.showMessageDialog(mainSplitPane, 
                            "已恢复请求测试:\n" + entry.getUrl() + "\n\nMD5: " + dataMd5 + "\n\n只影响此特定请求，不影响其他请求", 
                            "测试控制", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        // 停止测试
                        burpExtender.pausedRequests.add(dataMd5);
                        callbacks.printOutput("已停止请求测试 (MD5: " + dataMd5 + "): " + entry.getUrl());
                        JOptionPane.showMessageDialog(mainSplitPane, 
                            "已停止请求测试:\n" + entry.getUrl() + "\n\nMD5: " + dataMd5 + "\n\n只影响此特定请求，不影响其他请求", 
                            "测试控制", 
                            JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            }
        });
        
        // 删除测试请求
        JMenuItem deleteTestItem = new JMenuItem(burpExtender.i18n.getText("menu.delete.test"));
        deleteTestItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                if (modelRow >= 0 && modelRow < scanResults.size()) {
                    deleteTestRequest(modelRow);
                }
            }
        });
        
        // 暂停所有扫描（只暂停当前时间点之前的请求）
        JMenuItem pauseAllItem = new JMenuItem(burpExtender.i18n.getText("menu.pause.all"));
        pauseAllItem.addActionListener(e -> {
            pauseAllCurrentRequests();
        });
        
        contextMenu.add(stopResumeTestItem);
        contextMenu.add(deleteTestItem);
        contextMenu.addSeparator();
        contextMenu.add(pauseAllItem);
        
        // 添加右键菜单到表格
        table.setComponentPopupMenu(contextMenu);
        
        //callbacks.printOutput("扫描结果表格右键菜单已添加 - 3.0.6版本功能");
    }
    
    /**
     * 添加Payload详情表格右键菜单 - 3.0.6版本新增功能
     */
    private void addPayloadDetailsContextMenu(JTable table) {
        JPopupMenu contextMenu = new JPopupMenu();
        
        // 删除此payload测试结果
        JMenuItem deletePayloadItem = new JMenuItem(burpExtender.i18n.getText("menu.delete.payload"));
        deletePayloadItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                List<LogEntry> filteredDetails = getFilteredPayloadDetails();
                if (modelRow >= 0 && modelRow < filteredDetails.size()) {
                    LogEntry entry = filteredDetails.get(modelRow);
                    int rawIndex = payloadDetails.indexOf(entry);
                    if (rawIndex >= 0) {
                        deletePayloadResult(rawIndex);
                    }
                }
            }
        });
        
        // 重新测试此payload
        JMenuItem retestPayloadItem = new JMenuItem(burpExtender.i18n.getText("menu.retest.payload"));
        retestPayloadItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                List<LogEntry> filteredDetails = getFilteredPayloadDetails();
                if (modelRow >= 0 && modelRow < filteredDetails.size()) {
                    LogEntry entry = filteredDetails.get(modelRow);
                    retestPayload(entry);
                }
            }
        });

        JMenuItem sendToSqlmapItem = new JMenuItem("发送到 SQLMap");
        sendToSqlmapItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                List<LogEntry> filteredDetails = getFilteredPayloadDetails();
                if (modelRow >= 0 && modelRow < filteredDetails.size()) {
                    sendPayloadToSqlmap(filteredDetails.get(modelRow));
                }
            }
        });
        
        contextMenu.add(deletePayloadItem);
        contextMenu.add(retestPayloadItem);
        contextMenu.add(sendToSqlmapItem);
        
        // 添加右键菜单到表格
        table.setComponentPopupMenu(contextMenu);
        
        //callbacks.printOutput("Payload详情表格右键菜单已添加 - 3.0.6版本功能");
    }
    
    /**
     * 停止当前目标请求测试 - 3.0.6版本新增功能
     */
    private void stopTargetTesting(LogEntry entry) {
        callbacks.printOutput("=== 停止目标测试 ===");
        callbacks.printOutput("目标URL: " + entry.getUrl());
        callbacks.printOutput("MD5标识: " + entry.getDataMd5());
        
        // 实现停止逻辑：将该目标的状态标记为已停止
        synchronized (scanResults) {
            for (int i = 0; i < scanResults.size(); i++) {
                LogEntry scanEntry = scanResults.get(i);
                if (scanEntry.getDataMd5().equals(entry.getDataMd5())) {
                    // 创建新的LogEntry，状态改为"stopped"
                    LogEntry stoppedEntry = new LogEntry(
                        scanEntry.getId(),
                        scanEntry.getUrl(),
                        "stopped",
                        scanEntry.getParameterCount(),
                        scanEntry.getTimestamp(),
                        scanEntry.getRequestResponse(),
                        scanEntry.getDataMd5(),
                        scanEntry.getToolFlag()
                    );
                    
                    scanResults.set(i, stoppedEntry);
                    
                    // 更新UI - 使用final变量
                    final int finalIndex = i;
                    SwingUtilities.invokeLater(() -> {
                        scanResultsModel.fireTableRowsUpdated(finalIndex, finalIndex);
                    });
                    
                    break;
                }
            }
        }
        
        // 将该目标添加到停止列表中，防止继续测试
        burpExtender.processedUrls.add(entry.getDataMd5() + "_STOPPED");
        
        callbacks.printOutput("目标测试已停止: " + entry.getUrl());
        
        JOptionPane.showMessageDialog(mainSplitPane, 
            "已停止目标测试:\n" + entry.getUrl(), 
            "停止成功", 
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * 删除测试请求 - 3.0.6版本新增功能
     */
    private void deleteTestRequest(int modelRow) {
        callbacks.printOutput("=== 删除测试请求 ===");
        
        LogEntry entryToDelete = scanResults.get(modelRow);
        String dataMd5 = entryToDelete.getDataMd5();
        
        callbacks.printOutput("删除目标URL: " + entryToDelete.getUrl());
        callbacks.printOutput("MD5标识: " + dataMd5);
        
        int result = JOptionPane.showConfirmDialog(mainSplitPane,
            "确定要删除此测试请求吗？\n" +
            "URL: " + entryToDelete.getUrl() + "\n" +
            "删除后相关的所有payload测试结果也会被删除。",
            "确认删除",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (result == JOptionPane.YES_OPTION) {
            // 删除扫描结果
            synchronized (scanResults) {
                scanResults.remove(modelRow);
            }
            
            // 删除相关的payload详情
            synchronized (payloadDetails) {
                payloadDetails.removeIf(detail -> detail.getDataMd5().equals(dataMd5));
            }
            
            // 更新UI
            SwingUtilities.invokeLater(() -> {
                scanResultsModel.fireTableRowsDeleted(modelRow, modelRow);
                payloadDetailsModel.fireTableDataChanged();
                
                // 清空HTTP编辑器
                requestEditor.setMessage(new byte[0], true);
                responseEditor.setMessage(new byte[0], false);
                currentDisplayedItem = null;
            });
            
            callbacks.printOutput("测试请求删除完成: " + entryToDelete.getUrl());
            
            JOptionPane.showMessageDialog(mainSplitPane,
                "测试请求删除成功",
                "删除成功",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 删除payload测试结果 - 3.0.6版本新增功能
     */
    private void deletePayloadResult(int modelRow) {
        callbacks.printOutput("=== 删除Payload测试结果 ===");
        
        LogEntry entryToDelete = payloadDetails.get(modelRow);
        
        callbacks.printOutput("删除参数: " + entryToDelete.getParameter());
        callbacks.printOutput("删除payload: " + entryToDelete.getPayload());
        
        int result = JOptionPane.showConfirmDialog(mainSplitPane,
            "确定要删除此payload测试结果吗？\n" +
            "参数: " + entryToDelete.getParameter() + "\n" +
            "Payload: " + entryToDelete.getPayload(),
            "确认删除",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (result == JOptionPane.YES_OPTION) {
            // 删除payload详情
            synchronized (payloadDetails) {
                payloadDetails.remove(modelRow);
            }
            
            // 更新UI
            SwingUtilities.invokeLater(() -> {
                payloadDetailsModel.fireTableRowsDeleted(modelRow, modelRow);
                
                // 清空HTTP编辑器
                requestEditor.setMessage(new byte[0], true);
                responseEditor.setMessage(new byte[0], false);
                currentDisplayedItem = null;
            });
            
            callbacks.printOutput("Payload测试结果删除完成");
            
            JOptionPane.showMessageDialog(mainSplitPane,
                "Payload测试结果删除成功",
                "删除成功",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 重新测试payload - 3.0.6版本新增功能
     */
    private void retestPayload(LogEntry entry) {
        callbacks.printOutput("=== 重新测试Payload ===");
        callbacks.printOutput("参数: " + entry.getParameter());
        callbacks.printOutput("Payload: " + entry.getPayload());
        
        // 这里可以实现重新测试的逻辑
        // 由于需要原始请求信息，这里先提供一个基础实现
        JOptionPane.showMessageDialog(mainSplitPane,
            "重新测试功能正在开发中\n" +
            "参数: " + entry.getParameter() + "\n" +
            "Payload: " + entry.getPayload(),
            "功能提示",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void createContentArea() {
        // 预留方法，用于创建内容区域
    }
    
    /**
     * 创建响应过滤配置面板
     */
    private Component createResponseFilterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(burpExtender.i18n.getText("config.response.filter")));
        
        // 顶部控制区域
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JCheckBox enableFilterCheckBox = new JCheckBox(burpExtender.i18n.getText("checkbox.enable.response.filter"), 
            burpExtender.config.getResponseFilterConfig().isEnabled());
        
        JRadioButton andModeRadio = new JRadioButton("所有条件都满足(AND)", 
            burpExtender.config.getResponseFilterConfig().isMatchAll());
        JRadioButton orModeRadio = new JRadioButton("任一条件满足(OR)", 
            !burpExtender.config.getResponseFilterConfig().isMatchAll());
        
        // 注册组件
        registerI18nComponent("checkbox.enable.response.filter", enableFilterCheckBox);
        
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(andModeRadio);
        modeGroup.add(orModeRadio);
        
        topPanel.add(enableFilterCheckBox);
        topPanel.add(new JLabel("  |  "));
        topPanel.add(andModeRadio);
        topPanel.add(orModeRadio);
        
        // 条件列表区域
        JPanel centerPanel = new JPanel(new BorderLayout());
        
        // 创建条件列表模型
        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (config.ResponseFilterConfig.FilterCondition condition : 
             burpExtender.config.getResponseFilterConfig().getConditions()) {
            listModel.addElement(condition.toString());
        }
        
        JList<String> conditionsList = new JList<>(listModel);
        conditionsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scrollPane = new JScrollPane(conditionsList);
        scrollPane.setPreferredSize(new Dimension(400, 200));
        
        centerPanel.add(scrollPane, BorderLayout.CENTER);
        
        // 按钮区域
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton addButton = new JButton(burpExtender.i18n.getText("button.add.condition"));
        JButton editButton = new JButton(burpExtender.i18n.getText("button.edit.condition"));
        JButton deleteButton = new JButton(burpExtender.i18n.getText("button.delete.condition"));
        JButton saveButton = new JButton(burpExtender.i18n.getText("button.save.config"));
        
        // 注册按钮组件
        registerI18nComponent("button.add.condition", addButton);
        registerI18nComponent("button.edit.condition", editButton);
        registerI18nComponent("button.delete.condition", deleteButton);
        registerI18nComponent("button.save.config", saveButton);
        
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(saveButton);
        
        centerPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // 事件处理
        enableFilterCheckBox.addActionListener(e -> {
            burpExtender.config.getResponseFilterConfig().setEnabled(enableFilterCheckBox.isSelected());
        });
        
        andModeRadio.addActionListener(e -> {
            burpExtender.config.getResponseFilterConfig().setMatchAll(true);
        });
        
        orModeRadio.addActionListener(e -> {
            burpExtender.config.getResponseFilterConfig().setMatchAll(false);
        });
        
        // 显示添加条件对话框
        addButton.addActionListener(e -> showAddConditionDialog(listModel));
        
        editButton.addActionListener(e -> {
            int selectedIndex = conditionsList.getSelectedIndex();
            if (selectedIndex >= 0) {
                showEditConditionDialog(listModel, selectedIndex);
            } else {
                JOptionPane.showMessageDialog(panel, "请先选择要编辑的条件", "提示", JOptionPane.WARNING_MESSAGE);
            }
        });
        
        deleteButton.addActionListener(e -> {
            int selectedIndex = conditionsList.getSelectedIndex();
            if (selectedIndex >= 0) {
                burpExtender.config.getResponseFilterConfig().removeCondition(selectedIndex);
                listModel.remove(selectedIndex);
            } else {
                JOptionPane.showMessageDialog(panel, "请先选择要删除的条件", "提示", JOptionPane.WARNING_MESSAGE);
            }
        });
        
        saveButton.addActionListener(e -> {
            burpExtender.config.saveResponseFilterConfig();
            JOptionPane.showMessageDialog(panel, "响应过滤配置已保存", "保存成功", JOptionPane.INFORMATION_MESSAGE);
        });
        
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(centerPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 显示添加条件对话框
     */
    private void showAddConditionDialog(DefaultListModel<String> listModel) {
        showConditionDialog(listModel, -1, null);
    }
    
    /**
     * 显示编辑条件对话框
     */
    private void showEditConditionDialog(DefaultListModel<String> listModel, int index) {
        config.ResponseFilterConfig.FilterCondition condition = 
            burpExtender.config.getResponseFilterConfig().getConditions().get(index);
        showConditionDialog(listModel, index, condition);
    }
    
    /**
     * 显示条件配置对话框
     */
    private void showConditionDialog(DefaultListModel<String> listModel, int editIndex, 
                                   config.ResponseFilterConfig.FilterCondition existingCondition) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainSplitPane), 
                                   editIndex >= 0 ? burpExtender.i18n.getText("button.edit.condition") : burpExtender.i18n.getText("button.add.condition"), true);
        dialog.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // 条件类型
        gbc.gridx = 0; gbc.gridy = 0;
        JLabel conditionTypeLabel = new JLabel(burpExtender.i18n.getText("label.condition.type"));
        dialog.add(conditionTypeLabel, gbc);
        
        JComboBox<config.ResponseFilterConfig.FilterType> typeCombo = 
            new JComboBox<>(config.ResponseFilterConfig.FilterType.values());
        if (existingCondition != null) {
            typeCombo.setSelectedItem(existingCondition.getType());
        }
        gbc.gridx = 1;
        dialog.add(typeCombo, gbc);
        
        // 响应头名称（仅当类型为响应头时显示）
        gbc.gridx = 0; gbc.gridy = 1;
        JLabel headerNameLabel = new JLabel(burpExtender.i18n.getText("label.header.name"));
        dialog.add(headerNameLabel, gbc);
        
        JTextField headerNameField = new JTextField(20);
        if (existingCondition != null && existingCondition.getHeaderName() != null) {
            headerNameField.setText(existingCondition.getHeaderName());
        }
        gbc.gridx = 1;
        dialog.add(headerNameField, gbc);
        
        // 比较操作符
        gbc.gridx = 0; gbc.gridy = 2;
        JLabel compareOpLabel = new JLabel(burpExtender.i18n.getText("label.compare.operation"));
        dialog.add(compareOpLabel, gbc);
        
        JComboBox<config.ResponseFilterConfig.CompareOperator> operatorCombo = 
            new JComboBox<>(config.ResponseFilterConfig.CompareOperator.values());
        if (existingCondition != null) {
            operatorCombo.setSelectedItem(existingCondition.getOperator());
        }
        gbc.gridx = 1;
        dialog.add(operatorCombo, gbc);
        
        // 比较值
        gbc.gridx = 0; gbc.gridy = 3;
        JLabel compareValueLabel = new JLabel(burpExtender.i18n.getText("label.compare.value"));
        dialog.add(compareValueLabel, gbc);
        
        JTextField valueField = new JTextField(20);
        if (existingCondition != null && existingCondition.getValue() != null) {
            valueField.setText(existingCondition.getValue());
        }
        gbc.gridx = 1;
        dialog.add(valueField, gbc);
        
        // 启用状态
        gbc.gridx = 0; gbc.gridy = 4;
        JCheckBox enabledCheckBox = new JCheckBox(burpExtender.i18n.getText("checkbox.enable.condition"), 
            existingCondition == null || existingCondition.isEnabled());
        gbc.gridwidth = 2;
        dialog.add(enabledCheckBox, gbc);
        
        // 按钮
        gbc.gridx = 0; gbc.gridy = 5;
        gbc.gridwidth = 2;
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton okButton = new JButton(burpExtender.i18n.getText("button.ok"));
        JButton cancelButton = new JButton(burpExtender.i18n.getText("button.cancel"));
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        dialog.add(buttonPanel, gbc);
        
        // 类型变化时控制响应头名称字段的可见性
        typeCombo.addActionListener(e -> {
            boolean isHeaderType = typeCombo.getSelectedItem() == config.ResponseFilterConfig.FilterType.RESPONSE_HEADER;
            headerNameLabel.setVisible(isHeaderType);
            headerNameField.setVisible(isHeaderType);
            dialog.revalidate();
        });
        
        // 初始化可见性
        boolean isHeaderType = typeCombo.getSelectedItem() == config.ResponseFilterConfig.FilterType.RESPONSE_HEADER;
        headerNameLabel.setVisible(isHeaderType);
        headerNameField.setVisible(isHeaderType);
        
        // 事件处理
        okButton.addActionListener(e -> {
            try {
                config.ResponseFilterConfig.FilterCondition condition = new config.ResponseFilterConfig.FilterCondition();
                condition.setType((config.ResponseFilterConfig.FilterType) typeCombo.getSelectedItem());
                condition.setOperator((config.ResponseFilterConfig.CompareOperator) operatorCombo.getSelectedItem());
                condition.setValue(valueField.getText().trim());
                condition.setEnabled(enabledCheckBox.isSelected());
                
                if (condition.getType() == config.ResponseFilterConfig.FilterType.RESPONSE_HEADER) {
                    condition.setHeaderName(headerNameField.getText().trim());
                    if (condition.getHeaderName().isEmpty()) {
                        JOptionPane.showMessageDialog(dialog, "响应头名称不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                }
                
                if (condition.getValue().isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "比较值不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                if (editIndex >= 0) {
                    // 编辑现有条件
                    burpExtender.config.getResponseFilterConfig().getConditions().set(editIndex, condition);
                    listModel.set(editIndex, condition.toString());
                } else {
                    // 添加新条件
                    burpExtender.config.getResponseFilterConfig().addCondition(condition);
                    listModel.addElement(condition.toString());
                }
                
                dialog.dispose();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog, "保存条件时发生错误: " + ex.getMessage(), 
                                            "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        dialog.pack();
        dialog.setLocationRelativeTo(mainSplitPane);
        dialog.setVisible(true);
    }
    
    /**
     * 暂停所有当前请求（只暂停当前时间点之前的请求，不影响后续新请求）
     */
    private void pauseAllCurrentRequests() {
        int pausedCount = 0;
        
        synchronized (scanResults) {
            for (LogEntry entry : scanResults) {
                String dataMd5 = entry.getDataMd5();
                if (!burpExtender.pausedRequests.contains(dataMd5)) {
                    burpExtender.pausedRequests.add(dataMd5);
                    
                    // 更新扫描结果状态为暂停
                    entry.setState("paused");
                    pausedCount++;
                }
            }
        }
        
        // 刷新表格显示
        refreshScanResultsTable();
        
        callbacks.printOutput(burpExtender.i18n.getText("message.requests.paused", pausedCount));
        callbacks.printOutput(burpExtender.i18n.getText("message.new.requests.normal"));
        
        JOptionPane.showMessageDialog(mainSplitPane, 
            burpExtender.i18n.getText("message.requests.paused", pausedCount) + "\n" +
            burpExtender.i18n.getText("message.new.requests.normal") + "\n" +
            burpExtender.i18n.getText("message.single.resume.hint"), 
            burpExtender.i18n.getText("dialog.scan.control"), 
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * 创建语言设置面板
     */
    private Component createLanguagePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Language Settings / 语言设置"));
        
        JPanel centerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.anchor = GridBagConstraints.WEST;
        
        // 当前语言显示
        gbc.gridx = 0; gbc.gridy = 0;
        centerPanel.add(new JLabel("Current Language / 当前语言:"), gbc);
        
        JLabel currentLanguageLabel = new JLabel(burpExtender.i18n.getCurrentLanguage().getDisplayName());
        currentLanguageLabel.setFont(currentLanguageLabel.getFont().deriveFont(Font.BOLD, 14f));
        gbc.gridx = 1;
        centerPanel.add(currentLanguageLabel, gbc);
        
        // 语言选择
        gbc.gridx = 0; gbc.gridy = 1;
        centerPanel.add(new JLabel("Select Language / 选择语言:"), gbc);
        
        JComboBox<utils.I18nManager.Language> languageCombo = new JComboBox<>();
        for (utils.I18nManager.Language lang : utils.I18nManager.Language.values()) {
            languageCombo.addItem(lang);
        }
        languageCombo.setSelectedItem(burpExtender.i18n.getCurrentLanguage());
        gbc.gridx = 1;
        centerPanel.add(languageCombo, gbc);
        
        // 切换按钮
        JButton switchButton = new JButton("Switch Language / 切换语言");
        switchButton.setPreferredSize(new Dimension(200, 30));
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        centerPanel.add(switchButton, gbc);
        
        // 说明文本
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        
        JTextArea infoArea = new JTextArea();
        infoArea.setText("Note: After switching language, please close and reopen the DouSQL tab\n" +
                        "to see all interface elements in the new language.\n\n" +
                        "注意：切换语言后，请关闭并重新打开 DouSQL 标签页\n" +
                        "以查看所有界面元素的新语言显示。");
        infoArea.setEditable(false);
        infoArea.setOpaque(false);
        infoArea.setFont(infoArea.getFont().deriveFont(Font.ITALIC, 12f));
        infoArea.setForeground(Color.GRAY);
        centerPanel.add(infoArea, gbc);
        
        // 事件处理
        switchButton.addActionListener(e -> {
            utils.I18nManager.Language selectedLanguage = 
                (utils.I18nManager.Language) languageCombo.getSelectedItem();
            
            if (selectedLanguage != null && selectedLanguage != burpExtender.i18n.getCurrentLanguage()) {
                burpExtender.i18n.switchLanguage(selectedLanguage);
                currentLanguageLabel.setText(selectedLanguage.getDisplayName());
                
                // 显示成功消息
                String message = burpExtender.i18n.getText("language.switch.success");
                
                // 提供两个选项：立即更新 或 重新加载扩展
                int option = JOptionPane.showOptionDialog(panel,
                    message + "\n\n" + 
                    "Choose an option / 选择一个选项:\n" +
                    "• Update Now: Update visible text immediately (recommended)\n" +
                    "• Reload Extension: Completely reload the extension for full effect\n\n" +
                    "• 立即更新：立即更新可见文本（推荐）\n" +
                    "• 重新加载扩展：完全重新加载扩展以获得完整效果",
                    "Language Switch / 语言切换",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.INFORMATION_MESSAGE,
                    null,
                    new String[]{"Update Now / 立即更新", "Reload Extension / 重新加载扩展"},
                    "Update Now / 立即更新");
                
                if (option == 0) {
                    // 立即更新UI文本
                    updateUITexts();
                } else if (option == 1) {
                    // 提示用户重新加载扩展
                    JOptionPane.showMessageDialog(panel,
                        "Please reload the DouSQL extension from Burp's Extensions tab for complete language change.\n\n" +
                        "请从Burp的扩展标签页重新加载DouSQL扩展以完成语言切换。",
                        "Reload Required / 需要重新加载",
                        JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });
        
        panel.add(centerPanel, BorderLayout.CENTER);
        return panel;
    }
    
    // 存储需要国际化的UI组件
    private Map<String, JComponent> i18nComponents = new HashMap<>();
    
    /**
     * 注册需要国际化的组件
     */
    private void registerI18nComponent(String key, JComponent component) {
        i18nComponents.put(key, component);
    }
    
    /**
     * 更新UI文本（只更新控制面板和配置区域）
     */
    private void updateUITexts() {
        SwingUtilities.invokeLater(() -> {
            try {
                callbacks.printOutput("开始更新UI文本...");
                
                // 1. 更新控制面板中的组件文本
                updateControlPanelTexts();
                
                // 2. 更新配置标签页标题
                updateConfigTabTitles();
                
                // 3. 更新注册的国际化组件
                updateRegisteredComponents();
                
                // 4. 刷新界面
                if (mainSplitPane != null) {
                    mainSplitPane.revalidate();
                    mainSplitPane.repaint();
                }
                
                callbacks.printOutput("UI文本更新完成");
            } catch (Exception e) {
                callbacks.printError("更新UI文本时发生错误: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }
    
    /**
     * 更新注册的国际化组件
     */
    private void updateRegisteredComponents() {
        for (Map.Entry<String, JComponent> entry : i18nComponents.entrySet()) {
            String key = entry.getKey();
            JComponent component = entry.getValue();
            
            try {
                if (component instanceof JButton) {
                    ((JButton) component).setText(burpExtender.i18n.getText(key));
                } else if (component instanceof JLabel) {
                    // 特殊处理带参数的标签
                    if ("label.config.file.hint".equals(key)) {
                        String configPath = burpExtender.config.getConfigDirectory() + "/xia_SQL_diy_payload.ini";
                        ((JLabel) component).setText(burpExtender.i18n.getText(key, configPath));
                    } else {
                        ((JLabel) component).setText(burpExtender.i18n.getText(key));
                    }
                } else if (component instanceof JCheckBox) {
                    JCheckBox checkBox = (JCheckBox) component;
                    String currentText = checkBox.getText();
                    
                    // 特殊处理带参数的复选框
                    if ("checkbox.enable.custom.error".equals(key)) {
                        String configPath = burpExtender.config.getConfigDirectory() + "/xia_SQL_diy_error.ini";
                        checkBox.setText(burpExtender.i18n.getText(key, configPath));
                    } else if (currentText.contains("(值:") || currentText.contains("(value:")) {
                        // 处理参数测试复选框
                        String[] parts = currentText.split(" \\(");
                        if (parts.length >= 2) {
                            String paramName = parts[0];
                            String valuesPart = parts[1];
                            String paramValue = valuesPart.substring(valuesPart.indexOf(":") + 1, valuesPart.lastIndexOf(")"));
                            checkBox.setText(burpExtender.i18n.getText("checkbox.param.test", paramName, paramValue));
                        } else {
                            checkBox.setText(burpExtender.i18n.getText(key));
                        }
                    } else {
                        checkBox.setText(burpExtender.i18n.getText(key));
                    }
                } else if (component instanceof JTextField) {
                    JTextField textField = (JTextField) component;
                    // 特殊处理占位符文本
                    if ("placeholder.new.group.name".equals(key)) {
                        String currentText = textField.getText();
                        String chinesePlaceholder = "新组名";
                        String englishPlaceholder = "New Group Name";
                        if (currentText.equals(chinesePlaceholder) || currentText.equals(englishPlaceholder)) {
                            textField.setText(burpExtender.i18n.getText(key));
                        }
                    }
                } else if (component instanceof JRadioButton) {
                    ((JRadioButton) component).setText(burpExtender.i18n.getText(key));
                }
            } catch (Exception e) {
                callbacks.printError("更新组件失败: " + key + " - " + e.getMessage());
            }
        }
    }
    
    /**
     * 更新控制面板文本
     */
    private void updateControlPanelTexts() {
        if (enablePluginCheckBox != null) {
            enablePluginCheckBox.setText(burpExtender.i18n.getText("control.enable.plugin"));
        }
        if (monitorRepeaterCheckBox != null) {
            monitorRepeaterCheckBox.setText(burpExtender.i18n.getText("control.monitor.repeater"));
        }
        if (monitorProxyCheckBox != null) {
            monitorProxyCheckBox.setText(burpExtender.i18n.getText("control.monitor.proxy"));
        }
        if (processNumbersCheckBox != null) {
            processNumbersCheckBox.setText(burpExtender.i18n.getText("control.process.numbers"));
        }
        if (testCookieCheckBox != null) {
            testCookieCheckBox.setText(burpExtender.i18n.getText("control.test.cookie"));
        }
        if (clearListButton != null) {
            clearListButton.setText(burpExtender.i18n.getText("control.clear.list"));
        }
        if (whitelistButton != null) {
            whitelistButton.setText(burpExtender.i18n.getText("control.whitelist.enable"));
        }
        if (whitelistTextField != null) {
            String currentText = whitelistTextField.getText();
            String chinesePlaceholder = "填写白名单域名";
            String englishPlaceholder = "Enter whitelist domains";
            if (currentText.equals(chinesePlaceholder) || currentText.equals(englishPlaceholder)) {
                whitelistTextField.setText(burpExtender.i18n.getText("control.whitelist.placeholder"));
            }
        }
    }
    
    /**
     * 更新表格标题
     */
    private void updateTableTitles() {
        try {
            // 查找并更新扫描结果表格的边框标题
            updateBorderTitle(scanResultsTable.getParent().getParent(), "table.scan.results");
            
            // 查找并更新Payload详情表格的边框标题
            updateBorderTitle(payloadDetailsTable.getParent().getParent(), "table.payload.details");
            
        } catch (Exception e) {
            callbacks.printError("更新表格标题失败: " + e.getMessage());
        }
    }
    
    /**
     * 更新配置标签页标题
     */
    private void updateConfigTabTitles() {
        if (configTabs != null) {
            try {
                // 更新所有标签页的标题
                String[] configKeys = {
                    "config.custom.sql",
                    "config.param.filter", 
                    "config.response.filter",
                    "config.custom.error",
                    "config.time.threshold",
                    "config.length.diff",
                    "config.url.blacklist",
                    "config.delay",
                    "config.append.params",
                    "config.advanced",
                    "config.language"
                };
                
                for (int i = 0; i < configKeys.length && i < configTabs.getTabCount(); i++) {
                    configTabs.setTitleAt(i, burpExtender.i18n.getText(configKeys[i]));
                }
                
            } catch (Exception e) {
                callbacks.printError("更新配置标签页标题失败: " + e.getMessage());
            }
        }
    }
    
    /**
     * 更新HTTP编辑器标题
     */
    private void updateHttpEditorTitles() {
        try {
            // 查找Request和Response面板并更新标题
            Component[] components = findComponentsWithBorder(mainSplitPane);
            for (Component comp : components) {
                if (comp instanceof JPanel) {
                    JPanel panel = (JPanel) comp;
                    if (panel.getBorder() instanceof javax.swing.border.TitledBorder) {
                        javax.swing.border.TitledBorder border = 
                            (javax.swing.border.TitledBorder) panel.getBorder();
                        String currentTitle = border.getTitle();
                        
                        if ("Request".equals(currentTitle) || "请求".equals(currentTitle)) {
                            border.setTitle(burpExtender.i18n.getText("editor.request"));
                        } else if ("Response".equals(currentTitle) || "响应".equals(currentTitle)) {
                            border.setTitle(burpExtender.i18n.getText("editor.response"));
                        }
                    }
                }
            }
        } catch (Exception e) {
            callbacks.printError("更新HTTP编辑器标题失败: " + e.getMessage());
        }
    }
    
    /**
     * 更新指定组件的边框标题
     */
    private void updateBorderTitle(Component component, String textKey) {
        if (component instanceof JPanel) {
            JPanel panel = (JPanel) component;
            if (panel.getBorder() instanceof javax.swing.border.TitledBorder) {
                javax.swing.border.TitledBorder border = 
                    (javax.swing.border.TitledBorder) panel.getBorder();
                border.setTitle(burpExtender.i18n.getText(textKey));
                panel.repaint();
            }
        }
    }
    
    /**
     * 递归查找所有带边框的组件
     */
    private Component[] findComponentsWithBorder(Container container) {
        java.util.List<Component> components = new java.util.ArrayList<>();
        findComponentsWithBorderRecursive(container, components);
        return components.toArray(new Component[0]);
    }
    
    /**
     * 递归查找带边框的组件
     */
    private void findComponentsWithBorderRecursive(Container container, java.util.List<Component> result) {
        for (Component comp : container.getComponents()) {
            if (comp instanceof JPanel) {
                JPanel panel = (JPanel) comp;
                if (panel.getBorder() instanceof javax.swing.border.TitledBorder) {
                    result.add(comp);
                }
            }
            
            if (comp instanceof Container) {
                findComponentsWithBorderRecursive((Container) comp, result);
            }
        }
    }
}
