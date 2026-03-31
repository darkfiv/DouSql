package utils;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IParameter;

import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.util.*;
import java.util.concurrent.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/**
 * HTTP请求处理工具类
 */
public class HttpUtils {
    private final BurpExtender burpExtender;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final ResponseFilter responseFilter;
    
    public HttpUtils(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.callbacks;
        this.helpers = burpExtender.helpers;
        this.responseFilter = new ResponseFilter(callbacks, helpers);
    }
    
    /**
     * 处理HTTP请求
     */
    public void processHttpRequest(IHttpRequestResponse requestResponse, int toolFlag) {
        try {
            // 基本检查
            if (requestResponse == null || requestResponse.getRequest() == null) {
                callbacks.printOutput("警告: 请求为空，跳过处理");
                return;
            }
            
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            String url = requestInfo.getUrl().toString();
            String method = requestInfo.getMethod();
            
            // 只处理 GET 和 POST 请求
            if (!"GET".equalsIgnoreCase(method) && !"POST".equalsIgnoreCase(method)) {
                callbacks.printOutput("跳过非 GET/POST 请求: " + method + " " + url);
                return;
            }
            
            // 检查域名白名单过滤
            if (!isInWhitelist(requestResponse)) {
                callbacks.printOutput("域名不在白名单中，跳过处理: " + url);
                return;
            }
            
            // 检查URL黑名单过滤
            if (isUrlBlacklisted(url)) {
                callbacks.printOutput("URL被黑名单过滤，跳过处理: " + url);
                return;
            }
            
            callbacks.printOutput("=== 开始处理HTTP请求 ===");
            callbacks.printOutput("URL: " + url);
            callbacks.printOutput("方法: " + method);
            callbacks.printOutput("工具标识: " + toolFlag + " (" + getToolName(toolFlag) + ")");

            // 预检查：没有可测试参数时，不展示扫描结果
            if (!hasTestableParameters(requestResponse, requestInfo)) {
                callbacks.printOutput("无可测试参数，跳过展示与测试: " + method + " " + url);
                return;
            }

            // 去重：相同方法+路径+参数结构只测试一次
            String requestFingerprint = generateRequestFingerprint(requestInfo);
            if (!burpExtender.processedRequestFingerprints.add(requestFingerprint)) {
                callbacks.printOutput("命中去重规则，跳过重复测试: " + requestFingerprint);
                return;
            }
            
            // 生成MD5标识
            String dataMd5 = generateMd5(url + "+" + method + "+" + System.currentTimeMillis());
            callbacks.printOutput("生成MD5标识: " + dataMd5);
            
            // 添加到已处理列表（用于统计，不用于去重）
            burpExtender.processedUrls.add(dataMd5);
            
            // 计算原始响应长度（只计算响应体长度）
            int originalResponseLength = 0;
            if (requestResponse.getResponse() != null) {
                IResponseInfo originalResponseInfo = helpers.analyzeResponse(requestResponse.getResponse());
                int bodyOffset = originalResponseInfo.getBodyOffset();
                originalResponseLength = requestResponse.getResponse().length - bodyOffset;
                callbacks.printOutput("原始响应体长度: " + originalResponseLength);
            }
            
            // 创建扫描结果条目 - 传递正确的toolFlag和原始响应长度
            LogEntry scanResult = new LogEntry(
                burpExtender.ui.scanResults.size() + 1,
                url,
                "start",
                getParameterCount(requestInfo),
                getCurrentTimestamp(),
                requestResponse,
                dataMd5,
                toolFlag // 传递真实的工具标识
            );
            
            // 设置原始响应长度
            scanResult.setResponseLength(originalResponseLength);
            
            // 保存原始响应长度用于后续比较
            burpExtender.originalResponseLengths.put(dataMd5, originalResponseLength);
            callbacks.printOutput("保存原始响应体长度: " + originalResponseLength + " (MD5: " + dataMd5 + ")");
            
            // 调试：验证工具标识传递
            callbacks.printOutput("=== 工具标识调试 ===");
            callbacks.printOutput("传入的toolFlag: " + toolFlag);
            callbacks.printOutput("LogEntry中的toolFlag: " + scanResult.getToolFlag());
            callbacks.printOutput("LogEntry的getToolName(): " + scanResult.getToolName());
            callbacks.printOutput("=== 工具标识调试结束 ===");
            
            // 调试：验证数据
            callbacks.printOutput("=== 创建LogEntry调试 ===");
            callbacks.printOutput("URL: " + url);
            callbacks.printOutput("RequestResponse是否为null: " + (requestResponse == null));
            if (requestResponse != null) {
                callbacks.printOutput("Request长度: " + (requestResponse.getRequest() != null ? requestResponse.getRequest().length : "null"));
                callbacks.printOutput("Response长度: " + (requestResponse.getResponse() != null ? requestResponse.getResponse().length : "null"));
            }
            
            // 添加到UI
            callbacks.printOutput("=== 添加到UI ===");
            burpExtender.ui.addScanResult(scanResult);
            callbacks.printOutput("扫描结果已添加到UI，当前总数: " + burpExtender.ui.scanResults.size());
            
            // 开始payload测试
            callbacks.printOutput("=== 准备开始Payload测试 ===");
            callbacks.printOutput("即将调用startPayloadTesting方法");
            callbacks.printOutput("参数: requestResponse=" + (requestResponse != null) + ", requestInfo=" + (requestInfo != null) + ", dataMd5=" + dataMd5);
            
            try {
                startPayloadTesting(requestResponse, requestInfo, dataMd5, toolFlag);
                callbacks.printOutput("=== startPayloadTesting调用完成 ===");
            } catch (Exception payloadException) {
                callbacks.printError("startPayloadTesting调用失败: " + payloadException.getMessage());
                payloadException.printStackTrace();
            }
            
        } catch (Exception e) {
            callbacks.printError("处理HTTP请求失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 检查域名是否在白名单中
     */
    private boolean isInWhitelist(IHttpRequestResponse requestResponse) {
        if (!burpExtender.whitelistEnabled || burpExtender.whitelistDomains.isEmpty()) {
            return true; // 白名单未启用或为空时，允许所有域名
        }
        
        try {
            String host = helpers.analyzeRequest(requestResponse).getUrl().getHost();
            String[] domains = burpExtender.whitelistDomains.split(",");
            
            callbacks.printOutput("=== 域名白名单检查 ===");
            callbacks.printOutput("检查域名: " + host);
            callbacks.printOutput("白名单配置: " + burpExtender.whitelistDomains);
            
            for (String domain : domains) {
                String trimmedDomain = domain.trim();
                callbacks.printOutput("检查白名单规则: " + trimmedDomain);
                
                // 支持通配符匹配
                String pattern = trimmedDomain.replace(".", "\\.").replace("*", ".*");
                if (host.matches(pattern)) {
                    callbacks.printOutput("✓ 匹配白名单规则: " + trimmedDomain);
                    callbacks.printOutput("=== 域名检查通过 ===");
                    return true;
                }
            }
            
            callbacks.printOutput("✗ 未匹配任何白名单规则");
            callbacks.printOutput("=== 域名被过滤 ===");
            return false;
        } catch (Exception e) {
            callbacks.printError("白名单检查失败: " + e.getMessage());
            return true; // 出错时允许通过
        }
    }
    
    /**
     * 检查URL是否在黑名单中
     */
    private boolean isUrlBlacklisted(String url) {
        List<String> blacklistUrls = burpExtender.config.getUrlBlacklist();
        if (blacklistUrls.isEmpty()) {
            return false;
        }
        
        // callbacks.printOutput("=== URL黑名单检查 ===");
        // callbacks.printOutput("检查URL: " + url);
        
        for (String pattern : blacklistUrls) {
            if (isUrlMatched(url, pattern)) {
                // callbacks.printOutput("✓ 匹配黑名单规则: " + pattern);
                // callbacks.printOutput("=== URL被过滤 ===");
                return true;
            }
        }
        
        // callbacks.printOutput("✗ 未匹配任何黑名单规则");
        // callbacks.printOutput("=== URL检查通过 ===");
        return false;
    }
    
    /**
     * URL匹配工具方法，支持通配符 - 修复版本，只匹配路径部分，不匹配域名
     */
    private boolean isUrlMatched(String url, String pattern) {
        try {
            // 解析URL，分离域名和路径
            java.net.URL urlObj = new java.net.URL(url);
            String path = urlObj.getPath(); // 只获取路径部分，不包含域名
            String query = urlObj.getQuery();
            
            // 完整的路径（包含查询参数）
            String fullPath = path;
            if (query != null && !query.isEmpty()) {
                fullPath = path + "?" + query;
            }
            
            // callbacks.printOutput("  检查规则: " + pattern);
            // callbacks.printOutput("  URL路径: " + fullPath);
            
            // 判断规则类型
            if (pattern.startsWith("*.")) {
                // 文件扩展名匹配，如 *.js, *.css
                String extension = pattern.substring(1); // 去掉*，保留.js
                boolean matched = path.endsWith(extension);
               // callbacks.printOutput("  扩展名匹配: " + extension + " -> " + matched);
                return matched;
            } else if (pattern.startsWith("/")) {
                // 路径前缀匹配，如 /static/*, /admin/*
                String pathPrefix = pattern.replace("*", "");
                boolean matched = fullPath.startsWith(pathPrefix);
                //callbacks.printOutput("  路径前缀匹配: " + pathPrefix + " -> " + matched);
                return matched;
            } else if (pattern.contains("/")) {
                // 路径包含匹配，如 /api/*/test
                String regex = pattern
                    .replace(".", "\\.")  // 转义点号
                    .replace("*", ".*")   // 将*转换为.*
                    .replace("?", ".");   // 将?转换为.
                boolean matched = fullPath.matches(".*" + regex + ".*");
                //callbacks.printOutput("  路径正则匹配: " + regex + " -> " + matched);
                return matched;
            } else {
                // 简单包含匹配（路径中包含该字符串）
                boolean matched = fullPath.contains(pattern);
               // callbacks.printOutput("  路径包含匹配: " + pattern + " -> " + matched);
                return matched;
            }
            
        } catch (Exception e) {
            //callbacks.printOutput("  URL解析失败: " + e.getMessage());
            // 如果URL解析失败，降级为简单匹配（但仍然避免匹配域名）
            // 尝试从URL中提取路径部分
            try {
                int pathStart = url.indexOf('/', url.indexOf("://") + 3);
                if (pathStart > 0) {
                    String path = url.substring(pathStart);
                    
                    if (pattern.startsWith("*.")) {
                        String extension = pattern.substring(1);
                        return path.endsWith(extension);
                    } else {
                        return path.contains(pattern);
                    }
                }
            } catch (Exception ex) {
                // 完全失败，返回false（不过滤）
            }
            return false;
        }
    }
    
    /**
     * 使用指定payload组处理请求
     */
    public void processWithPayloadGroup(IHttpRequestResponse requestResponse, String payloadGroup) {
        // 临时切换到指定组
        String originalGroup = burpExtender.payloadUtils.getCurrentGroup();
        burpExtender.payloadUtils.switchToGroup(payloadGroup);
        
        try {
            processHttpRequest(requestResponse, 1024);
        } finally {
            // 恢复原来的组
            burpExtender.payloadUtils.switchToGroup(originalGroup);
        }
    }
    
    /**
     * 开始Payload测试
     */
    private void startPayloadTesting(IHttpRequestResponse originalRequest, IRequestInfo requestInfo, String dataMd5, int toolFlag) {
        // callbacks.printOutput("=== startPayloadTesting方法开始执行 ===");
        // callbacks.printOutput("方法参数检查: originalRequest=" + (originalRequest != null) + ", requestInfo=" + (requestInfo != null) + ", dataMd5=" + dataMd5);
        
        // 检查扫描是否被暂停（只检查特定请求暂停）
        if (burpExtender.pausedRequests.contains(dataMd5)) {
            callbacks.printOutput("扫描已暂停，跳过payload测试 (请求暂停: " + burpExtender.pausedRequests.contains(dataMd5) + ")");
            updateScanResultState(dataMd5, "paused");
            return;
        }
        
        try {
            List<IParameter> parameters = requestInfo.getParameters();
            List<String> payloads = burpExtender.payloadUtils.getCurrentPayloads();
            
            // callbacks.printOutput("=== Payload测试详情 ===");
            // callbacks.printOutput("参数数量: " + parameters.size());
            // callbacks.printOutput("Payload数量: " + payloads.size());
            // callbacks.printOutput("当前Payload组: " + burpExtender.payloadUtils.getCurrentGroup());
            // callbacks.printOutput("测试Cookie设置: " + burpExtender.testCookie);
            // callbacks.printOutput("参数过滤模式: " + burpExtender.config.getParamFilterMode() + " (0:无过滤 1:白名单 2:黑名单)");
            
            // 检查payload内容是否正常
            callbacks.printOutput("=== Payload内容检查 ===");
            boolean hasInvalidPayloads = false;
            for (int i = 0; i < payloads.size(); i++) {
                String payload = payloads.get(i);
                if (payload.startsWith("&") && payload.contains("=")) {
                    callbacks.printOutput("警告: 发现疑似追加参数格式的payload[" + i + "]: " + payload);
                    hasInvalidPayloads = true;
                }
            }
            if (hasInvalidPayloads) {
                callbacks.printOutput("检测到payload列表中包含追加参数格式的内容，这可能导致重复测试");
                callbacks.printOutput("建议检查payload配置文件，移除追加参数格式的内容");
            }
            // callbacks.printOutput("=== Payload内容检查完成 ===");
            
            // callbacks.printOutput("=== 追加参数配置调试 ===");
            // callbacks.printOutput("追加参数启用状态: " + burpExtender.config.isAppendParamsEnabled());
            // callbacks.printOutput("追加参数数量: " + burpExtender.config.getAppendParams().size());
            // callbacks.printOutput("可测试追加参数数量: " + burpExtender.config.getTestableAppendParams().size());
            if (!burpExtender.config.getAppendParams().isEmpty()) {
                callbacks.printOutput("追加参数列表:");
                for (Map.Entry<String, String> entry : burpExtender.config.getAppendParams().entrySet()) {
                    callbacks.printOutput("  " + entry.getKey() + " = " + entry.getValue());
                }
            }
            callbacks.printOutput("=== 追加参数配置调试结束 ===");
            
            // // 详细列出所有payload
            // callbacks.printOutput("=== 当前Payload列表 ===");
            // for (int i = 0; i < payloads.size(); i++) {
            //     callbacks.printOutput("Payload[" + i + "]: " + payloads.get(i));
            // }
            // callbacks.printOutput("=== Payload列表结束 ===");
            
            // 详细列出所有参数
            for (IParameter param : parameters) {
                String paramType = getParameterTypeName(param.getType());
                //callbacks.printOutput("发现参数: " + param.getName() + " (类型: " + param.getType() + " - " + paramType + ", 值: " + param.getValue() + ")");
            }
            
            // 如果启用了追加参数，先添加追加参数到请求中
            IHttpRequestResponse workingRequest = originalRequest;
            if (burpExtender.config.isAppendParamsEnabled()) {
                workingRequest = addAppendParamsToRequest(originalRequest, requestInfo);
                if (workingRequest != originalRequest) {
                    callbacks.printOutput("=== 追加参数已添加到请求 ===");
                    // 重新分析请求以获取更新后的参数列表
                    requestInfo = helpers.analyzeRequest(workingRequest);
                    parameters = requestInfo.getParameters();
                    callbacks.printOutput("更新后参数数量: " + parameters.size());
                    
                    // 列出更新后的参数
                    for (IParameter param : parameters) {
                        String paramType = getParameterTypeName(param.getType());
                        callbacks.printOutput("更新后参数: " + param.getName() + " (类型: " + param.getType() + " - " + paramType + ", 值: " + param.getValue() + ")");
                    }
                }
            }
            
            if (parameters.isEmpty()) {
                callbacks.printOutput("警告: 没有找到可测试的参数");
                updateScanResultState(dataMd5, "no_params");
                return;
            }
            
            if (payloads.isEmpty()) {
                callbacks.printOutput("警告: 没有找到可用的payload");
                updateScanResultState(dataMd5, "no_payloads");
                return;
            }
            
            int testCount = 0;
            int skippedCount = 0;
            
            for (IParameter param : parameters) {
                // 跳过不需要测试的参数类型
                if (shouldSkipParameter(param)) {
                    String paramType = getParameterTypeName(param.getType());
                    callbacks.printOutput("跳过参数: " + param.getName() + " (类型: " + param.getType() + " - " + paramType + ")");
                    skippedCount++;
                    continue;
                }
                
                // 检查是否是追加参数且不参与测试
                if (burpExtender.config.isAppendParamsEnabled() && 
                    burpExtender.config.getAppendParams().containsKey(param.getName()) &&
                    !burpExtender.config.getTestableAppendParams().contains(param.getName())) {
                    callbacks.printOutput("跳过追加参数（不参与测试）: " + param.getName());
                    skippedCount++;
                    continue;
                }
                
                String paramType = getParameterTypeName(param.getType());
                callbacks.printOutput("测试参数: " + param.getName() + " (类型: " + param.getType() + " - " + paramType + ", 值: " + param.getValue() + ")");
                
                // 数字参数处理：如果启用，给当前参数追加 -1 / -0 payload
                List<String> payloadsForParam = payloads;
                if (burpExtender.processNumbers && isPureNumber(param.getValue())) {
                    List<String> enrichedPayloads = new ArrayList<>(payloads.size() + 2);
                    if (!payloads.contains("-1")) {
                        enrichedPayloads.add("-1");
                    }
                    if (!payloads.contains("-0")) {
                        enrichedPayloads.add("-0");
                    }
                    enrichedPayloads.addAll(payloads);
                    payloadsForParam = enrichedPayloads;
                    callbacks.printOutput("数字参数已追加payload -1/-0: " + param.getName());
                }
                
                for (String payload : payloadsForParam) {
                    // 检查扫描是否被暂停（只检查特定请求暂停）
                    if (burpExtender.pausedRequests.contains(dataMd5)) {
                        callbacks.printOutput("扫描已暂停，停止payload测试");
                        updateScanResultState(dataMd5, "paused");
                        return;
                    }
                    
                    testParameterWithPayload(workingRequest, param, payload, dataMd5, toolFlag);
                    testCount++;
                }
            }
            
            callbacks.printOutput("完成测试，总共执行了 " + testCount + " 次payload测试，跳过了 " + skippedCount + " 个参数");
            
            // 如果没有执行任何测试，给出详细建议
            if (testCount == 0) {
                callbacks.printOutput("=== 没有执行任何payload测试的原因分析 ===");
                if (skippedCount > 0) {
                    callbacks.printOutput("所有 " + skippedCount + " 个参数都被跳过了，原因如下：");
                    for (IParameter param : parameters) {
                        String paramType = getParameterTypeName(param.getType());
                        if (param.getType() == IParameter.PARAM_COOKIE) {
                            callbacks.printOutput("- " + param.getName() + " (" + paramType + "): Cookie测试已禁用，请在控制面板中勾选'测试Cookie'");
                        } else if (param.getType() != IParameter.PARAM_URL && 
                                  param.getType() != IParameter.PARAM_BODY && 
                                  param.getType() != IParameter.PARAM_JSON) {
                            callbacks.printOutput("- " + param.getName() + " (" + paramType + "): 不支持的参数类型");
                        } else {
                            callbacks.printOutput("- " + param.getName() + " (" + paramType + "): 被参数过滤规则跳过");
                        }
                    }
                    callbacks.printOutput("建议：");
                    callbacks.printOutput("1. 如果要测试Cookie参数，请在控制面板中勾选'测试Cookie'");
                    callbacks.printOutput("2. 确保请求包含URL参数、POST参数或JSON参数");
                    callbacks.printOutput("3. 检查参数过滤配置是否正确");
                } else {
                    callbacks.printOutput("没有找到任何参数，请确保请求包含可测试的参数");
                }
                callbacks.printOutput("当前测试Cookie设置: " + burpExtender.testCookie);
            }
            
            // 更新扫描结果状态
            updateScanResultState(dataMd5, "end");
            
        } catch (Exception e) {
            callbacks.printError("Payload测试失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 检查是否是 POST JSON 请求
     */
    private boolean isPostJsonRequest(IHttpRequestResponse request) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            
            // 检查请求方法是否为 POST
            if (!"POST".equalsIgnoreCase(requestInfo.getMethod())) {
                return false;
            }
            
            // 检查 Content-Type 是否包含 json
            java.util.List<String> headers = requestInfo.getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    String contentType = header.toLowerCase();
                    if (contentType.contains("json")) {
                        callbacks.printOutput("  -> 确认为 POST JSON 请求，Content-Type: " + header);
                        return true;
                    }
                }
            }
            
            return false;
        } catch (Exception e) {
            callbacks.printError("检查 POST JSON 请求失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 处理自定义payload配置（URL编码和参数值置空）
     */
    private String processCustomPayload(String originalPayload, String paramName) {
        // callbacks.printOutput("    [processCustomPayload] 开始处理");
        // callbacks.printOutput("    [processCustomPayload] 输入payload: [" + originalPayload + "]");
        // callbacks.printOutput("    [processCustomPayload] urlEncodeSpaces: " + burpExtender.urlEncodeSpaces);
        // callbacks.printOutput("    [processCustomPayload] customPayloadEnabled: " + burpExtender.customPayloadEnabled);
        // callbacks.printOutput("    [processCustomPayload] emptyParameterValues: " + burpExtender.emptyParameterValues);
        
        String processedPayload = originalPayload;
        
        // 处理空格替换为+ - 独立于customPayloadEnabled，只要urlEncodeSpaces启用就执行
        if (burpExtender.urlEncodeSpaces) {
            // callbacks.printOutput("    [processCustomPayload] 执行空格编码...");
            // callbacks.printOutput("    [processCustomPayload] 编码前: [" + processedPayload + "]");
            processedPayload = processedPayload.replace(" ", "+");
            //callbacks.printOutput("    [processCustomPayload] 编码后: [" + processedPayload + "]");
        } else {
            //callbacks.printOutput("    [processCustomPayload] 跳过空格编码（urlEncodeSpaces=false）");
        }
        
        // 处理参数值置空 - 需要customPayloadEnabled启用
        if (burpExtender.customPayloadEnabled && burpExtender.emptyParameterValues) {
           // callbacks.printOutput("    [processCustomPayload] 应用参数值置空配置");
            // 参数值置空：清空原始参数值，只使用payload
            // 这个逻辑在调用方处理，这里只是标记
        }
        
       // callbacks.printOutput("    [processCustomPayload] 返回payload: [" + processedPayload + "]");
        return processedPayload;
    }
    
    /**
     * 处理特殊的参数值（数字、null、空字符串）
     */
    private String processParameterValue(String originalValue, String paramName) {
        if (originalValue == null) {
            callbacks.printOutput("  -> 参数值为null，跳过处理");
            return ""; // null值返回空字符串，后续会使用默认值1
        }
        
        String trimmedValue = originalValue.trim();
        
        // 处理空字符串
        if (trimmedValue.isEmpty()) {
            callbacks.printOutput("  -> 参数值为空字符串");
            return ""; // 空字符串返回空，后续会使用默认值1
        }
        
        // 处理数字值 - 转换为字符串格式
        if (isNumericValue(trimmedValue)) {
            callbacks.printOutput("  -> 参数值为数字: " + trimmedValue + "，转换为字符串格式");
            return trimmedValue; // 数字直接返回字符串形式
        }
        
        // 处理null字符串
        if ("null".equalsIgnoreCase(trimmedValue)) {
            callbacks.printOutput("  -> 参数值为null字符串，跳过处理");
            return ""; // null字符串返回空，后续会使用默认值1
        }
        
        // 其他情况直接返回原值
        return trimmedValue;
    }
    
    /**
     * 检查是否为数字值
     */
    private boolean isNumericValue(String value) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }
        
        try {
            // 尝试解析为数字
            Double.parseDouble(value.trim());
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * 检查是否为纯数字（只包含0-9）
     */
    private boolean isPureNumber(String value) {
        if (value == null) {
            return false;
        }
        String trimmedValue = value.trim();
        return !trimmedValue.isEmpty() && trimmedValue.matches("[0-9]+");
    }
    
    /**
     * 测试参数与payload组合 - 参考daimabak_fixed.txt的实现
     */
    private void testParameterWithPayload(IHttpRequestResponse originalRequest, IParameter param, String payload, String dataMd5, int toolFlag) {
        try {
            String paramName = param.getName();
            String originalValue = param.getValue();
            
            // callbacks.printOutput("  -> 测试payload: " + payload + " 在参数: " + paramName);
            // callbacks.printOutput("  -> 原始参数值: " + originalValue);
            
            // 基于中文编码修复说明：简化编码处理逻辑
            // 总是进行ISO_8859_1→UTF_8转换，这是为了修复中文编码问题
            byte[] bytes = originalValue.getBytes(StandardCharsets.ISO_8859_1);
            String workingValue = new String(bytes, StandardCharsets.UTF_8);
            
            // // 调试信息
            // callbacks.printOutput("=== 参数编码调试信息 ===");
            // callbacks.printOutput("参数名: " + paramName);
            // callbacks.printOutput("参数类型: " + getParameterTypeName(param.getType()));
            // callbacks.printOutput("  原始值: " + originalValue);
            // callbacks.printOutput("  修复后值: " + workingValue);
            
            // 检查是否包含中文字符
            boolean originalHasChinese = originalValue.matches(".*[\\u4e00-\\u9fa5].*");
            boolean workingHasChinese = workingValue.matches(".*[\\u4e00-\\u9fa5].*");
            // callbacks.printOutput("  原始值包含中文: " + originalHasChinese);
            // callbacks.printOutput("  修复后包含中文: " + workingHasChinese);
            
            // 修复方案：总是使用修复后的值
            // callbacks.printOutput("  -> 使用修复后的值进行payload拼接");
            // callbacks.printOutput("最终使用值: " + workingValue);
            // callbacks.printOutput("=== 编码调试信息结束 ===");
            
            // 特殊参数值处理
            String processedValue = processParameterValue(workingValue, paramName);
            // callbacks.printOutput("  -> 参数值处理结果: " + processedValue);
            
            // // 应用自定义payload配置
            // callbacks.printOutput("=== Payload编码处理调试 ===");
            // callbacks.printOutput("  -> 原始payload: [" + payload + "]");
            // callbacks.printOutput("  -> urlEncodeSpaces设置: " + burpExtender.urlEncodeSpaces);
            // callbacks.printOutput("  -> customPayloadEnabled设置: " + burpExtender.customPayloadEnabled);
            
            String finalPayload = processCustomPayload(payload, paramName);
            
            // 新增策略：如果是 POST JSON 请求，转义 payload 中的引号
            if (isPostJsonRequest(originalRequest)) {
                callbacks.printOutput("  -> 检测到 POST JSON 请求，转义 payload 中的引号");
                callbacks.printOutput("  -> 转义前 payload: " + finalPayload);
                finalPayload = finalPayload.replace("\"", "\\\"");
                callbacks.printOutput("  -> 转义后 payload: " + finalPayload);
            }
            
            // callbacks.printOutput("  -> 处理后的payload: [" + finalPayload + "]");
            // callbacks.printOutput("  -> payload是否包含空格: " + payload.contains(" "));
            // callbacks.printOutput("  -> 处理后是否包含%20: " + finalPayload.contains("%20"));
            // callbacks.printOutput("=== Payload编码处理调试结束 ===");
            
            // 创建测试值：根据配置决定是否置空参数值
            String testValue;
            if (burpExtender.customPayloadEnabled && burpExtender.emptyParameterValues) {
                // 参数值置空：只使用payload，不使用原始参数值
                testValue = finalPayload;
              //  callbacks.printOutput("  -> 参数值置空模式，只使用payload: " + testValue);
            } else if (processedValue.isEmpty()) {
                // 如果参数值为空，使用默认值1再追加payload
                testValue = "1" + finalPayload;
              //  callbacks.printOutput("  -> 参数值为空，使用默认值1+payload: " + testValue);
            } else {
                // 如果参数值不为空，追加payload
                testValue = processedValue + finalPayload;
              //  callbacks.printOutput("  -> 追加payload到参数值: " + processedValue + " + " + finalPayload + " = " + testValue);
            }
            
            // 构建新请求 - 使用Burp的helpers方法（参考daimabak_fixed.txt）
            // callbacks.printOutput("  -> 开始构建新请求（使用Burp helpers方法）...");
            // callbacks.printOutput("  -> 参数类型: " + param.getType() + " - " + getParameterTypeName(param.getType()));
            // callbacks.printOutput("  -> 即将传递给buildParameter的testValue: [" + testValue + "]");
            
            IHttpService iHttpService = originalRequest.getHttpService();
            byte[] newRequestBytes;
            
            try {
                callbacks.printOutput("  -> 调用 helpers.buildParameter(\"" + paramName + "\", \"" + testValue + "\", " + param.getType() + ")");
                IParameter newParam = helpers.buildParameter(paramName, testValue, param.getType());
                callbacks.printOutput("  -> buildParameter 返回的参数值: [" + newParam.getValue() + "]");
                
                newRequestBytes = helpers.updateParameter(originalRequest.getRequest(), newParam);
                callbacks.printOutput("  -> updateParameter 完成");
            } catch (UnsupportedOperationException e) {
                callbacks.printOutput("  -> Burp的updateParameter不支持此参数类型，尝试手动构建请求...");
                callbacks.printOutput("  -> 参数名: " + paramName);
                callbacks.printOutput("  -> 参数类型: " + param.getType() + " - " + getParameterTypeName(param.getType()));
                callbacks.printOutput("  -> 参数原始值: " + param.getValue());
                callbacks.printOutput("  -> 测试值: " + testValue);
                
                // 尝试手动构建请求（特别是对于JSON数组）
                newRequestBytes = buildRequestManually(originalRequest.getRequest(), param, testValue);
                
                if (newRequestBytes == null || newRequestBytes == originalRequest.getRequest()) {
                    callbacks.printError("  -> 错误：手动构建请求也失败");
                    callbacks.printError("  -> 参数名: " + paramName);
                    callbacks.printError("  -> 参数类型: " + param.getType() + " - " + getParameterTypeName(param.getType()));
                    callbacks.printError("  -> 参数值: " + param.getValue());
                    callbacks.printError("  -> 这可能是JSON数组元素或其他特殊格式的参数");
                    callbacks.printError("  -> 跳过该参数的测试");
                    return;
                }
                
                callbacks.printOutput("  -> 手动构建请求成功");
            } catch (Exception e) {
                callbacks.printError("  -> 错误：构建请求时发生异常: " + e.getMessage());
                callbacks.printError("  -> 参数名: " + paramName);
                callbacks.printError("  -> 参数类型: " + param.getType() + " - " + getParameterTypeName(param.getType()));
                e.printStackTrace();
                return;
            }
            
            if (newRequestBytes == null || newRequestBytes.length == 0) {
                callbacks.printError("  -> 错误：构建请求失败（返回null或空数组）");
                return;
            }
            
            final byte[] newRequest = newRequestBytes;  // 创建final副本供lambda使用
            
            // callbacks.printOutput("  -> 构建新请求完成，参数值: " + testValue);
            // callbacks.printOutput("  -> 新请求长度: " + newRequest.length + " 字节");
            
            // 显示新请求的前200个字符用于调试
            String requestPreview = new String(newRequest, 0, Math.min(200, newRequest.length), StandardCharsets.UTF_8);
            //callbacks.printOutput("  -> 新请求预览: " + requestPreview.replace("\r\n", "\\r\\n"));
            
            // 发送请求前应用延时配置
            applyDelayBeforeRequest();
            
            // 发送请求
            // callbacks.printOutput("  -> 准备发送请求...");
            // callbacks.printOutput("  -> 目标服务: " + iHttpService.getHost() + ":" + iHttpService.getPort());
            // callbacks.printOutput("  -> 协议: " + iHttpService.getProtocol());
            
            int timeoutMs = burpExtender.config.getRequestTimeout();
            //callbacks.printOutput("  -> 请求超时设置: " + timeoutMs + "毫秒 (" + (timeoutMs/1000.0) + "秒)");
            
            long startTime = System.currentTimeMillis();
            IHttpRequestResponse testResponse = null;
            boolean isTimeout = false;
            
            try {
               // callbacks.printOutput("  -> 正在调用makeHttpRequest...");
                
                // 使用ExecutorService实现超时控制
                ExecutorService executor = Executors.newSingleThreadExecutor();
                Future<IHttpRequestResponse> future = executor.submit(() -> {
                    return callbacks.makeHttpRequest(iHttpService, newRequest);
                });
                
                try {
                    // 等待请求完成，设置超时时间
                    testResponse = future.get(timeoutMs, TimeUnit.MILLISECONDS);
                } catch (TimeoutException e) {
                    // 请求超时
                    isTimeout = true;
                    future.cancel(true); // 取消请求
                    callbacks.printOutput("  -> 请求超时: 超过 " + (timeoutMs/1000.0) + " 秒");
                } finally {
                    executor.shutdownNow(); // 关闭线程池
                }
                
                long responseTime = System.currentTimeMillis() - startTime;
                
                // 处理超时情况
                if (isTimeout) {
                    // callbacks.printOutput("  -> 请求已超时，丢弃该请求");
                    // callbacks.printOutput("  -> 超时时间: " + responseTime + "ms");
                    
                    // 创建超时记录
                    LogEntry payloadDetail = new LogEntry(
                        burpExtender.ui.payloadDetails.size() + 1,
                        paramName,
                        payload, // 只保存 payload
                        "timeout>" + (timeoutMs/1000.0) + "s",
                        0,
                        (int)responseTime,
                        "TIMEOUT",
                        null,
                        dataMd5,
                        toolFlag
                    );
                    burpExtender.ui.addPayloadDetail(payloadDetail);
                    
                    // 更新扫描结果状态为timeout
                    updateScanResultState(dataMd5, "timeout");
                    
                    callbacks.printOutput("  -> 超时记录已添加到UI");
                    return; // 直接返回，不继续处理
                }
                
                // callbacks.printOutput("  -> makeHttpRequest调用完成");
                // callbacks.printOutput("  -> 请求发送成功，响应时间: " + responseTime + "ms");
                
                // 调试：检查响应状态
               // callbacks.printOutput("  -> 调试：testResponse是否为null: " + (testResponse == null));
                if (testResponse != null) {
                    //callbacks.printOutput("  -> 调试：response是否为null: " + (testResponse.getResponse() == null));
                    if (testResponse.getResponse() != null) {
                      //  callbacks.printOutput("  -> 调试：response长度: " + testResponse.getResponse().length);
                        
                        // 如果响应长度为0，可能是连接问题
                        if (testResponse.getResponse().length == 0) {
                            // callbacks.printOutput("  -> 警告：响应长度为0，可能是连接超时或被拒绝");
                            // callbacks.printOutput("  -> 建议：检查目标服务器是否正常，或增加超时时间");
                        }
                    }
                }
                
                // 确保响应对象包含修改后的请求
                if (testResponse != null) {
                    // 检查请求是否正确
                    byte[] savedRequest = testResponse.getRequest();
                    if (savedRequest == null || !java.util.Arrays.equals(savedRequest, newRequest)) {
                        callbacks.printOutput("  -> 警告：响应对象中的请求与发送的请求不一致，手动设置请求");
                        // 创建新的响应对象，包含正确的请求
                        testResponse = createRequestResponse(iHttpService, newRequest, testResponse.getResponse());
                    }
                }
                
                // 分析响应 - 只保存 payload
               // callbacks.printOutput("  -> 准备调用analyzeResponseWithWorkingValue");
                analyzeResponseWithWorkingValue(testResponse, paramName, param.getValue(), payload, dataMd5, responseTime, toolFlag);
                //callbacks.printOutput("  -> analyzeResponseWithWorkingValue调用完成");
                
            } catch (Exception requestException) {
               // callbacks.printError("发送请求失败: " + requestException.getMessage());
               // callbacks.printError("异常类型: " + requestException.getClass().getName());
                requestException.printStackTrace();
                
                // 即使请求失败，也尝试创建一个空的响应记录
               // callbacks.printOutput("  -> 请求失败，创建空响应记录");
                try {
                    LogEntry payloadDetail = new LogEntry(
                        burpExtender.ui.payloadDetails.size() + 1,
                        paramName,
                        payload, // 只保存 payload
                        "请求失败: " + requestException.getMessage(),
                        0,
                        0,
                        "ERROR",
                        null,
                        dataMd5,
                        toolFlag
                    );
                    burpExtender.ui.addPayloadDetail(payloadDetail);
                   //callbacks.printOutput("  -> 错误记录已添加到UI");
                } catch (Exception logException) {
                    //callbacks.printError("创建错误记录失败: " + logException.getMessage());
                    logException.printStackTrace();
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("测试参数失败 [" + param.getName() + " + " + payload + "]: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 构建包含新参数值的请求 - 优先使用Burp的helpers方法，确保请求格式正确
     */
    private byte[] buildRequestWithParameter(byte[] originalRequest, IParameter param, String newValue) {
        try {
            String paramName = param.getName();
            byte paramType = param.getType();
            
           // callbacks.printOutput("  -> 构建请求，参数类型: " + getParameterTypeName(paramType));
            
            // 优先使用Burp的helpers.updateParameter方法
            // 这样可以确保请求格式正确，避免手动构建导致的问题
            try {
              //  callbacks.printOutput("  -> 使用Burp helpers.updateParameter方法");
                IParameter newParam = helpers.buildParameter(paramName, newValue, paramType);
                byte[] updatedRequest = helpers.updateParameter(originalRequest, newParam);
                
                // 验证更新是否成功
                if (updatedRequest != null && updatedRequest.length > 0) {
                    callbacks.printOutput("  -> Burp helpers方法构建成功");
                    return updatedRequest;
                } else {
                    callbacks.printOutput("  -> Burp helpers方法返回空，尝试手动构建");
                }
            } catch (Exception helpersException) {
                // callbacks.printOutput("  -> Burp helpers方法失败: " + helpersException.getMessage());
                // callbacks.printOutput("  -> 尝试手动构建请求");
            }
            
            // 如果helpers方法失败，使用手动构建作为备选
            switch (paramType) {
                case IParameter.PARAM_URL:
                    return buildUrlParameterRequest(originalRequest, paramName, newValue);
                    
                case IParameter.PARAM_BODY:
                    return buildBodyParameterRequest(originalRequest, paramName, newValue);
                    
                case IParameter.PARAM_JSON:
                    return buildJsonParameterRequest(originalRequest, paramName, newValue);
                    
                case IParameter.PARAM_COOKIE:
                    return buildCookieParameterRequest(originalRequest, paramName, newValue);
                    
                default:
                    callbacks.printOutput("  -> 不支持的参数类型: " + paramType);
                    return originalRequest;
            }
            
        } catch (Exception e) {
            callbacks.printError("构建请求失败: " + e.getMessage());
            e.printStackTrace();
            return originalRequest;
        }
    }
    
    /**
     * 构建URL参数请求
     */
    private byte[] buildUrlParameterRequest(byte[] originalRequest, String paramName, String newValue) {
        try {
            String requestString = new String(originalRequest, StandardCharsets.UTF_8);
            String[] lines = requestString.split("\r\n");
            
            if (lines.length > 0) {
                String requestLine = lines[0];
                if (requestLine.contains("?")) {
                    String[] parts = requestLine.split("\\?");
                    String baseUrl = parts[0];
                    String queryString = parts[1].split(" ")[0];
                    String httpVersion = requestLine.substring(requestLine.lastIndexOf(" "));
                    
                    // 重构查询字符串
                    String[] params = queryString.split("&");
                    StringBuilder newQueryString = new StringBuilder();
                    boolean paramFound = false;
                    
                    for (String param : params) {
                        if (param.startsWith(paramName + "=")) {
                            if (newQueryString.length() > 0) newQueryString.append("&");
                            // Payload不进行URL编码，直接使用原始值
                            newQueryString.append(paramName).append("=").append(newValue);
                            callbacks.printOutput("  -> URL参数不进行编码: " + newValue);
                            paramFound = true;
                        } else {
                            if (newQueryString.length() > 0) newQueryString.append("&");
                            newQueryString.append(param);
                        }
                    }
                    
                    if (paramFound) {
                        // 重构第一行
                        lines[0] = baseUrl + "?" + newQueryString.toString() + httpVersion;
                        String newRequestString = String.join("\r\n", lines);
                        callbacks.printOutput("  -> URL参数请求构建成功");
                        return newRequestString.getBytes(StandardCharsets.UTF_8);
                    }
                }
            }
            
            return originalRequest;
            
        } catch (Exception e) {
            callbacks.printError("构建URL参数请求失败: " + e.getMessage());
            return originalRequest;
        }
    }
    
    /**
     * 构建POST参数请求
     */
    private byte[] buildBodyParameterRequest(byte[] originalRequest, String paramName, String newValue) {
        try {
            String requestString = new String(originalRequest, StandardCharsets.UTF_8);
            String[] parts = requestString.split("\r\n\r\n", 2);
            
            if (parts.length > 1) {
                String headers = parts[0];
                String body = parts[1];
                
                // 重构请求体
                if (body.contains("&") || body.contains("=")) {
                    String[] params = body.split("&");
                    StringBuilder newBody = new StringBuilder();
                    boolean paramFound = false;
                    
                    for (String param : params) {
                        if (param.startsWith(paramName + "=")) {
                            if (newBody.length() > 0) newBody.append("&");
                            // Payload不进行URL编码，直接使用原始值
                            newBody.append(paramName).append("=").append(newValue);
                            callbacks.printOutput("  -> POST参数不进行编码: " + newValue);
                            paramFound = true;
                        } else {
                            if (newBody.length() > 0) newBody.append("&");
                            newBody.append(param);
                        }
                    }
                    
                    if (paramFound) {
                        String newRequestString = headers + "\r\n\r\n" + newBody.toString();
                        callbacks.printOutput("  -> POST参数请求构建成功");
                        return newRequestString.getBytes(StandardCharsets.UTF_8);
                    }
                }
            }
            
            return originalRequest;
            
        } catch (Exception e) {
        //    callbacks.printError("构建POST参数请求失败: " + e.getMessage());
            return originalRequest;
        }
    }
    
    /**
     * 构建JSON参数请求 - 改进版本，正确处理数组参数
     */
    private byte[] buildJsonParameterRequest(byte[] originalRequest, String paramName, String newValue) {
        try {
            String requestString = new String(originalRequest, StandardCharsets.UTF_8);
            String[] parts = requestString.split("\r\n\r\n", 2);
            
            if (parts.length > 1) {
                String headers = parts[0];
                String body = parts[1];
                
                //callbacks.printOutput("  -> 原始JSON体: " + body);
                
                // 获取原始参数值
                String originalValue = getOriginalJsonValue(body, paramName);
                String newBody = body;
                
                if (originalValue != null) {
                   // callbacks.printOutput("  -> 找到原始参数值: " + originalValue);
                    
                    // 检查原始值是否是数组格式
                    boolean isArray = isJsonArray(originalValue);
                    //callbacks.printOutput("  -> 参数是否为数组: " + isArray);
                    
                    if (isArray) {
                        // 数组参数：在数组中添加payload，而不是替换整个数组
                        newBody = injectPayloadIntoJsonArray(body, paramName, originalValue, newValue);
                    } else {
                        // 普通参数：直接替换值
                        newBody = replaceJsonValue(body, paramName, originalValue, newValue);
                    }
                } else {
                    callbacks.printOutput("  -> 未找到参数，尝试直接字符串替换");
                    // 如果没有找到匹配，尝试直接字符串替换
                    if (!originalValue.isEmpty()) {
                        newBody = body.replace(originalValue, newValue);
                    }
                }
                
               // callbacks.printOutput("  -> 新JSON体: " + newBody);
                
                String newRequestString = headers + "\r\n\r\n" + newBody;
              //  callbacks.printOutput("  -> JSON参数请求构建成功");
                return newRequestString.getBytes(StandardCharsets.UTF_8);
            }
            
            return originalRequest;
            
        } catch (Exception e) {
            callbacks.printError("构建JSON参数请求失败: " + e.getMessage());
            return originalRequest;
        }
    }
    
    /**
     * 检查JSON值是否是数组格式
     */
    private boolean isJsonArray(String value) {
        if (value == null) return false;
        String trimmed = value.trim();
        return trimmed.startsWith("[") && trimmed.endsWith("]");
    }
    
    /**
     * 在JSON数组中注入payload
     * 修改数组中的特定元素，将其转换为字符串并追加payload
     * 
     * @param jsonBody JSON请求体
     * @param paramName 参数名（可能包含数组索引，如 role_permissions[0]）
     * @param originalArrayValue 原始数组值
     * @param payload 要注入的payload
     * @return 修改后的JSON请求体
     */
    private String injectPayloadIntoJsonArray(String jsonBody, String paramName, String originalArrayValue, String payload) {
        try {
            callbacks.printOutput("  -> 处理JSON数组参数: " + paramName);
            callbacks.printOutput("  -> 原始数组值: " + originalArrayValue);
            callbacks.printOutput("  -> Payload: " + payload);
            
            // 检查参数名是否包含数组索引（如 role_permissions[0]）
            int arrayIndex = -1;
            String baseParamName = paramName;
            
            if (paramName.contains("[") && paramName.contains("]")) {
                // 提取数组索引
                int startIdx = paramName.indexOf("[");
                int endIdx = paramName.indexOf("]");
                try {
                    arrayIndex = Integer.parseInt(paramName.substring(startIdx + 1, endIdx));
                    baseParamName = paramName.substring(0, startIdx);
                    callbacks.printOutput("  -> 检测到数组索引: " + arrayIndex + ", 基础参数名: " + baseParamName);
                } catch (NumberFormatException e) {
                    callbacks.printOutput("  -> 无法解析数组索引，将作为普通参数处理");
                }
            }
            
            // 解析数组内容
            String arrayContent = originalArrayValue.substring(1, originalArrayValue.length() - 1).trim();
            
            if (arrayContent.isEmpty()) {
                // 空数组，直接添加payload作为字符串
                String newArrayValue = "[\"" + escapeJsonValue(payload) + "\"]";
                callbacks.printOutput("  -> 空数组，新值: " + newArrayValue);
                return replaceJsonValue(jsonBody, baseParamName, originalArrayValue, newArrayValue);
            }
            
            // 分割数组元素
            String[] elements = splitJsonArrayElements(arrayContent);
            
            if (elements.length == 0) {
                // 无法解析数组元素，降级处理
                callbacks.printOutput("  -> 无法解析数组元素，使用降级处理");
                return replaceJsonValue(jsonBody, baseParamName, originalArrayValue, "\"" + escapeJsonValue(payload) + "\"");
            }
            
            // 确定要修改的元素索引
            int targetIndex = arrayIndex >= 0 ? arrayIndex : 0; // 如果没有指定索引，默认修改第一个元素
            
            if (targetIndex >= elements.length) {
                callbacks.printOutput("  -> 警告：数组索引 " + targetIndex + " 超出范围（数组长度: " + elements.length + "）");
                targetIndex = 0; // 降级到第一个元素
            }
            
            callbacks.printOutput("  -> 将修改数组的第 " + targetIndex + " 个元素");
            callbacks.printOutput("  -> 原始元素值: " + elements[targetIndex]);
            
            // 获取目标元素的值
            String targetElement = elements[targetIndex].trim();
            String targetElementValue;
            
            if (targetElement.startsWith("\"") && targetElement.endsWith("\"")) {
                // 已经是字符串，去掉引号
                targetElementValue = targetElement.substring(1, targetElement.length() - 1);
            } else {
                // 是数字或其他类型，直接使用
                targetElementValue = targetElement;
            }
            
            // 构建新的元素值：原值 + payload，作为字符串
            String newElement = "\"" + escapeJsonValue(targetElementValue + payload) + "\"";
            callbacks.printOutput("  -> 新元素值: " + newElement);
            
            // 重新构建数组
            StringBuilder newArrayBuilder = new StringBuilder("[");
            for (int i = 0; i < elements.length; i++) {
                if (i > 0) {
                    newArrayBuilder.append(",");
                }
                
                if (i == targetIndex) {
                    // 使用新的元素值
                    newArrayBuilder.append(newElement);
                } else {
                    // 保持原有元素
                    newArrayBuilder.append(elements[i]);
                }
            }
            newArrayBuilder.append("]");
            
            String newArrayValue = newArrayBuilder.toString();
            callbacks.printOutput("  -> 新数组值: " + newArrayValue);
            
            return replaceJsonValue(jsonBody, baseParamName, originalArrayValue, newArrayValue);
            
        } catch (Exception e) {
            callbacks.printError("处理JSON数组失败: " + e.getMessage());
            e.printStackTrace();
            // 降级处理：直接替换为字符串（保持原有行为）
            return replaceJsonValue(jsonBody, paramName, originalArrayValue, "\"" + escapeJsonValue(payload) + "\"");
        }
    }
    
    /**
     * 分割JSON数组元素（简单实现，处理基本情况）
     */
    private String[] splitJsonArrayElements(String arrayContent) {
        List<String> elements = new ArrayList<>();
        StringBuilder currentElement = new StringBuilder();
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        
        for (int i = 0; i < arrayContent.length(); i++) {
            char c = arrayContent.charAt(i);
            
            if (escaped) {
                currentElement.append(c);
                escaped = false;
                continue;
            }
            
            if (c == '\\') {
                escaped = true;
                currentElement.append(c);
                continue;
            }
            
            if (c == '"') {
                inString = !inString;
                currentElement.append(c);
                continue;
            }
            
            if (!inString) {
                if (c == '[' || c == '{') {
                    depth++;
                } else if (c == ']' || c == '}') {
                    depth--;
                } else if (c == ',' && depth == 0) {
                    // 找到元素分隔符
                    elements.add(currentElement.toString().trim());
                    currentElement = new StringBuilder();
                    continue;
                }
            }
            
            currentElement.append(c);
        }
        
        // 添加最后一个元素
        if (currentElement.length() > 0) {
            elements.add(currentElement.toString().trim());
        }
        
        return elements.toArray(new String[0]);
    }
    
    /**
     * 替换JSON中的参数值 - 改进版本，正确处理数字、字符串、数组和对象
     */
    private String replaceJsonValue(String jsonBody, String paramName, String originalValue, String newValue) {
        try {
            callbacks.printOutput("  -> 替换JSON值: " + paramName);
            callbacks.printOutput("  -> 原始值: " + originalValue);
            callbacks.printOutput("  -> 新值: " + newValue);
            
            // 检查原始值的类型
            // 注意：JSON 中 "id":"1" 这种字符串数字不能按数字处理
            boolean originalIsQuotedString = java.util.regex.Pattern
                    .compile("\"" + escapeRegex(paramName) + "\"\\s*:\\s*\"")
                    .matcher(jsonBody)
                    .find();
            boolean originalIsNumber = !originalIsQuotedString && isNumericValue(originalValue);
            boolean originalIsArray = originalValue.trim().startsWith("[") && originalValue.trim().endsWith("]");
            boolean originalIsObject = originalValue.trim().startsWith("{") && originalValue.trim().endsWith("}");
            boolean originalIsString = !originalIsNumber && !originalIsArray && !originalIsObject;
            
            // 检查新值的类型
            boolean newValueIsNumber = isNumericValue(newValue) && !newValue.contains("'") && !newValue.contains("\"");
            boolean newValueIsArray = newValue.trim().startsWith("[") && newValue.trim().endsWith("]");
            boolean newValueIsObject = newValue.trim().startsWith("{") && newValue.trim().endsWith("}");
            
            callbacks.printOutput("  -> 原始值类型: 数字=" + originalIsNumber + ", 数组=" + originalIsArray + 
                                ", 对象=" + originalIsObject + ", 字符串=" + originalIsString);
            callbacks.printOutput("  -> 原始值是否JSON字符串: " + originalIsQuotedString);
            callbacks.printOutput("  -> 新值类型: 数字=" + newValueIsNumber + ", 数组=" + newValueIsArray + 
                                ", 对象=" + newValueIsObject);
            
            String result = jsonBody;
            
            // 构建替换模式和替换值
            String searchPattern;
            String replacement;
            
            if (originalIsArray || originalIsObject) {
                // 原始值是数组或对象，需要精确匹配整个结构
                // 转义特殊字符
                String escapedOriginal = escapeRegex(originalValue);
                searchPattern = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*" + escapedOriginal;
                
                // 新值也应该是数组或对象，不加引号
                if (newValueIsArray || newValueIsObject || newValueIsNumber) {
                    replacement = "\"" + paramName + "\":" + newValue;
                } else {
                    // 新值是字符串，加引号
                    replacement = "\"" + paramName + "\":\"" + escapeJsonValue(newValue) + "\"";
                }
                
                callbacks.printOutput("  -> 使用数组/对象替换模式");
                result = jsonBody.replaceAll(searchPattern, replacement);
                
                if (!result.equals(jsonBody)) {
                    callbacks.printOutput("  -> 数组/对象值替换成功");
                    return result;
                }
                
                // 如果正则替换失败，尝试直接字符串替换
                callbacks.printOutput("  -> 正则替换失败，尝试直接字符串替换");
                String directSearch = "\"" + paramName + "\":" + originalValue;
                String directReplacement = "\"" + paramName + "\":" + newValue;
                result = jsonBody.replace(directSearch, directReplacement);
                
                if (!result.equals(jsonBody)) {
                    callbacks.printOutput("  -> 直接字符串替换成功");
                    return result;
                }
                
            } else if (originalIsNumber) {
                // 原始值是数字
                searchPattern = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*" + escapeRegex(originalValue) + "(?=\\s*[,}])";
                
                if (newValueIsNumber) {
                    replacement = "\"" + paramName + "\":" + newValue;
                } else if (newValueIsArray || newValueIsObject) {
                    replacement = "\"" + paramName + "\":" + newValue;
                } else {
                    replacement = "\"" + paramName + "\":\"" + escapeJsonValue(newValue) + "\"";
                }
                
                callbacks.printOutput("  -> 使用数字替换模式");
                result = jsonBody.replaceAll(searchPattern, replacement);
                
                if (!result.equals(jsonBody)) {
                    callbacks.printOutput("  -> 数字值替换成功");
                    return result;
                }
                
            } else {
                // 原始值是字符串
                searchPattern = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*\"" + escapeRegex(originalValue) + "\"";
                
                if (newValueIsNumber) {
                    replacement = "\"" + paramName + "\":" + newValue;
                } else if (newValueIsArray || newValueIsObject) {
                    replacement = "\"" + paramName + "\":" + newValue;
                } else {
                    replacement = "\"" + paramName + "\":\"" + escapeJsonValue(newValue) + "\"";
                }
                
                callbacks.printOutput("  -> 使用字符串替换模式");
                result = jsonBody.replaceAll(searchPattern, replacement);
                
                if (!result.equals(jsonBody)) {
                    callbacks.printOutput("  -> 字符串值替换成功");
                    return result;
                }
            }
            
            // 如果精确匹配失败，尝试参数级兜底替换（只替换当前参数，避免误改其它同值参数）
            if (!originalValue.isEmpty()) {
                callbacks.printOutput("  -> 所有模式匹配失败，尝试参数级兜底替换");
                String finalReplacement;
                if (newValueIsNumber || newValueIsArray || newValueIsObject) {
                    finalReplacement = newValue;
                } else {
                    finalReplacement = "\"" + escapeJsonValue(newValue) + "\"";
                }

                String fallbackPattern = "(\"" + escapeRegex(paramName) + "\"\\s*:\\s*)(\"[^\"]*\"|\\[[^\\]]*\\]|\\{[^\\}]*\\}|[^,}\\]]+)";
                java.util.regex.Matcher fallbackMatcher = java.util.regex.Pattern.compile(fallbackPattern).matcher(jsonBody);
                if (fallbackMatcher.find()) {
                    String newSegment = fallbackMatcher.group(1) + finalReplacement;
                    result = fallbackMatcher.replaceFirst(java.util.regex.Matcher.quoteReplacement(newSegment));
                    if (!result.equals(jsonBody)) {
                        callbacks.printOutput("  -> 参数级兜底替换成功");
                        return result;
                    }
                }
            }
            
            callbacks.printOutput("  -> 所有替换方法都失败");
            return jsonBody;
            
        } catch (Exception e) {
            callbacks.printError("JSON值替换失败: " + e.getMessage());
            return jsonBody;
        }
    }
    
    /**
     * 转义正则表达式中的特殊字符
     */
    private String escapeRegex(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                   .replace(".", "\\.")
                   .replace("*", "\\*")
                   .replace("+", "\\+")
                   .replace("?", "\\?")
                   .replace("^", "\\^")
                   .replace("$", "\\$")
                   .replace("|", "\\|")
                   .replace("(", "\\(")
                   .replace(")", "\\)")
                   .replace("[", "\\[")
                   .replace("]", "\\]")
                   .replace("{", "\\{")
                   .replace("}", "\\}");
    }
    
    /**
     * 构建Cookie参数请求
     */
    private byte[] buildCookieParameterRequest(byte[] originalRequest, String paramName, String newValue) {
        try {
            String requestString = new String(originalRequest, StandardCharsets.UTF_8);
            String[] lines = requestString.split("\r\n");
            
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].toLowerCase().startsWith("cookie:")) {
                    String cookieLine = lines[i];
                    String[] cookies = cookieLine.substring(7).trim().split(";");
                    StringBuilder newCookieLine = new StringBuilder("Cookie: ");
                    boolean paramFound = false;
                    
                    for (int j = 0; j < cookies.length; j++) {
                        String cookie = cookies[j].trim();
                        if (cookie.startsWith(paramName + "=")) {
                            if (j > 0) newCookieLine.append("; ");
                            newCookieLine.append(paramName).append("=").append(newValue);
                            paramFound = true;
                        } else {
                            if (j > 0) newCookieLine.append("; ");
                            newCookieLine.append(cookie);
                        }
                    }
                    
                    if (paramFound) {
                        lines[i] = newCookieLine.toString();
                        String newRequestString = String.join("\r\n", lines);
                        callbacks.printOutput("  -> Cookie参数请求构建成功");
                        return newRequestString.getBytes(StandardCharsets.UTF_8);
                    }
                }
            }
            
            return originalRequest;
            
        } catch (Exception e) {
            callbacks.printError("构建Cookie参数请求失败: " + e.getMessage());
            return originalRequest;
        }
    }
    
    /**
     * 从JSON中获取原始参数值 - 改进版本，支持数组
     */
    private String getOriginalJsonValue(String jsonBody, String paramName) {
        try {
            callbacks.printOutput("  -> [getOriginalJsonValue] 查找参数: " + paramName);
            callbacks.printOutput("  -> [getOriginalJsonValue] JSON Body: " + jsonBody);
            
            // 改进的JSON值提取，支持数组和复杂值
            String pattern = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*([^,}\\]]+(?:\\[[^\\]]*\\])?[^,}\\]]*)";
            callbacks.printOutput("  -> [getOriginalJsonValue] 正则模式: " + pattern);
            
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
            java.util.regex.Matcher m = p.matcher(jsonBody);
            
            if (m.find()) {
                String value = m.group(1).trim();
                callbacks.printOutput("  -> [getOriginalJsonValue] 正则匹配成功，值: " + value);
                
                // 如果值以引号开始，提取引号内的内容
                if (value.startsWith("\"") && value.endsWith("\"")) {
                    String result = value.substring(1, value.length() - 1);
                    callbacks.printOutput("  -> [getOriginalJsonValue] 返回字符串值: " + result);
                    return result;
                }
                
                // 如果是数组或对象，返回完整的值
                if (value.startsWith("[") || value.startsWith("{")) {
                    callbacks.printOutput("  -> [getOriginalJsonValue] 检测到数组或对象，调用 extractComplexJsonValue");
                    // 需要找到匹配的结束符
                    return extractComplexJsonValue(jsonBody, paramName);
                }
                
                // 其他情况（数字、布尔值等）
                callbacks.printOutput("  -> [getOriginalJsonValue] 返回简单值: " + value);
                return value;
            }
            
            callbacks.printOutput("  -> [getOriginalJsonValue] 正则匹配失败，尝试 extractComplexJsonValue");
            // 如果正则匹配失败，直接尝试提取复杂值
            return extractComplexJsonValue(jsonBody, paramName);
            
        } catch (Exception e) {
            callbacks.printError("提取JSON值失败: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 提取复杂的JSON值（数组、对象）
     */
    private String extractComplexJsonValue(String jsonBody, String paramName) {
        try {
            callbacks.printOutput("  -> [extractComplexJsonValue] 查找参数: " + paramName);
            
            String searchPattern = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*";
            callbacks.printOutput("  -> [extractComplexJsonValue] 搜索模式: " + searchPattern);
            
            int startIndex = jsonBody.indexOf("\"" + paramName + "\"");
            callbacks.printOutput("  -> [extractComplexJsonValue] 参数名位置: " + startIndex);
            
            if (startIndex == -1) {
                callbacks.printOutput("  -> [extractComplexJsonValue] 未找到参数名");
                return null;
            }
            
            int colonIndex = jsonBody.indexOf(":", startIndex);
            if (colonIndex == -1) {
                callbacks.printOutput("  -> [extractComplexJsonValue] 未找到冒号");
                return null;
            }
            
            int valueStart = colonIndex + 1;
            while (valueStart < jsonBody.length() && Character.isWhitespace(jsonBody.charAt(valueStart))) {
                valueStart++;
            }
            
            callbacks.printOutput("  -> [extractComplexJsonValue] 值开始位置: " + valueStart);
            
            if (valueStart >= jsonBody.length()) {
                callbacks.printOutput("  -> [extractComplexJsonValue] 值开始位置超出范围");
                return null;
            }
            
            char firstChar = jsonBody.charAt(valueStart);
            callbacks.printOutput("  -> [extractComplexJsonValue] 第一个字符: " + firstChar);
            
            char endChar;
            
            if (firstChar == '[') {
                endChar = ']';
            } else if (firstChar == '{') {
                endChar = '}';
            } else if (firstChar == '"') {
                // 字符串值
                int endIndex = jsonBody.indexOf('"', valueStart + 1);
                if (endIndex != -1) {
                    String result = jsonBody.substring(valueStart, endIndex + 1);
                    callbacks.printOutput("  -> [extractComplexJsonValue] 返回字符串: " + result);
                    return result;
                }
                callbacks.printOutput("  -> [extractComplexJsonValue] 字符串未闭合");
                return null;
            } else {
                // 简单值（数字、布尔值等）
                int endIndex = valueStart;
                while (endIndex < jsonBody.length()) {
                    char c = jsonBody.charAt(endIndex);
                    if (c == ',' || c == '}' || c == ']' || Character.isWhitespace(c)) {
                        break;
                    }
                    endIndex++;
                }
                String result = jsonBody.substring(valueStart, endIndex).trim();
                callbacks.printOutput("  -> [extractComplexJsonValue] 返回简单值: " + result);
                return result;
            }
            
            // 处理嵌套的数组或对象
            callbacks.printOutput("  -> [extractComplexJsonValue] 处理嵌套结构，开始字符: " + firstChar + ", 结束字符: " + endChar);
            int depth = 1;
            int currentIndex = valueStart + 1;
            
            while (currentIndex < jsonBody.length() && depth > 0) {
                char c = jsonBody.charAt(currentIndex);
                if (c == firstChar) {
                    depth++;
                } else if (c == endChar) {
                    depth--;
                }
                currentIndex++;
            }
            
            callbacks.printOutput("  -> [extractComplexJsonValue] 结束位置: " + currentIndex + ", depth: " + depth);
            
            if (depth == 0) {
                String result = jsonBody.substring(valueStart, currentIndex);
                callbacks.printOutput("  -> [extractComplexJsonValue] 返回复杂值: " + result);
                return result;
            }
            
            callbacks.printOutput("  -> [extractComplexJsonValue] 括号未匹配");
            return null;
        } catch (Exception e) {
            callbacks.printError("提取复杂JSON值失败: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 转义JSON值中的特殊字符
     */
    private String escapeJsonValue(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t")
                   .replace("\b", "\\b")
                   .replace("\f", "\\f");
    }
    
    /**
     * 构建JSON请求，确保UTF-8编码
     * 基于daimabak.txt中的实现
     */
    private byte[] buildJsonRequestWithUTF8(IHttpRequestResponse originalRequest, IParameter param, String newValue) {
        try {
            callbacks.printOutput("  -> 构建JSON请求（UTF-8编码）");
            
            // 使用helpers.updateParameter，但确保中文字符正确处理
            byte[] updatedRequest = helpers.updateParameter(originalRequest.getRequest(), 
                helpers.buildParameter(param.getName(), newValue, param.getType()));
            
            callbacks.printOutput("  -> JSON请求构建成功，字节长度: " + updatedRequest.length);
            return updatedRequest;
            
        } catch (Exception e) {
            callbacks.printError("构建JSON请求失败: " + e.getMessage());
            return originalRequest.getRequest();
        }
    }
    
    /**
     * 检测响应变化 - 实现完整的检测逻辑，包括错误关键字检测
     */
    private String detectChange(IHttpRequestResponse response, String dataMd5, String testValue, long responseTime) {
        try {
            callbacks.printOutput("  -> [detectChange] 方法开始执行");
            
            if (response == null || response.getResponse() == null) {
                callbacks.printOutput("  -> [detectChange] 响应为null，返回");
                return "无响应";
            }
            
            callbacks.printOutput("  -> [detectChange] 开始分析响应");
            IResponseInfo responseInfo = helpers.analyzeResponse(response.getResponse());
            int bodyOffset = responseInfo.getBodyOffset();
            int responseLength = response.getResponse().length - bodyOffset;  // 只计算响应体长度
            int statusCode = responseInfo.getStatusCode();
            
           // callbacks.printOutput("  -> [detectChange] 检测变化: 状态码=" + statusCode + ", 响应体长度=" + responseLength + ", 时间=" + responseTime + "ms");
            
            // 获取完整响应用于错误关键字检测
          //  callbacks.printOutput("  -> [detectChange] 准备获取响应字符串");
            String responseString = new String(response.getResponse(), StandardCharsets.UTF_8);
           // callbacks.printOutput("  -> [detectChange] 响应字符串长度: " + responseString.length());
            
            // 优先级1：检查时间延迟（最高优先级）
           // callbacks.printOutput("  -> [detectChange] 检查时间延迟");
            boolean isTimeExceeded = responseTime >= burpExtender.config.getResponseTimeThreshold();
           // callbacks.printOutput("  -> [detectChange] 时间延迟检查结果: " + isTimeExceeded);
            
            // 优先级2：检查是否包含错误信息
            //callbacks.printOutput("  -> [detectChange] 准备检查错误关键字");
            boolean hasError = containsErrorKeywords(responseString);
           // callbacks.printOutput("  -> [detectChange] 错误关键字检查结果: " + hasError);
            
            // 优先级3：检查长度差异（布尔盲注）
            //callbacks.printOutput("  -> [detectChange] 准备检查长度差异");
            // 使用原始响应长度作为基准
            Integer originalLength = burpExtender.originalResponseLengths.get(dataMd5);
            boolean hasLengthDiff = false;
            String lengthDiffInfo = "";
            
           // callbacks.printOutput("  -> 长度差异检测: 原始长度=" + originalLength + ", 当前长度=" + responseLength + ", 阈值=" + burpExtender.config.getLengthDiffThreshold());
            
            // 如果有原始响应长度，检查长度差异
            if (originalLength != null && originalLength != responseLength) {
                // 计算差异：当前长度 - 原始长度
                // 正数表示变大，负数表示变小
                int lengthDiff = responseLength - originalLength;
                callbacks.printOutput("  -> 长度差异: " + lengthDiff + " (当前:" + responseLength + " - 原始:" + originalLength + ")");
                
                // 检查是否超过配置的阈值
                if (Math.abs(lengthDiff) >= burpExtender.config.getLengthDiffThreshold()) {
                    hasLengthDiff = true;
                    // 格式化差异值，确保显示正负号
                    String diffStr = lengthDiff > 0 ? "+" + lengthDiff : String.valueOf(lengthDiff);
                    lengthDiffInfo = "diff " + diffStr;
                    // callbacks.printOutput("  -> ✓ 长度差异超过阈值，标记为diff");
                    // callbacks.printOutput("  -> 调用 updateScanResultState(dataMd5, \"diff\")");
                    updateScanResultState(dataMd5, "diff");
                } else {
                    // 未超过阈值，不显示差异值
                    lengthDiffInfo = "";
                    // callbacks.printOutput("  -> 长度差异未超过阈值: " + Math.abs(lengthDiff) + " < " + burpExtender.config.getLengthDiffThreshold());
                    // callbacks.printOutput("  -> 不标记diff，不显示差异值");
                }
            } else if (originalLength == null) {
                callbacks.printOutput("  -> 警告: 原始响应长度为null，无法比较");
            } else {
                callbacks.printOutput("  -> 长度相同，无差异");
            }
            
            // 按优先级返回结果
            // callbacks.printOutput("  -> [detectChange] 准备返回结果");
            // callbacks.printOutput("  -> isTimeExceeded=" + isTimeExceeded + ", hasError=" + hasError + ", hasLengthDiff=" + hasLengthDiff);
            // callbacks.printOutput("  -> lengthDiffInfo=[" + lengthDiffInfo + "]");
            
            if (isTimeExceeded) {
                // 时间延迟优先级最高 - 显示配置的阈值而不是实际时间
                updateScanResultState(dataMd5, "time");
                double thresholdSeconds = burpExtender.config.getResponseTimeThreshold() / 1000.0;
               // callbacks.printOutput("  -> [detectChange] 返回: time > " + thresholdSeconds + "s");
                return "time > " + thresholdSeconds + "s";
            } else if (hasError) {
                // 错误信息优先级第二
                updateScanResultState(dataMd5, "err");
               // callbacks.printOutput("  -> [detectChange] 返回: ERR!");
                return "ERR!";
            } else if (hasLengthDiff) {
                // 长度差异优先级第三
              //  callbacks.printOutput("  -> [detectChange] 返回: " + lengthDiffInfo + " (hasLengthDiff=true)");
                return lengthDiffInfo;
            } else if (!lengthDiffInfo.isEmpty()) {
                // 显示长度差异信息（即使不显著）
               // callbacks.printOutput("  -> [detectChange] 返回: " + lengthDiffInfo + " (仅显示差异值，不标记)");
                return lengthDiffInfo;
            } else {
                // 无明显异常
              //  callbacks.printOutput("  -> [detectChange] 返回: 空字符串（无异常）");
                return "";
            }
            
        } catch (Exception e) {
           // callbacks.printError("检测变化失败: " + e.getMessage());
            return "检测失败";
        }
    }
            
    /**
     * 分析响应结果（只保存 payload）
     */
    private void analyzeResponseWithWorkingValue(IHttpRequestResponse response, String paramName, String originalValue, 
                                               String payload, String dataMd5, long responseTime, int toolFlag) {
        try {
            callbacks.printOutput("  -> === analyzeResponseWithWorkingValue开始 ===");
            callbacks.printOutput("  -> 参数: " + paramName + ", 原始值: " + originalValue + ", Payload: " + payload + ", MD5: " + dataMd5);
            
            if (response == null) {
                callbacks.printOutput("  -> 错误: response为null");
                return;
            }
            
            if (response.getResponse() == null) {
                callbacks.printOutput("  -> 警告: 响应为空");
                return;
            }
            
            // 检查响应过滤条件 - 只针对当前payload测试的响应
            if (!responseFilter.shouldProcessResponse(response, burpExtender.config.getResponseFilterConfig())) {
                callbacks.printOutput("  -> 响应不符合过滤条件，跳过此payload测试: " + payload);
                return;
            }
            
            IResponseInfo responseInfo = helpers.analyzeResponse(response.getResponse());
            int bodyOffset = responseInfo.getBodyOffset();
            int responseLength = response.getResponse().length - bodyOffset;  // 只计算响应体长度
            String statusCode = String.valueOf(responseInfo.getStatusCode());
            
            callbacks.printOutput("  -> 响应分析: 状态码=" + statusCode + ", 响应体长度=" + responseLength + ", 时间=" + responseTime + "ms");
            
            // 检测变化（使用完整的测试值进行检测）
            String fullTestValue = originalValue + payload;
            String change = detectChange(response, dataMd5, fullTestValue, responseTime);
            callbacks.printOutput("  -> 检测到变化: " + change);
            
            // 创建Payload详情条目 - 只保存 payload
            callbacks.printOutput("  -> 准备创建LogEntry");
            callbacks.printOutput("  -> 使用MD5: " + dataMd5 + " (应该与扫描结果MD5匹配)");
            LogEntry payloadDetail = new LogEntry(
                burpExtender.ui.payloadDetails.size() + 1,
                paramName,
                payload, // 只保存 payload，不保存完整的测试值
                change,
                responseLength,
                (int)responseTime,
                statusCode,
                response,
                dataMd5,
                toolFlag // 传递正确的工具标识
            );
            
            callbacks.printOutput("  -> LogEntry创建成功，准备添加到UI");
            callbacks.printOutput("  -> PayloadDetail MD5: " + payloadDetail.getDataMd5());
            callbacks.printOutput("  -> 当前payloadDetails大小: " + burpExtender.ui.payloadDetails.size());
            
            // 添加到UI
            burpExtender.ui.addPayloadDetail(payloadDetail);
            callbacks.printOutput("  -> addPayloadDetail调用完成");
            callbacks.printOutput("  -> 新的payloadDetails大小: " + burpExtender.ui.payloadDetails.size());
            callbacks.printOutput("  -> Payload详情已添加到UI（只保存了payload）");
            
            // 更新扫描结果的响应长度（使用第一个响应的长度）
            updateScanResultResponseLength(dataMd5, responseLength);
            
            callbacks.printOutput("  -> === analyzeResponseWithWorkingValue结束 ===");
            
        } catch (Exception e) {
            callbacks.printError("分析响应失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 对参数值进行URL编码 - 基于test.txt中的URLencode方法
     */
    private String urlEncodeForParameter(String value) {
        try {
            // 使用UTF-8编码，这样中文字符会被正确编码
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            callbacks.printError("URL编码失败: " + e.getMessage());
            return value; // 编码失败时返回原值
        }
    }
    
    /**
     * 是否应该清空参数值
     */
    private boolean shouldEmptyValue(String payload) {
        // 简化实现 - 对于非基础payload，如果配置了参数值置空则清空
        return !payload.equals("'") && !payload.equals("''") && !payload.equals("-1") && !payload.equals("-0");
    }

    
    /**
     * 检查响应是否包含错误关键字 - 改进版本，支持正则表达式和普通字符串匹配
     */
    private boolean containsErrorKeywords(String responseString) {
        List<String> errorKeywords = burpExtender.config.getErrorKeywords();
        if (errorKeywords.isEmpty() || responseString.isEmpty()) {
            callbacks.printOutput("  -> 错误关键字检测: 关键字列表为空或响应为空");
            return false;
        }
        
        callbacks.printOutput("  -> 开始错误关键字检测，关键字数量: " + errorKeywords.size());
        
        for (String keyword : errorKeywords) {
            try {
                boolean matched = false;
                
                // 检查是否是正则表达式模式
                if (keyword.contains("\\\\") || keyword.contains(".*") || keyword.contains("\\\\d") || 
                    keyword.contains("[") || keyword.contains("]") || keyword.contains("^") || keyword.contains("$")) {
                    // 正则表达式匹配
                    try {
                        matched = responseString.matches("[\\s\\S]*" + keyword + "[\\s\\S]*");
                        callbacks.printOutput("  -> 正则表达式匹配: " + keyword + " -> " + matched);
                    } catch (Exception regexException) {
                        // 正则表达式错误，降级为普通字符串匹配
                        matched = responseString.toLowerCase().contains(keyword.toLowerCase());
                        callbacks.printOutput("  -> 正则表达式失败，使用普通匹配: " + keyword + " -> " + matched);
                    }
                } else {
                    // 普通字符串匹配（不区分大小写）
                    matched = responseString.toLowerCase().contains(keyword.toLowerCase());
                    //callbacks.printOutput("  -> 普通字符串匹配: " + keyword + " -> " + matched);
                }
                
                if (matched) {
                    callbacks.printOutput("  -> ✓ 检测到错误关键字: " + keyword);
                    return true;
                }
            } catch (Exception e) {
                callbacks.printOutput("  -> 关键字匹配异常: " + keyword + " - " + e.getMessage());
                // 继续检查下一个关键字
            }
        }
        
        callbacks.printOutput("  -> 未检测到任何错误关键字");
        return false;
    }
    
    // 存储基准长度的Map
    private static final Map<String, Integer> baselineLengths = new HashMap<>();
    
    /**
     * 获取基准长度
     */
    private Integer getBaselineLength(String dataMd5) {
        Integer baseline = baselineLengths.get(dataMd5);
        callbacks.printOutput("  -> 获取基准长度: MD5=" + dataMd5 + ", 基准长度=" + baseline);
        return baseline;
    }
    
    /**
     * 设置基准长度
     */
    private void setBaselineLength(String dataMd5, int length) {
        baselineLengths.put(dataMd5, length);
        callbacks.printOutput("  -> 设置基准长度: MD5=" + dataMd5 + ", 长度=" + length + ", 当前存储数量=" + baselineLengths.size());
    }
    
    /**
     * 更新扫描结果状态 - 改进版本，支持多个检测结果累积显示
     */
    private void updateScanResultState(String dataMd5, String newState) {
        // 在UI线程中更新
        SwingUtilities.invokeLater(() -> {
            synchronized (burpExtender.ui.scanResults) {
                for (int i = 0; i < burpExtender.ui.scanResults.size(); i++) {
                    LogEntry entry = burpExtender.ui.scanResults.get(i);
                    if (entry.getDataMd5().equals(dataMd5)) {
                        String currentState = entry.getState();
                        String finalState = newState;
                        
                        // 如果是超时状态，不更新扫描结果状态（只在payload详情中显示）
                        if (newState.equals("timeout")) {
                            callbacks.printOutput("请求超时，不更新扫描结果状态: " + dataMd5);
                            return; // 直接返回，不更新状态
                        }
                        // 如果是结束状态，收集所有检测结果
                        else if (newState.equals("end")) {
                            Set<String> detectionTypes = new HashSet<>();
                            boolean hasDiff = false;
                            boolean hasTimeout = false;
                            
                            synchronized (burpExtender.ui.payloadDetails) {
                                for (LogEntry detail : burpExtender.ui.payloadDetails) {
                                    if (detail.getDataMd5().equals(dataMd5)) {
                                        String change = detail.getChange();
                                        if (change.contains("time >")) {
                                            detectionTypes.add("TIME");
                                        }
                                        if (change.contains("ERR!")) {
                                            detectionTypes.add("ERR");
                                        }
                                        if (change.contains("✔")) {
                                            detectionTypes.add("BOOL");
                                        }
                                        if (change.contains("timeout>")) {
                                            hasTimeout = true;
                                        }
                                        if (change.contains("diff") && !change.contains("✔")) {
                                            hasDiff = true;
                                        }
                                    }
                                }
                            }
                            
                            // 构建最终状态字符串
                            StringBuilder stateBuilder = new StringBuilder("end!");
                            
                            // 按优先级添加检测结果（不包括timeout）
                            if (detectionTypes.contains("TIME")) {
                                stateBuilder.append(" TIME");
                            }
                            if (detectionTypes.contains("ERR")) {
                                stateBuilder.append(" ERR");
                            }
                            if (detectionTypes.contains("BOOL")) {
                                stateBuilder.append(" BOOL");
                            }
                            if (hasDiff) {
                                // 总是显示diff（如果检测到）
                                stateBuilder.append(" DIFF");
                            }
                            
                            finalState = stateBuilder.toString();
                        }
                        // 累积状态：如果当前状态已经包含某个标记，保留它
                        else if (!currentState.isEmpty() && !currentState.equals("start") && !currentState.equals("paused")) {
                            // 解析当前状态中的标记
                            Set<String> existingStates = new HashSet<>();
                            if (currentState.contains("time")) existingStates.add("time");
                            if (currentState.contains("err")) existingStates.add("err");
                            if (currentState.contains("diff")) existingStates.add("diff");
                            if (currentState.contains("timeout")) existingStates.add("timeout");
                            
                            // 添加新状态
                            existingStates.add(newState);
                            
                            // 按优先级构建状态字符串：time > err > diff
                            StringBuilder stateBuilder = new StringBuilder();
                            if (existingStates.contains("timeout")) {
                                int timeoutSeconds = burpExtender.config.getRequestTimeout() / 1000;
                                stateBuilder.append("timeout>").append(timeoutSeconds).append("s");
                            } else if (existingStates.contains("time")) {
                                stateBuilder.append("time");
                            } else if (existingStates.contains("err")) {
                                stateBuilder.append("err");
                                // 如果有err，也显示diff（如果存在）
                                if (existingStates.contains("diff")) {
                                    stateBuilder.append("+diff");
                                }
                            } else if (existingStates.contains("diff")) {
                                stateBuilder.append("diff");
                            }
                            
                            finalState = stateBuilder.toString();
                        }
                        
                        // 直接更新状态（使用新的 setter 方法）
                        entry.setState(finalState);
                        
                        // 通知表格模型数据已更改（使用public方法）
                        burpExtender.ui.refreshScanResultsTable();
                        callbacks.printOutput("扫描结果状态已更新: " + dataMd5 + " -> " + finalState);
                        break;
                    }
                }
            }
        });
    }
    
    /**
     * 更新扫描结果的响应长度 - 3.0.7版本新增
     * 注意：现在响应长度在创建扫描结果时就已经设置了，这个方法不再需要更新
     */
    private void updateScanResultResponseLength(String dataMd5, int responseLength) {
        // 响应长度已经在创建扫描结果时设置为原始响应长度，不需要再更新
        callbacks.printOutput("跳过响应长度更新（已在创建时设置）: " + dataMd5);
    }
    
    /**
     * 编码修复 - 基于daimabak.txt中的成功实现
     */
    public IHttpRequestResponse fixEncodingIssues(IHttpRequestResponse original) {
       // callbacks.printOutput("=== 右键菜单编码修复开始 ===");
        
        try {
            // 获取原始请求字符串
            String requestString = new String(original.getRequest(), StandardCharsets.UTF_8);
           // callbacks.printOutput("原始请求字符串长度: " + requestString.length());
            
            // 尝试用不同编码重新解释请求字符串
            String[] encodings = {"UTF-8", "GBK", "GB2312", "ISO-8859-1"};
            String bestRequestString = requestString;
            
            for (String encoding : encodings) {
                try {
                    // 将字符串转为字节再用指定编码重新解释
                    byte[] requestBytes = requestString.getBytes("ISO-8859-1");
                    String reinterpreted = new String(requestBytes, encoding);
                    
                    // 检查是否包含中文字符
                    boolean hasChinese = reinterpreted.matches(".*[\\u4e00-\\u9fa5].*");
                    boolean hasValidChars = !reinterpreted.matches(".*[\\uFFFD\\u00C0-\\u00FF].*");
                    
                    //callbacks.printOutput("编码 " + encoding + " 重新解释: 包含中文=" + hasChinese + ", 无乱码=" + hasValidChars);
                    
                    if (hasChinese && hasValidChars) {
                        callbacks.printOutput("使用编码 " + encoding + " 修复请求");
                        bestRequestString = reinterpreted;
                        break;
                    }
                } catch (Exception e) {
                    callbacks.printOutput("编码 " + encoding + " 处理失败: " + e.getMessage());
                }
            }
            
            // 如果找到了更好的编码，重新构建请求
            if (!bestRequestString.equals(requestString)) {
                try {
                    // 使用修复后的字符串创建新的请求
                    byte[] fixedRequestBytes = bestRequestString.getBytes(StandardCharsets.UTF_8);
                    callbacks.printOutput("成功创建编码修复后的请求");
                    
                    // 创建新的请求响应对象
                    final byte[] finalFixedRequest = fixedRequestBytes;
                    
                    IHttpRequestResponse fixedRequestResponse = new IHttpRequestResponse() {
                        @Override
                        public byte[] getRequest() {
                            return finalFixedRequest;
                        }
                        
                        @Override
                        public void setRequest(byte[] message) {
                            // 不实现，因为这是只读的
                        }
                        
                        @Override
                        public byte[] getResponse() {
                            return original.getResponse();
                        }
                        
                        @Override
                        public void setResponse(byte[] message) {
                            // 不实现，因为这是只读的
                        }
                        
                        @Override
                        public String getComment() {
                            return original.getComment();
                        }
                        
                        @Override
                        public void setComment(String comment) {
                            original.setComment(comment);
                        }
                        
                        @Override
                        public String getHighlight() {
                            return original.getHighlight();
                        }
                        
                        @Override
                        public void setHighlight(String color) {
                            original.setHighlight(color);
                        }
                        
                        @Override
                        public IHttpService getHttpService() {
                            return original.getHttpService();
                        }
                        
                        @Override
                        public void setHttpService(IHttpService httpService) {
                            original.setHttpService(httpService);
                        }
                    };
                    
                    callbacks.printOutput("=== 编码修复完成 ===");
                    return fixedRequestResponse;
                } catch (Exception e) {
                    callbacks.printOutput("创建修复请求失败: " + e.getMessage());
                }
            }
            
            callbacks.printOutput("=== 编码修复完成（无需修复）===");
            return original;
            
        } catch (Exception e) {
            callbacks.printError("编码修复过程出错: " + e.getMessage());
            return original;
        }
    }
    
    /**
     * 是否应该跳过参数
     */
    private boolean shouldSkipParameter(IParameter param) {
        // 首先检查参数类型是否支持
        byte paramType = param.getType();
        String paramTypeName = getParameterTypeName(paramType);
        
        // 只支持这些参数类型
        if (paramType != IParameter.PARAM_URL && 
            paramType != IParameter.PARAM_BODY && 
            paramType != IParameter.PARAM_JSON &&
            paramType != IParameter.PARAM_COOKIE) {
            callbacks.printOutput("跳过不支持的参数类型: " + param.getName() + " (类型: " + paramType + " - " + paramTypeName + ")");
            return true; // 不支持的参数类型直接跳过
        }
        
        // Cookie参数需要特殊检查
        if (paramType == IParameter.PARAM_COOKIE) {
            if (!burpExtender.testCookie) {
                return true; // Cookie测试未启用，跳过
            }
        }
        
        // 跳过一些明显不需要测试的参数（Cookie参数除外）
        // 当开启Cookie测试时，Cookie即使是__Host/__Secure前缀也应允许进入测试流程
        if (paramType != IParameter.PARAM_COOKIE) {
            String paramName = param.getName().toLowerCase();
            if (paramName.equals("csrf_token") || paramName.equals("_token") ||
                paramName.equals("authenticity_token") || paramName.startsWith("__")) {
                return true;
            }
        }
        
        // 检查参数过滤配置
        return shouldSkipByParamFilter(param.getName());
    }
    
    /**
     * 根据参数过滤配置判断是否跳过参数
     */
    private boolean shouldSkipByParamFilter(String paramName) {
        int filterMode = burpExtender.config.getParamFilterMode();
        
        switch (filterMode) {
            case 0: // 无过滤
                return false;
                
            case 1: // 白名单模式 - 只测试白名单中的参数
                List<String> whitelistParams = burpExtender.config.getWhitelistParams();
                boolean inWhitelist = whitelistParams.contains(paramName);
                if (!inWhitelist) {
                    callbacks.printOutput("参数 '" + paramName + "' 不在白名单中，跳过测试");
                }
                return !inWhitelist;
                
            case 2: // 黑名单模式 - 跳过黑名单中的参数
                List<String> blacklistParams = burpExtender.config.getBlacklistParams();
                boolean inBlacklist = blacklistParams.contains(paramName);
                if (inBlacklist) {
                    callbacks.printOutput("参数 '" + paramName + "' 在黑名单中，跳过测试");
                }
                return inBlacklist;
                
            default:
                return false;
        }
    }
    
    /**
     * 获取参数数量
     */
    private int getParameterCount(IRequestInfo requestInfo) {
        return requestInfo.getParameters().size();
    }

    /**
     * 是否存在可测试参数
     */
    private boolean hasTestableParameters(IHttpRequestResponse originalRequest, IRequestInfo requestInfo) {
        try {
            List<IParameter> parameters = requestInfo.getParameters();

            // 预估追加参数生效后的参数集合，保持与实际测试逻辑一致
            if (burpExtender.config.isAppendParamsEnabled()) {
                IHttpRequestResponse workingRequest = addAppendParamsToRequest(originalRequest, requestInfo);
                if (workingRequest != originalRequest) {
                    IRequestInfo updatedRequestInfo = helpers.analyzeRequest(workingRequest);
                    parameters = updatedRequestInfo.getParameters();
                }
            }

            for (IParameter param : parameters) {
                if (shouldSkipParameter(param)) {
                    continue;
                }

                // 追加参数未勾选“参与测试”时跳过
                if (burpExtender.config.isAppendParamsEnabled() &&
                    burpExtender.config.getAppendParams().containsKey(param.getName()) &&
                    !burpExtender.config.getTestableAppendParams().contains(param.getName())) {
                    continue;
                }

                return true;
            }
            return false;
        } catch (Exception e) {
            callbacks.printError("可测试参数预检查失败，按可测试处理: " + e.getMessage());
            return true;
        }
    }

    /**
     * 生成请求去重指纹：方法 + 协议 + 主机 + 端口 + 路径 + 参数结构
     */
    private String generateRequestFingerprint(IRequestInfo requestInfo) {
        try {
            java.net.URL urlObj = requestInfo.getUrl();
            String method = requestInfo.getMethod().toUpperCase(Locale.ROOT);
            String protocol = urlObj.getProtocol().toLowerCase(Locale.ROOT);
            String host = urlObj.getHost().toLowerCase(Locale.ROOT);
            int port = urlObj.getPort() != -1 ? urlObj.getPort() : urlObj.getDefaultPort();
            String path = urlObj.getPath() != null ? urlObj.getPath() : "/";

            List<String> parameterKeys = new ArrayList<>();
            for (IParameter param : requestInfo.getParameters()) {
                byte type = param.getType();
                if (type == IParameter.PARAM_URL ||
                    type == IParameter.PARAM_BODY ||
                    type == IParameter.PARAM_JSON ||
                    type == IParameter.PARAM_COOKIE) {
                    parameterKeys.add(type + ":" + param.getName().toLowerCase(Locale.ROOT));
                }
            }

            if (burpExtender.config.isAppendParamsEnabled()) {
                for (String appendParam : burpExtender.config.getTestableAppendParams()) {
                    parameterKeys.add("APPEND:" + appendParam.toLowerCase(Locale.ROOT));
                }
            }
            Collections.sort(parameterKeys);

            return method + "|" + protocol + "|" + host + "|" + port + "|" + path + "|" + String.join("&", parameterKeys);
        } catch (Exception e) {
            return requestInfo.getMethod() + "|" + requestInfo.getUrl().toString();
        }
    }
    
    /**
     * 生成MD5
     */
    private String generateMd5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (Exception e) {
            return String.valueOf(input.hashCode());
        }
    }
    
    /**
     * 获取参数类型名称
     */
    private String getParameterTypeName(byte paramType) {
        switch (paramType) {
            case IParameter.PARAM_URL: return "URL参数";
            case IParameter.PARAM_BODY: return "POST参数";
            case IParameter.PARAM_COOKIE: return "Cookie参数";
            case IParameter.PARAM_XML: return "XML参数";
            case IParameter.PARAM_XML_ATTR: return "XML属性";
            case IParameter.PARAM_MULTIPART_ATTR: return "多部分属性";
            case IParameter.PARAM_JSON: return "JSON参数";
            default: return "未知类型(" + paramType + ")";
        }
    }
    
    /**
     * 获取当前时间戳
     */
    private String getCurrentTimestamp() {
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    }
    
    /**
     * 在发送请求前应用延时配置
     */
    private void applyDelayBeforeRequest() {
        if (burpExtender.config == null) {
            return;
        }
        
        int delayMode = burpExtender.config.getDelayMode();
        
        switch (delayMode) {
            case 0: // 无延时
                callbacks.printOutput("  -> 延时模式: 无延时");
                break;
                
            case 1: // 固定延时
                int fixedDelay = burpExtender.config.getFixedDelay();
                callbacks.printOutput("  -> 延时模式: 固定延时 " + fixedDelay + "ms");
                try {
                    Thread.sleep(fixedDelay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    callbacks.printOutput("  -> 延时被中断");
                }
                break;
                
            case 2: // 随机延时
                int minDelay = burpExtender.config.getRandomDelayMin();
                int maxDelay = burpExtender.config.getRandomDelayMax();
                int randomDelay = minDelay + (int)(Math.random() * (maxDelay - minDelay));
                callbacks.printOutput("  -> 延时模式: 随机延时 " + randomDelay + "ms (范围: " + minDelay + "-" + maxDelay + "ms)");
                try {
                    Thread.sleep(randomDelay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    callbacks.printOutput("  -> 延时被中断");
                }
                break;
                
            default:
                callbacks.printOutput("  -> 未知延时模式: " + delayMode);
                break;
        }
    }
    
    /**
     * 获取工具名称
     * 基于daimabak.txt中的实现
     */
    private String getToolName(int toolFlag) {
        switch (toolFlag) {
            case 4: return "Proxy";
            case 16: return "Scanner";
            case 32: return "Intruder";
            case 64: return "Repeater";
            case 1024: return "Menu";
            default: return String.valueOf(toolFlag);
        }
    }
    
    /**
     * 添加追加参数到请求中
     */
    private IHttpRequestResponse addAppendParamsToRequest(IHttpRequestResponse originalRequest, IRequestInfo requestInfo) {
        try {
            callbacks.printOutput("=== addAppendParamsToRequest 调试开始 ===");
            callbacks.printOutput("追加参数启用状态: " + burpExtender.config.isAppendParamsEnabled());
            
            if (!burpExtender.config.isAppendParamsEnabled()) {
                callbacks.printOutput("追加参数功能已禁用，直接返回原始请求");
                return originalRequest;
            }
            
            Map<String, String> appendParams = burpExtender.config.getAppendParams();
            callbacks.printOutput("获取到的追加参数数量: " + appendParams.size());
            
            if (appendParams.isEmpty()) {
                callbacks.printOutput("追加参数配置为空，跳过添加");
                return originalRequest;
            }
            
            callbacks.printOutput("=== 开始添加追加参数 ===");
            callbacks.printOutput("追加参数数量: " + appendParams.size());
            
            byte[] modifiedRequest = originalRequest.getRequest();
            
            // 根据请求类型添加参数
            String method = requestInfo.getMethod();
            String contentType = getContentType(originalRequest.getRequest());
            
            callbacks.printOutput("请求方法: " + method);
            callbacks.printOutput("Content-Type: " + contentType);
            
            if ("GET".equalsIgnoreCase(method)) {
                // GET请求：添加到URL参数
                modifiedRequest = addAppendParamsToUrl(modifiedRequest, appendParams);
            } else if ("POST".equalsIgnoreCase(method)) {
                if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                    // JSON请求：添加到JSON体
                    modifiedRequest = addAppendParamsToJson(modifiedRequest, appendParams);
                } else {
                    // 表单请求：添加到POST参数
                    modifiedRequest = addAppendParamsToForm(modifiedRequest, appendParams);
                }
            } else {
                // 其他方法：尝试添加到URL参数
                modifiedRequest = addAppendParamsToUrl(modifiedRequest, appendParams);
            }
            
            if (modifiedRequest != originalRequest.getRequest()) {
                callbacks.printOutput("追加参数添加成功");
                // 创建新的请求响应对象
                return createModifiedRequestResponse(originalRequest, modifiedRequest);
            } else {
                callbacks.printOutput("追加参数添加失败或无需添加");
                return originalRequest;
            }
            
        } catch (Exception e) {
            callbacks.printError("添加追加参数失败: " + e.getMessage());
            e.printStackTrace();
            return originalRequest;
        } finally {
            callbacks.printOutput("=== addAppendParamsToRequest 调试结束 ===");
        }
    }
    
    /**
     * 获取Content-Type头
     */
    private String getContentType(byte[] request) {
        try {
            String requestString = new String(request, StandardCharsets.UTF_8);
            String[] lines = requestString.split("\r\n");
            
            for (String line : lines) {
                if (line.toLowerCase().startsWith("content-type:")) {
                    return line.substring(13).trim();
                }
            }
        } catch (Exception e) {
            // 忽略错误
        }
        return null;
    }
    
    /**
     * 添加追加参数到URL
     */
    private byte[] addAppendParamsToUrl(byte[] originalRequest, Map<String, String> appendParams) {
        try {
            String requestString = new String(originalRequest, StandardCharsets.UTF_8);
            String[] lines = requestString.split("\r\n");
            
            if (lines.length > 0) {
                String requestLine = lines[0];
                String[] parts = requestLine.split(" ");
                if (parts.length >= 2) {
                    String method = parts[0];
                    String url = parts[1];
                    String httpVersion = parts.length > 2 ? parts[2] : "HTTP/1.1";
                    
                    // 构建追加参数字符串
                    StringBuilder appendParamString = new StringBuilder();
                    for (Map.Entry<String, String> entry : appendParams.entrySet()) {
                        if (appendParamString.length() > 0) {
                            appendParamString.append("&");
                        }
                        appendParamString.append(entry.getKey()).append("=").append(entry.getValue());
                    }
                    
                    // 添加到URL
                    String newUrl;
                    if (url.contains("?")) {
                        newUrl = url + "&" + appendParamString.toString();
                    } else {
                        newUrl = url + "?" + appendParamString.toString();
                    }
                    
                    // 重构请求行
                    lines[0] = method + " " + newUrl + " " + httpVersion;
                    String newRequestString = String.join("\r\n", lines);
                    
                    callbacks.printOutput("URL追加参数成功: " + appendParamString.toString());
                    return newRequestString.getBytes(StandardCharsets.UTF_8);
                }
            }
        } catch (Exception e) {
            callbacks.printError("添加URL追加参数失败: " + e.getMessage());
        }
        return originalRequest;
    }
    
    /**
     * 添加追加参数到表单
     */
    private byte[] addAppendParamsToForm(byte[] originalRequest, Map<String, String> appendParams) {
        try {
            String requestString = new String(originalRequest, StandardCharsets.UTF_8);
            String[] parts = requestString.split("\r\n\r\n", 2);
            
            if (parts.length > 1) {
                String headers = parts[0];
                String body = parts[1];
                
                // 构建追加参数字符串
                StringBuilder appendParamString = new StringBuilder();
                for (Map.Entry<String, String> entry : appendParams.entrySet()) {
                    if (appendParamString.length() > 0) {
                        appendParamString.append("&");
                    }
                    appendParamString.append(entry.getKey()).append("=").append(entry.getValue());
                }
                
                // 添加到请求体
                String newBody;
                if (body.trim().isEmpty()) {
                    newBody = appendParamString.toString();
                } else {
                    newBody = body + "&" + appendParamString.toString();
                }
                
                // 更新Content-Length头
                String newHeaders = updateContentLength(headers, newBody.getBytes(StandardCharsets.UTF_8).length);
                
                String newRequestString = newHeaders + "\r\n\r\n" + newBody;
                
                callbacks.printOutput("表单追加参数成功: " + appendParamString.toString());
                return newRequestString.getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            callbacks.printError("添加表单追加参数失败: " + e.getMessage());
        }
        return originalRequest;
    }
    
    /**
     * 添加追加参数到JSON - 改进版本，支持嵌套JSON
     */
    private byte[] addAppendParamsToJson(byte[] originalRequest, Map<String, String> appendParams) {
        try {
            String requestString = new String(originalRequest, StandardCharsets.UTF_8);
            String[] parts = requestString.split("\r\n\r\n", 2);
            
            if (parts.length > 1) {
                String headers = parts[0];
                String body = parts[1].trim();
                
                if (body.isEmpty()) {
                    // 创建新的JSON对象
                    StringBuilder jsonBuilder = new StringBuilder("{");
                    boolean first = true;
                    for (Map.Entry<String, String> entry : appendParams.entrySet()) {
                        if (!first) jsonBuilder.append(",");
                        jsonBuilder.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
                        first = false;
                    }
                    jsonBuilder.append("}");
                    body = jsonBuilder.toString();
                } else {
                    // 检查是否是JSON数组格式 [{"user":"测试","id":1}]
                    if (body.startsWith("[") && body.endsWith("]")) {
                        // 数组格式：在数组的第一个对象中添加参数
                        body = addParamsToJsonArray(body, appendParams);
                    } else if (body.startsWith("{") && body.endsWith("}")) {
                        // 对象格式：直接在对象中添加参数
                        body = addParamsToJsonObject(body, appendParams);
                    } else {
                        callbacks.printOutput("  -> 不支持的JSON格式，跳过追加参数");
                        return originalRequest;
                    }
                }
                
                // 更新Content-Length头
                String newHeaders = updateContentLength(headers, body.getBytes(StandardCharsets.UTF_8).length);
                
                String newRequestString = newHeaders + "\r\n\r\n" + body;
                
                callbacks.printOutput("JSON追加参数成功");
                return newRequestString.getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            callbacks.printError("添加JSON追加参数失败: " + e.getMessage());
        }
        return originalRequest;
    }
    
    /**
     * 在JSON数组中添加参数
     */
    private String addParamsToJsonArray(String jsonArray, Map<String, String> appendParams) {
        try {
            // 解析数组内容
            String arrayContent = jsonArray.substring(1, jsonArray.length() - 1).trim();
            
            if (arrayContent.isEmpty()) {
                // 空数组，创建一个新对象
                StringBuilder newObject = new StringBuilder("{");
                boolean first = true;
                for (Map.Entry<String, String> entry : appendParams.entrySet()) {
                    if (!first) newObject.append(",");
                    newObject.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
                    first = false;
                }
                newObject.append("}");
                return "[" + newObject.toString() + "]";
            } else {
                // 找到第一个对象并在其中添加参数
                int firstObjectStart = arrayContent.indexOf("{");
                if (firstObjectStart >= 0) {
                    int braceCount = 0;
                    int firstObjectEnd = firstObjectStart;
                    
                    for (int i = firstObjectStart; i < arrayContent.length(); i++) {
                        char c = arrayContent.charAt(i);
                        if (c == '{') braceCount++;
                        else if (c == '}') braceCount--;
                        
                        if (braceCount == 0) {
                            firstObjectEnd = i;
                            break;
                        }
                    }
                    
                    String firstObject = arrayContent.substring(firstObjectStart, firstObjectEnd + 1);
                    String modifiedObject = addParamsToJsonObject(firstObject, appendParams);
                    
                    String newArrayContent = arrayContent.substring(0, firstObjectStart) + 
                                           modifiedObject + 
                                           arrayContent.substring(firstObjectEnd + 1);
                    
                    return "[" + newArrayContent + "]";
                }
            }
        } catch (Exception e) {
            callbacks.printError("处理JSON数组失败: " + e.getMessage());
        }
        return jsonArray;
    }
    
    /**
     * 在JSON对象中添加参数
     */
    private String addParamsToJsonObject(String jsonObject, Map<String, String> appendParams) {
        try {
            // 移除最后的}，准备添加新参数
            String existingJson = jsonObject.substring(0, jsonObject.length() - 1).trim();
            
            StringBuilder appendJson = new StringBuilder();
            boolean first = existingJson.equals("{");
            
            // 添加所有参数
            for (Map.Entry<String, String> entry : appendParams.entrySet()) {
                if (!first) {
                    appendJson.append(",");
                }
                
                // 检查值是否为数字，如果是数字则不加引号
                String value = entry.getValue();
                if (isNumericValue(value)) {
                    appendJson.append("\"").append(entry.getKey()).append("\":").append(value);
                } else {
                    appendJson.append("\"").append(entry.getKey()).append("\":\"").append(value).append("\"");
                }
                first = false;
            }
            
            return existingJson + appendJson.toString() + "}";
        } catch (Exception e) {
            callbacks.printError("处理JSON对象失败: " + e.getMessage());
            return jsonObject;
        }
    }
    
    /**
     * 更新Content-Length头
     */
    private String updateContentLength(String headers, int newLength) {
        try {
            String[] lines = headers.split("\r\n");
            StringBuilder newHeaders = new StringBuilder();
            boolean contentLengthUpdated = false;
            
            for (String line : lines) {
                if (line.toLowerCase().startsWith("content-length:")) {
                    newHeaders.append("Content-Length: ").append(newLength).append("\r\n");
                    contentLengthUpdated = true;
                } else {
                    newHeaders.append(line).append("\r\n");
                }
            }
            
            // 如果没有Content-Length头，添加一个
            if (!contentLengthUpdated) {
                newHeaders.append("Content-Length: ").append(newLength).append("\r\n");
            }
            
            return newHeaders.toString().trim();
        } catch (Exception e) {
            return headers;
        }
    }
    
    /**
     * 创建修改后的请求响应对象
     */
    private IHttpRequestResponse createModifiedRequestResponse(IHttpRequestResponse original, byte[] newRequest) {
        return new IHttpRequestResponse() {
            @Override
            public byte[] getRequest() {
                return newRequest;
            }
            
            @Override
            public void setRequest(byte[] message) {
                // 不实现
            }
            
            @Override
            public byte[] getResponse() {
                return original.getResponse();
            }
            
            @Override
            public void setResponse(byte[] message) {
                original.setResponse(message);
            }
            
            @Override
            public String getComment() {
                return original.getComment();
            }
            
            @Override
            public void setComment(String comment) {
                original.setComment(comment);
            }
            
            @Override
            public String getHighlight() {
                return original.getHighlight();
            }
            
            @Override
            public void setHighlight(String color) {
                original.setHighlight(color);
            }
            
            @Override
            public IHttpService getHttpService() {
                return original.getHttpService();
            }
            
            @Override
            public void setHttpService(IHttpService httpService) {
                original.setHttpService(httpService);
            }
        };
    }
    
    /**
     * 手动构建请求 - 用于处理Burp的updateParameter不支持的参数类型
     * 特别是JSON数组参数的情况
     */
    private byte[] buildRequestManually(byte[] originalRequest, IParameter param, String newValue) {
        try {
            callbacks.printOutput("  -> 开始手动构建请求...");
            
            String requestString = new String(originalRequest, StandardCharsets.UTF_8);
            String[] parts = requestString.split("\r\n\r\n", 2);
            
            if (parts.length < 2) {
                callbacks.printOutput("  -> 无法分离请求头和请求体");
                return originalRequest;
            }
            
            String headers = parts[0];
            String body = parts[1];
            
            // callbacks.printOutput("  -> 原始请求体: " + body);
            // callbacks.printOutput("  -> 参数名: " + param.getName());
            // callbacks.printOutput("  -> 参数原始值: " + param.getValue());
            // callbacks.printOutput("  -> 新值: " + newValue);
            
            // 检查是否是JSON格式
            String contentType = "";
            for (String line : headers.split("\r\n")) {
                if (line.toLowerCase().startsWith("content-type:")) {
                    contentType = line.toLowerCase();
                    break;
                }
            }
            
            if (!contentType.contains("json")) {
                callbacks.printOutput("  -> 不是JSON格式，无法手动构建");
                return originalRequest;
            }
            
            // 获取参数对应的完整JSON值（可能是数组）
            String fullValue = getOriginalJsonValue(body, param.getName());
            callbacks.printOutput("  -> 参数的完整JSON值: " + fullValue);
            
            String newBody = body;
            
            if (fullValue != null && isJsonArray(fullValue)) {
                // 参数值是数组，需要在数组中找到对应元素并替换
                callbacks.printOutput("  -> 参数是数组类型");
                callbacks.printOutput("  -> 需要在数组中查找值为 " + param.getValue() + " 的元素");
                
                // 在数组中查找并替换指定值的元素
                newBody = replaceArrayElementByValue(body, param.getName(), fullValue, param.getValue(), newValue);
                
            } else if (fullValue != null) {
                // 普通参数：直接替换值
                callbacks.printOutput("  -> 参数是普通类型");
                callbacks.printOutput("  -> 原始完整值: " + fullValue);
                callbacks.printOutput("  -> 新测试值: " + newValue);
                callbacks.printOutput("  -> 新测试值是否包含引号: " + newValue.contains("\""));
                
                // 对于 JSON 字符串参数，确保新值被正确转义
                if (fullValue.startsWith("\"") && fullValue.endsWith("\"")) {
                    callbacks.printOutput("  -> 检测到字符串类型参数，确保转义");
                    // 原始值是带引号的字符串，新值也应该是转义后的字符串
                    String escapedNewValue = escapeJsonValue(newValue);
                    callbacks.printOutput("  -> 转义后的新值: " + escapedNewValue);
                    newBody = replaceJsonValue(body, param.getName(), fullValue, "\"" + escapedNewValue + "\"");
                } else {
                    // 其他类型（数字、布尔等）
                    newBody = replaceJsonValue(body, param.getName(), fullValue, newValue);
                }
            } else {
                callbacks.printOutput("  -> 未找到参数的完整值，尝试直接替换");
                // 如果没有找到匹配，尝试使用旧的替换方法
                newBody = replaceJsonParameterInBody(body, param.getName(), param.getValue(), newValue);
            }
            
            if (newBody.equals(body)) {
                callbacks.printOutput("  -> JSON参数替换失败，body未改变");
                return originalRequest;
            }
            
            callbacks.printOutput("  -> 新请求体: " + newBody);
            
            // 更新Content-Length
            String newHeaders = updateContentLength(headers, newBody.getBytes(StandardCharsets.UTF_8).length);
            
            String newRequestString = newHeaders + "\r\n\r\n" + newBody;
            callbacks.printOutput("  -> 手动构建请求成功");
            
            return newRequestString.getBytes(StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            callbacks.printError("手动构建请求失败: " + e.getMessage());
            e.printStackTrace();
            return originalRequest;
        }
    }
    
    /**
     * 在JSON请求体中替换参数值
     */
    private String replaceJsonParameterInBody(String body, String paramName, String oldValue, String newValue) {
        try {
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 开始");
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 参数名: " + paramName);
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 旧值: " + oldValue);
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 新值: " + newValue);
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 新值包含引号: " + newValue.contains("\""));
            
            // 尝试多种替换策略
            
            // 策略1：精确匹配 "paramName":"oldValue"
            String pattern1 = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*\"" + escapeRegex(oldValue) + "\"";
            String replacement1 = "\"" + paramName + "\":\"" + escapeJsonValue(newValue) + "\"";
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 策略1 - 模式: " + pattern1);
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 策略1 - 替换: " + replacement1);
            
            String result = body.replaceAll(pattern1, replacement1);
            if (!result.equals(body)) {
                callbacks.printOutput("  -> 策略1成功：字符串值精确匹配");
                return result;
            }
            
            // 策略2：数字值匹配 "paramName":123
            if (isNumericValue(oldValue)) {
                String pattern2 = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*" + escapeRegex(oldValue);
                String replacement2 = "\"" + paramName + "\":" + (isNumericValue(newValue) ? newValue : "\"" + escapeJsonValue(newValue) + "\"");
                callbacks.printOutput("  -> [replaceJsonParameterInBody] 策略2 - 模式: " + pattern2);
                callbacks.printOutput("  -> [replaceJsonParameterInBody] 策略2 - 替换: " + replacement2);
                
                result = body.replaceAll(pattern2, replacement2);
                if (!result.equals(body)) {
                    callbacks.printOutput("  -> 策略2成功：数字值匹配");
                    return result;
                }
            }
            
            // 策略3：参数级字符串兜底替换（仅替换目标参数）
            String pattern3 = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*\"[^\"]*\"";
            String replacement3 = "\"" + paramName + "\":\"" + escapeJsonValue(newValue) + "\"";
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 策略3 - 模式: " + pattern3);
            callbacks.printOutput("  -> [replaceJsonParameterInBody] 策略3 - 替换: " + replacement3);

            result = body.replaceAll(pattern3, java.util.regex.Matcher.quoteReplacement(replacement3));
            if (!result.equals(body)) {
                callbacks.printOutput("  -> 策略3成功：参数级字符串兜底替换");
                return result;
            }

            // 策略4：参数级数字兜底替换（仅替换目标参数）
            if (isNumericValue(oldValue)) {
                String pattern4 = "\"" + escapeRegex(paramName) + "\"\\s*:\\s*" + escapeRegex(oldValue) + "(?=\\s*[,}\\]])";
                String replacement4 = "\"" + paramName + "\":" + (isNumericValue(newValue) ? newValue : "\"" + escapeJsonValue(newValue) + "\"");
                result = body.replaceAll(pattern4, java.util.regex.Matcher.quoteReplacement(replacement4));
                if (!result.equals(body)) {
                    callbacks.printOutput("  -> 策略4成功：参数级数字兜底替换");
                    return result;
                }
            }
            
            callbacks.printOutput("  -> 所有替换策略都失败");
            return body;
            
        } catch (Exception e) {
            callbacks.printError("替换JSON参数失败: " + e.getMessage());
            return body;
        }
    }
    
    /**
     * 在JSON数组中查找并替换指定值的元素
     * 
     * @param jsonBody JSON请求体
     * @param paramName 参数名
     * @param arrayValue 完整的数组值（如 [1,2,3,4,5]）
     * @param oldElementValue 要查找的元素值（如 "3"）
     * @param newElementValue 新的元素值（如 "3'"）
     * @return 修改后的JSON请求体
     */
    private String replaceArrayElementByValue(String jsonBody, String paramName, String arrayValue, 
                                               String oldElementValue, String newElementValue) {
        try {
            callbacks.printOutput("  -> 在数组中查找并替换元素");
            callbacks.printOutput("  -> 数组值: " + arrayValue);
            callbacks.printOutput("  -> 查找元素: " + oldElementValue);
            callbacks.printOutput("  -> 新元素值: " + newElementValue);
            
            // 解析数组内容
            String arrayContent = arrayValue.substring(1, arrayValue.length() - 1).trim();
            
            if (arrayContent.isEmpty()) {
                callbacks.printOutput("  -> 数组为空，无法替换");
                return jsonBody;
            }
            
            // 分割数组元素
            String[] elements = splitJsonArrayElements(arrayContent);
            callbacks.printOutput("  -> 数组元素数量: " + elements.length);
            
            boolean found = false;
            StringBuilder newArrayBuilder = new StringBuilder("[");
            
            for (int i = 0; i < elements.length; i++) {
                if (i > 0) {
                    newArrayBuilder.append(",");
                }
                
                String element = elements[i].trim();
                String elementValue = element;
                
                // 去掉引号（如果有）
                if (element.startsWith("\"") && element.endsWith("\"")) {
                    elementValue = element.substring(1, element.length() - 1);
                }
                
                callbacks.printOutput("  -> 检查元素[" + i + "]: " + element + " (值: " + elementValue + ")");
                
                // 检查是否匹配要查找的值
                if (elementValue.equals(oldElementValue)) {
                    // 找到匹配的元素，替换为新值
                    callbacks.printOutput("  -> 找到匹配元素，索引: " + i);
                    
                    // 将新值转为字符串格式（添加引号）
                    String newElement = "\"" + escapeJsonValue(newElementValue) + "\"";
                    newArrayBuilder.append(newElement);
                    found = true;
                } else {
                    // 保持原有元素
                    newArrayBuilder.append(element);
                }
            }
            
            newArrayBuilder.append("]");
            
            if (!found) {
                callbacks.printOutput("  -> 警告：未找到匹配的元素值: " + oldElementValue);
                return jsonBody;
            }
            
            String newArrayValue = newArrayBuilder.toString();
            callbacks.printOutput("  -> 新数组值: " + newArrayValue);
            
            // 直接进行字符串替换，避免 replaceJsonValue 添加引号
            // 查找 "paramName":[原数组] 并替换为 "paramName":[新数组]
            String searchStr = "\"" + paramName + "\":" + arrayValue;
            String replaceStr = "\"" + paramName + "\":" + newArrayValue;
            
            callbacks.printOutput("  -> 搜索字符串: " + searchStr);
            callbacks.printOutput("  -> 替换字符串: " + replaceStr);
            
            String result = jsonBody.replace(searchStr, replaceStr);
            
            if (result.equals(jsonBody)) {
                callbacks.printOutput("  -> 直接替换失败，尝试带空格的版本");
                // 尝试带空格的版本
                searchStr = "\"" + paramName + "\" : " + arrayValue;
                replaceStr = "\"" + paramName + "\":" + newArrayValue;
                result = jsonBody.replace(searchStr, replaceStr);
                
                if (result.equals(jsonBody)) {
                    callbacks.printOutput("  -> 所有替换尝试都失败");
                    return jsonBody;
                }
            }
            
            callbacks.printOutput("  -> 数组替换成功");
            return result;
            
        } catch (Exception e) {
            callbacks.printError("替换数组元素失败: " + e.getMessage());
            e.printStackTrace();
            return jsonBody;
        }
    }
    
    /**
     * 创建包含指定请求和响应的 IHttpRequestResponse 对象
     */
    private IHttpRequestResponse createRequestResponse(IHttpService httpService, byte[] request, byte[] response) {
        return new IHttpRequestResponse() {
            private byte[] req = request;
            private byte[] resp = response;
            private IHttpService service = httpService;
            private String comment;
            private String highlight;
            
            @Override
            public byte[] getRequest() {
                return req;
            }
            
            @Override
            public void setRequest(byte[] message) {
                req = message;
            }
            
            @Override
            public byte[] getResponse() {
                return resp;
            }
            
            @Override
            public void setResponse(byte[] message) {
                resp = message;
            }
            
            @Override
            public String getComment() {
                return comment;
            }
            
            @Override
            public void setComment(String comment) {
                this.comment = comment;
            }
            
            @Override
            public String getHighlight() {
                return highlight;
            }
            
            @Override
            public void setHighlight(String color) {
                this.highlight = color;
            }
            
            @Override
            public IHttpService getHttpService() {
                return service;
            }
            
            @Override
            public void setHttpService(IHttpService httpService) {
                this.service = httpService;
            }
        };
    }
}
