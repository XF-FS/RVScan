/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.swagger;

import APIKit.utils.CommonUtils;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.UUID;
import java.util.HashSet;

public class SwaggerObject {
    public final String boundary = "----" + UUID.randomUUID();
    public final String newLine = "\r\n";
    public String basePath;
    public JsonObject definitions;
    public JsonObject link;
    public HashMap<String, String> params;
    public HashMap<List<String>, byte[]> apiRequestResponse;
    public String content_type;
    public String para_bodystr;
    public String para_querystr;
    public String in;
    public String method;
    public List<String> headers;
    public ArrayList<String> newheaders;
    public Stack<String> itemsStack = new Stack();
    public String uri;
    public String path;
    public boolean isctset;
    
    // 添加一个Set来跟踪已处理的路径，避免重复
    private Set<String> processedPaths = new HashSet<>();

    public SwaggerObject(List<String> headers) {
        this.headers = headers;
        this.basePath = "";
        this.params = new HashMap();
        this.newheaders = new ArrayList<String>(headers);
        this.apiRequestResponse = new HashMap();
        this.method = "GET";
        this.para_querystr = "";
        this.para_bodystr = "";
        this.path = "";
        this.isctset = false;
    }

    public static String replaceStr(String testStr) {
        testStr = testStr.replace("\"*int64*\"", "1");
        testStr = testStr.replace("\"*int32*\"", "1");
        testStr = testStr.replace("\"*float*\"", "1");
        testStr = testStr.replace("\"*double*\"", "1");
        testStr = testStr.replace("\"int64\"", "2");
        testStr = testStr.replace("\"int32\"", "2");
        testStr = testStr.replace("\"float\"", "2.0");
        testStr = testStr.replace("\"double\"", "2.0");
        testStr = testStr.replace("*string*", "aaaa");
        testStr = testStr.replace("*int64*", "1");
        testStr = testStr.replace("*int32*", "1");
        testStr = testStr.replace("*float*", "1");
        testStr = testStr.replace("*double*", "1");
        testStr = testStr.replace("*byte*", "MTIzNDU2");
        testStr = testStr.replace("*binary*", "binary");
        testStr = testStr.replace("*date-time*", "2023-10-10T23:59:59");
        testStr = testStr.replace("*datetime*", "2023-10-10T23:59:59");
        testStr = testStr.replace("*date*", "23:59:60");
        testStr = testStr.replace("*password*", "password");
        testStr = testStr.replace("string", "test");
        testStr = testStr.replace("int64", "2");
        testStr = testStr.replace("int32", "2");
        testStr = testStr.replace("float", "2.0");
        testStr = testStr.replace("double", "2.0");
        testStr = testStr.replace("byte", "MTIz");
        testStr = testStr.replace("binary", "binary");
        testStr = testStr.replace("date-time", "2023-10-10T23:59:59");
        testStr = testStr.replace("datetime", "2023-10-10T23:59:59");
        testStr = testStr.replace("date", "23:59:60");
        testStr = testStr.replace("password", "password");
        testStr = testStr.replace("\"*integer*\"", "4");
        testStr = testStr.replace("\"*number*\"", "4.0");
        testStr = testStr.replace("*integer*", "4");
        testStr = testStr.replace("*number*", "4.0");
        testStr = testStr.replace("\"*boolean*\"", "false");
        testStr = testStr.replace("*boolean*", "false");
        testStr = testStr.replace("\"integer\"", "3");
        testStr = testStr.replace("\"number\"", "3.0");
        testStr = testStr.replace("integer", "3");
        testStr = testStr.replace("number", "3.0");
        testStr = testStr.replace("\"boolean\"", "true");
        testStr = testStr.replace("boolean", "true");
        testStr = testStr.replace("uuid", "11111111-0000-2222-3333-444444444444");
        return testStr;
    }

    public HashMap<String, String> SwaggerParseObject(JsonObject inputJsonobj, String _basePath) throws MalformedURLException {
        JsonArray apisarray;
        this.link = inputJsonobj.getAsJsonObject();
        if (this.link.get("basePath") != null) {
            this.basePath = this.link.get("basePath").getAsString();
            if (this.basePath.equals("/")) {
                this.basePath = this.basePath.substring(1);
            }
        }
        if (this.link.get("servers") != null) {
            String url = this.link.get("servers").getAsJsonArray().get(0).getAsJsonObject().get("url").getAsString();
            if (url.length() == 0) {
                this.basePath = "/";
            } else {
                String string = this.basePath = url.startsWith("/") ? url : new URL(url).getPath();
                if (url.contains("{")) {
                    JsonObject servervariables = this.link.get("servers").getAsJsonObject().get("variables").getAsJsonObject();
                    Set<Map.Entry<String, JsonElement>> servervariabless = servervariables.entrySet();
                    for (Map.Entry<String, JsonElement> servervariable : servervariabless) {
                        this.basePath = this.basePath.replace("{" + servervariable.getKey() + "}", servervariable.getValue().getAsJsonObject().get("default").getAsString());
                    }
                }
            }
            if (this.basePath.equals("/")) {
                this.basePath = this.basePath.substring(1);
            }
        }
        if (_basePath.endsWith("/")) {
            _basePath = _basePath.substring(0, _basePath.length() - 1);
        }
        this.basePath = CommonUtils.combineURLs(_basePath, this.basePath);
        if (this.link.get("components") != null) {
            this.definitions = this.link.get("components").getAsJsonObject();
            if (this.definitions.get("schemas") != null) {
                this.definitions = this.definitions.get("schemas").getAsJsonObject();
            }
        }
        if (this.link.get("models") != null) {
            this.definitions = this.link.get("models").getAsJsonObject();
        }
        if (this.link.get("apis") != null && this.link.get("apis").isJsonArray() && null != (apisarray = this.link.get("apis").getAsJsonArray())) {
            for (JsonElement ae : apisarray) {
                JsonArray operations;
                if (!ae.isJsonObject()) continue;
                this.uri = CommonUtils.combineURLs(this.basePath, ae.getAsJsonObject().get("path").getAsString());
                boolean globals_content_type = false;
                if (ae.getAsJsonObject().get("consumes") != null) {
                    JsonArray content_types = ae.getAsJsonObject().get("consumes").getAsJsonArray();
                    this.content_type = content_types.get(0).getAsString();
                    globals_content_type = true;
                }
                if (ae.getAsJsonObject().get("operations") == null || (operations = ae.getAsJsonObject().get("operations").getAsJsonArray()).isJsonNull())
                    continue;
                for (JsonElement operation : operations) {
                    JsonArray parameters;
                    if (!operation.isJsonObject()) continue;
                    JsonObject op = operation.getAsJsonObject();
                    this.method = op.get("method").getAsString();
                    if (!globals_content_type) {
                        this.content_type = "";
                    }
                    if (op.get("consumes") != null) {
                        JsonArray content_types = op.get("consumes").getAsJsonArray();
                        this.content_type = content_types.get(0).getAsString();
                    }
                    if (!((JsonElement) (parameters = op.get("parameters").getAsJsonArray())).isJsonArray()) continue;
                    this.isctset = false;
                    for (Object parameter : parameters) {
                        if (!((JsonElement) parameter).isJsonObject()) continue;
                        this.params.clear();
                        this.in = "";
                        this.Openapi1ParserObject("", ((JsonElement) parameter).getAsJsonObject());
                        this.makeHttpRequest();
                    }
                    if (parameters.size() == 0) {
                        this.cleanparam();
                        this.makeHttpRequest();
                    }
                    this.saveHttpRequest();
                    this.para_querystr = "";
                    this.para_bodystr = "";
                    this.path = "";
                }
            }
        }
        if (this.link.get("definitions") != null) {
            this.definitions = this.link.get("definitions").getAsJsonObject();
        }
        if (this.link.get("paths") != null && this.link.get("paths").isJsonObject()) {
            JsonObject paths = this.link.get("paths").getAsJsonObject();
            Set<Map.Entry<String, JsonElement>> apiPaths = paths.getAsJsonObject().entrySet();
            for (Map.Entry<String, JsonElement> apiPath : apiPaths) {
                this.uri = CommonUtils.combineURLs(this.basePath, apiPath.getKey());
                if (!apiPath.getValue().isJsonObject()) continue;
                for (Map.Entry<String, JsonElement> apiMethod : apiPath.getValue().getAsJsonObject().entrySet()) {
                    JsonArray content_types;
                    this.method = apiMethod.getKey().toUpperCase();
                    this.content_type = "";
                    if (!apiMethod.getValue().isJsonObject()) continue;
                    if (apiMethod.getValue().getAsJsonObject().get("consumes") != null && (content_types = apiMethod.getValue().getAsJsonObject().get("consumes").getAsJsonArray()).size() != 0) {
                        this.content_type = content_types.get(0).getAsString();
                    }
                    boolean reqparamnull = true;
                    this.isctset = false;
                    if (apiMethod.getValue().getAsJsonObject().get("parameters") != null) {
                        reqparamnull = false;
                        JsonArray apiParameters = apiMethod.getValue().getAsJsonObject().get("parameters").getAsJsonArray();
                        if (apiParameters.size() == 0) {
                            reqparamnull = true;
                        }
                        if (null != apiParameters) {
                            for (JsonElement apiParameter : apiParameters) {
                                if (apiParameter.isJsonNull()) continue;
                                this.params.clear();
                                this.in = "";
                                this.Openapi23ParserObject("", apiParameter.getAsJsonObject());
                                this.makeHttpRequest();
                            }
                        }
                    }
                    if (apiMethod.getValue().getAsJsonObject().get("requestBody") != null) {
                        reqparamnull = false;
                        JsonObject reqest = apiMethod.getValue().getAsJsonObject().get("requestBody").getAsJsonObject().get("content").getAsJsonObject();
                        this.isctset = false;
                        Set<Map.Entry<String, JsonElement>> reqs = reqest.entrySet();
                        Iterator<Map.Entry<String, JsonElement>> entryIterator = reqs.iterator();
                        if (entryIterator.hasNext()) {
                            Map.Entry<String, JsonElement> req = entryIterator.next();
                            this.content_type = req.getKey();
                            this.params.clear();
                            this.in = "body";
                            this.Openapi23ParserObject("", req.getValue().getAsJsonObject());
                            this.makeHttpRequest();
                            this.in = "";
                        }
                    }
                    if (reqparamnull) {
                        this.cleanparam();
                        this.makeHttpRequest();
                    }
                    this.saveHttpRequest();
                    this.para_querystr = "";
                    this.para_bodystr = "";
                    this.path = "";
                }
            }
        }
        return null;
    }

    private void cleanparam() {
        this.para_querystr = "";
        this.para_bodystr = "";
        this.content_type = "";
        this.path = "";
        this.params.clear();
        this.in = "";
    }

    private void Openapi23ParserObject(String para_name, JsonObject apiParam) {
        String para_format = "";
        String is_required = "";
        if (apiParam.get("name") != null) {
            para_name = apiParam.get("name").getAsString();
        }
        if (apiParam.get("in") != null) {
            this.in = apiParam.get("in").getAsString().toLowerCase();
        }
        if (apiParam.get("required") != null) {
            if (apiParam.get("required").isJsonPrimitive() && apiParam.get("required").getAsBoolean()) {
                is_required = "*";
            }
        } else {
            is_required = "";
        }
        if (apiParam.get("format") != null) {
            para_format = apiParam.get("format").getAsString();
        } else if (apiParam.get("schema") != null) {
            if (apiParam.get("schema").getAsJsonObject().get("$ref") == null) {
                this.Openapi23ParserObject(para_name, apiParam.get("schema").getAsJsonObject());
            } else {
                this.Openapi23ParserObject("", apiParam.get("schema").getAsJsonObject());
            }
        } else if (apiParam.get("$ref") != null) {
            String para_ref = apiParam.get("$ref").getAsString().replace("#/definitions/", "").replace("#/components/schemas/", "");
            if (this.definitions.isJsonObject() && this.definitions.get(para_ref) != null && this.definitions.get(para_ref).getAsJsonObject().get("properties") != null && Collections.frequency(this.itemsStack, para_ref) <= 0) {
                this.itemsStack.push(para_ref);
                JsonObject properties = this.definitions.get(para_ref).getAsJsonObject().get("properties").getAsJsonObject();
                Set<Map.Entry<String, JsonElement>> propertie = properties.entrySet();
                for (Map.Entry<String, JsonElement> en : propertie) {
                    this.Openapi23ParserObject(en.getKey(), en.getValue().getAsJsonObject());
                }
                this.itemsStack.pop();
            }
        } else if (apiParam.get("items") != null) {
            if (apiParam.get("items").getAsJsonObject().get("$ref") != null) {
                this.Openapi23ParserObject("", apiParam.get("items").getAsJsonObject());
            } else {
                this.Openapi23ParserObject(para_name, apiParam.get("items").getAsJsonObject());
            }
        } else if (apiParam.get("properties") != null) {
            JsonObject properties = apiParam.get("properties").getAsJsonObject();
            for (Map.Entry<String, JsonElement> propert : properties.entrySet()) {
                this.Openapi23ParserObject(propert.getKey(), propert.getValue().getAsJsonObject());
            }
        } else if (apiParam.get("additionalProperties") != null) {
            if (apiParam.get("additionalProperties").isJsonObject()) {
                this.Openapi23ParserObject(para_name, apiParam.get("additionalProperties").getAsJsonObject());
            }
        } else {
            String string = para_format = apiParam.get("type") != null ? apiParam.get("type").getAsString() : "null";
        }
        if (!(para_name.isEmpty() || para_format.isEmpty() || this.params.containsKey(para_name))) {
            this.params.put(para_name, is_required + para_format + is_required);
        }
    }

    private void Openapi1ParserObject(String para_name, JsonObject apiParam) {
        String para_format = "";
        String is_required = "";
        String para_ref = "";
        if (apiParam.get("name") != null) {
            para_name = apiParam.get("name").getAsString();
        }
        if (apiParam.get("paramType") != null) {
            this.in = apiParam.get("paramType").getAsString().toLowerCase();
        }
        if (apiParam.get("required") != null) {
            if (apiParam.get("required").getAsBoolean()) {
                is_required = "*";
            }
        } else {
            is_required = "";
        }
        if (apiParam.get("format") != null) {
            para_format = apiParam.get("format").getAsString();
        } else if (apiParam.get("$ref") != null) {
            para_ref = apiParam.get("$ref").getAsString();
            if (this.definitions.isJsonObject() && this.definitions.get(para_ref) != null && this.definitions.get(para_ref).getAsJsonObject().get("properties") != null && Collections.frequency(this.itemsStack, para_ref) <= 0) {
                this.itemsStack.push(para_ref);
                JsonObject properties = this.definitions.get(para_ref).getAsJsonObject().get("properties").getAsJsonObject();
                Set<Map.Entry<String, JsonElement>> propertie = properties.entrySet();
                for (Map.Entry<String, JsonElement> en : propertie) {
                    this.Openapi1ParserObject(en.getKey(), en.getValue().getAsJsonObject());
                }
                this.itemsStack.pop();
            }
        } else if (apiParam.get("items") != null) {
            if (apiParam.get("items").getAsJsonObject().get("$ref") != null) {
                this.Openapi1ParserObject("", apiParam.get("items").getAsJsonObject());
            } else {
                this.Openapi1ParserObject(para_name, apiParam.get("items").getAsJsonObject());
            }
        } else if (apiParam.get("type") != null) {
            para_format = apiParam.get("type").getAsString();
            if (this.definitions.isJsonObject() && this.definitions.get(para_format) != null) {
                if (this.definitions.get(para_format).getAsJsonObject().get("properties") != null && Collections.frequency(this.itemsStack, para_format) <= 0) {
                    this.itemsStack.push(para_format);
                    JsonObject properties = this.definitions.get(para_format).getAsJsonObject().get("properties").getAsJsonObject();
                    Set<Map.Entry<String, JsonElement>> propertie = properties.entrySet();
                    for (Map.Entry<String, JsonElement> en : propertie) {
                        this.Openapi1ParserObject(en.getKey(), en.getValue().getAsJsonObject());
                    }
                    this.itemsStack.pop();
                }
                para_format = "";
            }
        } else {
            para_format = "null";
        }
        if (!(para_name.isEmpty() || para_format.isEmpty() || this.params.containsKey(para_name))) {
            this.params.put(para_name, is_required + para_format + is_required);
        }
    }

    public void makeHttpRequest() {
        if (this.path.isEmpty()) {
            this.path = this.uri.replaceAll("/{2,}", "/");
        }
        for (Map.Entry<String, String> entry : this.params.entrySet()) {
            String _para_name = entry.getKey();
            String _para_format = entry.getValue();
            boolean isupload = false;
            switch (this.in) {
                case "body": {
                    if (this.content_type.isEmpty()) {
                        if (!this.isctset) {
                            this.isctset = true;
                            this.newheaders.add("Content-Type: application/json");
                        }
                        this.para_bodystr = this.para_bodystr + "\"" + _para_name + SwaggerObject.replaceStr("\": \"" + _para_format + "\",");
                        break;
                    }
                    if (!this.isctset) {
                        this.isctset = true;
                        if (_para_format.contains("binary") || _para_format.contains("base64") || this.content_type.contains("form-data")) {
                            this.newheaders.add("Content-Type: multipart/form-data; boundary=" + this.boundary);
                            isupload = true;
                        } else {
                            this.newheaders.add("Content-Type: " + this.content_type);
                        }
                    }
                    if (isupload) {
                        this.para_bodystr = this.para_bodystr + "--" + this.boundary + "\r\n" + String.format("Content-Disposition: form-data; name=\"%s\"; filename=\"tmp.jpg\"", _para_name) + "\r\nContent-Type: " + this.content_type + "\r\n\r\nGIF89aaaaaaaaaaaaaaaaaaaa\r\n";
                        break;
                    }
                    if (this.content_type.contains("x-www-form-urlencoded")) {
                        this.para_bodystr = this.para_bodystr + String.format("&%s=%s", _para_name, SwaggerObject.replaceStr(_para_format));
                        break;
                    }
                    if (this.content_type.contains("json")) {
                        this.para_bodystr = this.para_bodystr + "\"" + _para_name + SwaggerObject.replaceStr("\": \"" + _para_format + "\",");
                        break;
                    }
                    if (this.content_type.contains("form-data")) {
                        this.para_bodystr = this.para_bodystr + "--" + this.boundary + "\r\n" + String.format("Content-Disposition: form-data; name=\"%s\";", _para_name) + "\r\n\r\n" + SwaggerObject.replaceStr(_para_format) + "\r\n";
                        break;
                    }
                    if (this.content_type.contains("xml")) break;
                    break;
                }
                case "query": {
                    this.para_querystr = this.para_querystr + String.format("&%s=%s", _para_name, SwaggerObject.replaceStr(_para_format));
                    break;
                }
                case "formdata":
                case "form": {
                    if (!this.isctset) {
                        this.isctset = true;
                        this.newheaders.add("Content-Type: multipart/form-data; boundary=" + this.boundary);
                    }
                    if (_para_format.toLowerCase().contains("file")) {
                        this.para_bodystr = this.para_bodystr + "--" + this.boundary + "\r\n" + String.format("Content-Disposition: form-data; name=\"%s\"; filename=\"tmp.jpg\"", _para_name) + "\r\nContent-Type: application/octet-stream\r\n\r\nGIF89aaaaaaaaaaaaaaaaaaaa\r\n";
                        break;
                    }
                    this.para_bodystr = this.para_bodystr + "--" + this.boundary + "\r\n" + String.format("Content-Disposition: form-data; name=\"%s\";", _para_name) + "\r\n\r\n" + SwaggerObject.replaceStr(_para_format) + "\r\n";
                    break;
                }
                case "header": {
                    this.newheaders.add(_para_name + ": " + SwaggerObject.replaceStr(_para_format));
                    break;
                }
                case "path": {
                    this.path = this.path.replace("{" + _para_name + "}", SwaggerObject.replaceStr(_para_format));
                }
            }
        }
    }

    public void saveHttpRequest() {
        if (this.para_querystr.startsWith("&")) {
            this.para_querystr = this.para_querystr.substring(1);
            this.para_querystr = "?" + this.para_querystr;
        }
        if (this.para_bodystr.startsWith("&")) {
            this.para_bodystr = this.para_bodystr.substring(1);
        }
        if (this.para_bodystr.startsWith("\"")) {
            this.para_bodystr = "{" + this.para_bodystr.substring(0, this.para_bodystr.length() - 1) + "}";
        }
        if (this.para_bodystr.startsWith("-")) {
            this.para_bodystr = this.para_bodystr + "--" + this.boundary + "--\r\n";
        }
        this.path = this.path + this.para_querystr;
        
        // 创建唯一的路径标识符，包含方法和路径
        String uniquePathKey = this.method + " " + this.path;
        
        // 检查是否已经处理过这个路径
        if (processedPaths.contains(uniquePathKey)) {
            System.out.println("[SwaggerObject] Duplicate path detected, skipping: " + uniquePathKey);
            return; // 已经处理过，跳过
        }
        processedPaths.add(uniquePathKey);
        System.out.println("[SwaggerObject] Processing new path: " + uniquePathKey);
        
        // 应用路径过滤逻辑
        try {
            burp.ui.ConfigPanel configPanel = null.getConfigPanel();
            if (configPanel.shouldFilterPath(this.path)) {
                System.out.println("[Swagger Filter] Blocked path: " + this.path + " (contains filtered keywords: " + configPanel.getFilterPath() + ")");
                
                // 为过滤的请求创建独立的请求头副本
                ArrayList<String> filteredHeaders = new ArrayList<String>(this.newheaders);
                filteredHeaders.set(0, this.method + " " + this.path + " HTTP/1.1");
                
                // 使用特殊标记来标识被过滤的请求
                String filteredMarker = "FILTERED_PATH_MARKER";
                
                // 将过滤的请求标记添加到 apiRequestResponse 集合中
                this.apiRequestResponse.put(filteredHeaders, filteredMarker.getBytes(StandardCharsets.UTF_8));
                
                return;
            }
        } catch (Exception e) {
            // 如果获取ConfigPanel失败，继续正常处理
            System.out.println("[Swagger Filter] Warning: Could not apply path filter - " + e.getMessage());
        }
        
        switch (this.method) {
            case "GET":
            case "PATCH":
            case "DELETE": {
                break;
            }
            default: {
                this.newheaders.add("Content-Length: " + this.para_bodystr.length());
            }
        }
        this.newheaders.set(0, this.method + " " + this.path + " HTTP/1.1");
        this.apiRequestResponse.put(this.newheaders, this.para_bodystr.getBytes(StandardCharsets.UTF_8));
        this.newheaders = new ArrayList<String>(this.headers);
    }
}

