/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.rest;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import com.predic8.wadl.Application;
import com.predic8.wadl.Method;
import com.predic8.wadl.Option;
import com.predic8.wadl.Param;
import com.predic8.wadl.Representation;
import com.predic8.wadl.Resource;
import com.predic8.wadl.Resources;
import com.predic8.wadl.WADLParser;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import APIKit.BurpExtenderAdapter;

public class WadlParser {
    public final String boundary = "----" + UUID.randomUUID();
    public final String newLine = "\r\n";
    public String basePath;
    public HashMap<String, HashMap<String, String>> params;
    public HashMap<List<String>, byte[]> apiRequestResponse;
    public String content_type;
    public String para_bodystr;
    public String para_querystr;
    public String method;
    public List<String> headers;
    public ArrayList<String> newheaders;
    public String grammarsLink;
    public String path;

    public WadlParser(List<String> headers) {
        this.headers = headers;
        for (String header : this.headers) {
            if (!header.contains("Content-Type") && !header.contains("Content-Length")) continue;
            this.headers.remove(header);
        }
        this.params = new HashMap();
        this.params.put("query", new HashMap());
        this.params.put("template", new HashMap());
        this.params.put("header", new HashMap());
        this.params.put("matrix", new HashMap());
        this.apiRequestResponse = new HashMap();
        this.para_querystr = "";
        this.para_bodystr = "";
        this.content_type = "";
        this.path = "";
        this.basePath = "";
        this.grammarsLink = "";
        this.newheaders = new ArrayList<String>(this.headers);
    }

    public static String mockData(String value) {
        if (value.startsWith("*")) {
            return value.substring(1);
        }
        Boolean isRequired = false;
        if (value.startsWith("+")) {
            isRequired = true;
            value = value.substring(1).toLowerCase(Locale.ROOT);
        }
        switch (value) {
            case "string": {
                value = value.replace(value, "testString");
                break;
            }
            case "int": {
                value = value.replace(value, "123456");
                break;
            }
            default: {
                value = isRequired != false ? "{RequiredValue:\t" + value + "}" : "[OptionalValue\t" + value + "]";
            }
        }
        return value;
    }

    public HashMap<List<String>, byte[]> parseWadl(IHttpRequestResponse apiDocument, IHttpRequestResponse basePath) {
        IExtensionHelpers helpers = BurpExtenderAdapter.getHelpers();
        String APIDocumentURL = helpers.analyzeRequest(apiDocument).getUrl().toString();
        WADLParser parser = new WADLParser();
        Application application = parser.parse(APIDocumentURL);
        ArrayList<Resource> queue = new ArrayList<Resource>();
        Resources resources = application.getRscss().get(0);
        try {
            URL url = new URL(resources.getBase());
            String rawPath = url.getPath();
            if (!rawPath.endsWith("/")) {
                rawPath = rawPath + "/";
            }
            this.basePath = rawPath;
        } catch (Exception url) {
            // empty catch block
        }
        for (Resource resource : resources.getResources()) {
            queue.add(resource);
        }
        while (queue.size() != 0) {
            Resource resource = (Resource) queue.get(0);
            List<Resource> tmpResources = resource.getResources();
            if (tmpResources.size() != 0) {
                queue.addAll(tmpResources);
            }
            queue.remove(0);
            Object apiRequest = null;
            List<Method> methods = resource.getMethods();
            if (methods.size() == 0) continue;
            for (Method method : methods) {
                List<Representation> representations;
                this.method = method.getName();
                if (method.getRequest() != null && (representations = method.getRequest().getRepresentations()).size() != 0 && representations.get(0).getMediaType() != null) {
                    this.content_type = representations.get(0).getMediaType();
                }
                this.getParentParametersandPath(resource);
                this.path = this.path.replaceAll("//", "/");
                if (this.path.startsWith("/")) {
                    this.path = this.path.replaceFirst("/", "");
                }
                if (this.path.endsWith("/")) {
                    this.path = this.path.substring(0, this.path.length() - 1);
                }
                if (method.getRequest() != null) {
                    for (Param param : method.getRequest().getParams()) {
                        this.addParameter(param);
                    }
                }
                this.buildHttpRequestParams();
                this.saveHttpRequest();
                this.clearCache();
            }
        }
        return this.apiRequestResponse;
    }

    private void getParentParametersandPath(Resource parentResource) {
        this.path = parentResource.getPath() + "/" + this.path;
        List<Param> params = parentResource.getParams();
        if (params.size() != 0) {
            for (Param param : params) {
                this.addParameter(param);
            }
        }
        try {
            Resource parent = (Resource) parentResource.getParent();
            this.getParentParametersandPath(parent);
        } catch (Exception exception) {
            // empty catch block
        }
    }

    private void addParameter(Param param) {
        String paramName = param.getName();
        String paramValue = "";
        try {
            Object type = param.getType();
            paramValue = (String) type;
        } catch (Exception e) {
            System.err.println(e);
        }
        if (paramValue == "") {
            paramValue = "string";
        }
        boolean isRequired = param.getRequired();
        String paramDfault = param.getDfault();
        String fixed = param.getFixed();
        if (isRequired) {
            paramValue = "+" + paramValue;
        }
        if (paramDfault != null || fixed != null) {
            paramValue = "*" + (paramDfault == null ? fixed : paramDfault);
        }
        String paramMediaType = "";
        List<Option> options = param.getOptions();
        if (options.size() != 0) {
            paramMediaType = options.get(0).getMediaType();
        }
        String representation = "";
        try {
            Object representationObj = param.getProperty("representation");
            representation = (String) representationObj;
        } catch (Exception exception) {
            // empty catch block
        }
        if (representation != "") {
            paramMediaType = representation;
        }
        if (paramMediaType != "") {
            switch (paramMediaType) {
                case "application/json": {
                    paramValue = "*{json}";
                    break;
                }
                case "application/xml": {
                    paramValue = "*<?xml>";
                }
            }
        }
        this.params.get(param.getStyle()).put(paramName, paramValue);
    }

    private void clearCache() {
        this.para_querystr = "";
        this.para_bodystr = "";
        this.content_type = "";
        this.path = "";
        this.grammarsLink = "";
        this.newheaders = new ArrayList<String>(this.headers);
        this.params.get("header").clear();
        this.params.get("query").clear();
        this.params.get("matrix").clear();
        this.params.get("template").clear();
    }

    public void buildHttpRequestParams() {
        String paramValue;
        String paramName;
        if (this.params.get("template").size() != 0) {
            Set<Map.Entry<String, String>> template = this.params.get("template").entrySet();
            for (Map.Entry<String, String> entry : template) {
                paramName = entry.getKey();
                paramValue = WadlParser.mockData("+" + entry.getValue());
                this.path = this.path.replace("{" + paramName + "}", paramValue);
            }
        }
        if (this.params.get("query").size() != 0) {
            Set<Map.Entry<String, String>> query = this.params.get("query").entrySet();
            block13:
            for (Map.Entry<String, String> entry : query) {
                paramName = entry.getKey();
                paramValue = WadlParser.mockData(entry.getValue());
                switch (this.content_type) {
                    case "": {
                        this.para_querystr = this.para_querystr + String.format("&%s=%s", paramName, paramValue);
                        continue block13;
                    }
                    case "application/json": {
                        this.para_bodystr = this.para_bodystr + "\"" + paramName + "\": \"" + paramValue + "\",";
                        continue block13;
                    }
                    case "application/xml": {
                        this.para_bodystr = "<?xml>";
                        continue block13;
                    }
                    case "application/x-www-form-urlencoded": {
                        this.para_bodystr = this.para_bodystr + String.format("&%s=%s", paramName, paramValue);
                        continue block13;
                    }
                }
                this.para_bodystr = "Not Support Media Format";
            }
        }
        if (this.params.get("matrix").size() != 0) {
            Set<Map.Entry<String, String>> matrix = this.params.get("matrix").entrySet();
            for (Map.Entry<String, String> entry : matrix) {
                paramName = entry.getKey();
                paramValue = WadlParser.mockData(entry.getValue());
                this.para_querystr = this.para_querystr + ";" + paramName + "=" + paramValue;
            }
        }
        Set<Map.Entry<String, String>> header = this.params.get("header").entrySet();
        for (Map.Entry<String, String> entry : header) {
            paramName = entry.getKey();
            paramValue = WadlParser.mockData(entry.getValue());
            this.newheaders.add(paramName + ": " + paramValue + "\r\n");
        }
    }

    public void saveHttpRequest() {
        this.path = this.basePath + this.path;
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
        if (this.para_bodystr == "") {
            switch (this.content_type) {
                case "application/json": {
                    this.para_bodystr = "{}";
                    break;
                }
                case "application/xml": {
                    this.para_bodystr = "<?xml>";
                    break;
                }
                default: {
                    this.para_bodystr = "";
                }
            }
        }
        this.path = this.path + this.para_querystr;
        this.newheaders.set(0, this.method + " " + this.path + " HTTP/1.1");
        if (this.content_type != "") {
            this.newheaders.add("Content-Type: " + this.content_type + "\r\n");
            this.apiRequestResponse.put(this.newheaders, this.para_bodystr.getBytes(StandardCharsets.UTF_8));
        } else {
            this.apiRequestResponse.put(this.newheaders, null);
        }
    }
}

