package func;


import burp.Bfunc;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import utils.PathUtils;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 扫描任务线程类
 * 实现Runnable接口，用于在线程池中执行扫描任务
 */
public class threads implements Runnable {
    private Map<String, Object> zidian;
    private vulscan vul;
    private IHttpRequestResponse newHttpRequestResponse;
    private List<String> heads;
    private List<String> Bypass_List;
    private List<String> Bypass_List_first;
    private List<String> Bypass_End_List;

    public threads(Map<String, Object> zidian, vulscan vul, IHttpRequestResponse newHttpRequestResponse, List<String> heads, List<String> Bypass_List, List<String> Bypass_First_List, List<String> Bypass_End_List) {
        this.zidian = zidian;
        this.vul = vul;
        this.newHttpRequestResponse = newHttpRequestResponse;
        this.heads = heads;
        this.Bypass_List = Bypass_List;
        this.Bypass_List_first = Bypass_First_List;
        this.Bypass_End_List = Bypass_End_List;
    }

    @Override
    public void run() {
        go(this.zidian, this.vul, this.newHttpRequestResponse, this.heads, this.Bypass_List, this.Bypass_List_first, this.Bypass_End_List);
    }

    private static void go(Map<String, Object> zidian, vulscan vul, IHttpRequestResponse newHttpRequestResponse, List<String> heads, List<String> Bypass_List, List<String> Bypass_List_first, List<String> Bypass_End_List) {

        String name = (String) zidian.get("name");
        boolean loaded = (boolean) zidian.get("loaded");
        String urll = Bfunc.ProcTemplateLanguag((String) zidian.get("url"), newHttpRequestResponse, vul, false);
        String re = Bfunc.ProcTemplateLanguag((String) zidian.get("re"), newHttpRequestResponse, vul, true);
        String info = (String) zidian.get("info");
        Collection<Integer> states = Bfunc.StatusCodeProc((String) zidian.get("state"));

        if (loaded) {
            URL url = null;
            try {
                // 使用PathUtils工具类规范化路径
                url = PathUtils.buildURL(
                    vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getProtocol(),
                    vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getHost(),
                    vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getPort(),
                    String.valueOf(vul.Path_record),
                    urll
                );
            } catch (MalformedURLException e) {
                e.printStackTrace();
            }
            byte[] request = vul.burp.help.buildHttpRequest(url);
            // 添加head
            if (vul.burp.Carry_head) {
                synchronized (heads) {
                    heads.remove(0);
                    heads.add(0, vul.burp.help.analyzeRequest(request).getHeaders().get(0));
                    request = vul.burp.help.buildHttpMessage(heads, new byte[]{});
                }
            }
            if ("POST".equals(zidian.get("method"))) {
                String body = (String) zidian.get("body");
                List<String> headers = vul.burp.help.analyzeRequest(request).getHeaders();
                // 替换请求行为POST
                String firstLine = headers.get(0);
                if (!firstLine.startsWith("POST")) {
                    String[] parts = firstLine.split(" ", 3);
                    if (parts.length == 3) {
                        headers.set(0, "POST " + parts[1] + " " + parts[2]);
                    }
                }
                if (body != null && !body.isEmpty()) {
                    request = vul.burp.help.buildHttpMessage(headers, body.getBytes());
                } else {
                    request = vul.burp.help.buildHttpMessage(headers, new byte[]{});
                }
            }

            newHttpRequestResponse = vul.burp.call.makeHttpRequest(vul.httpService, request);

            // 是否匹配成功
            boolean IFconform = true;
            Integer stat = 0;
            if (newHttpRequestResponse.getResponse() == null){
                return;
            }

            if (states.contains(new Integer(vul.burp.help.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode()))) {
                byte[] resp = newHttpRequestResponse.getResponse();
                Pattern re_rule = Pattern.compile(re, Pattern.CASE_INSENSITIVE);
                Matcher pipe = re_rule.matcher(vul.burp.help.bytesToString(resp));
                String lang = String.valueOf(vul.burp.help.bytesToString(resp).length());
                if (pipe.find()) {
                    synchronized(vul){
                        vulscan.ir_add(vul.burp.tags, name, vul.burp.help.analyzeRequest(newHttpRequestResponse).getMethod(), vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().toString(), String.valueOf(vul.burp.help.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode()) + " ", info, lang, newHttpRequestResponse);
                        IFconform = false;
                    }
                }
            }
            
            // 无论正常匹配是否成功都执行bypass
            // bypass 第一个斜杠
            if (vul.burp.BypassFirst) {
                for (String i : Bypass_List_first) {
                    // 基于原始路径构建bypass请求：Path_record + bypass + Load_List路径
                    String bypassPath = vul.Path_record + "/" + i + urll;
                    vul.burp.call.printOutput("[Debug] Bypass path: " + bypassPath + " (Path_record: " + vul.Path_record + ", bypass: " + i + ", Load_List: " + urll + ")");
                    
                    URL bypassUrl = null;
                    try {
                        bypassUrl = PathUtils.buildURL(
                            vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getProtocol(),
                            vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getHost(),
                            vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getPort(),
                            "",
                            bypassPath
                        );
                    } catch (MalformedURLException e) {
                        e.printStackTrace();
                        continue;
                    }
                    byte[] bypassRequest = vul.burp.help.buildHttpRequest(bypassUrl);
                    
                    // 处理POST请求
                    if ("POST".equals(zidian.get("method"))) {
                        String body = (String) zidian.get("body");
                        List<String> headers = vul.burp.help.analyzeRequest(bypassRequest).getHeaders();
                        String firstLine = headers.get(0);
                        if (!firstLine.startsWith("POST")) {
                            String[] parts = firstLine.split(" ", 3);
                            if (parts.length == 3) {
                                headers.set(0, "POST " + parts[1] + " " + parts[2]);
                            }
                        }
                        if (body != null && !body.isEmpty()) {
                            bypassRequest = vul.burp.help.buildHttpMessage(headers, body.getBytes());
                        } else {
                            bypassRequest = vul.burp.help.buildHttpMessage(headers, new byte[]{});
                        }
                    }
                    
                    IHttpRequestResponse bypassResponse = vul.burp.call.makeHttpRequest(vul.httpService, bypassRequest);
                    if (bypassResponse.getResponse() != null && states.contains(new Integer(vul.burp.help.analyzeResponse(bypassResponse.getResponse()).getStatusCode()))) {
                        byte[] resp = bypassResponse.getResponse();
                        Pattern re_rule = Pattern.compile(re, Pattern.CASE_INSENSITIVE);
                        Matcher pipe = re_rule.matcher(vul.burp.help.bytesToString(resp));
                        String lang = String.valueOf(vul.burp.help.bytesToString(resp).length());
                        if (pipe.find()) {
                            synchronized(vul) {
                                vulscan.ir_add(vul.burp.tags, name, vul.burp.help.analyzeRequest(bypassResponse).getMethod(), vul.burp.help.analyzeRequest(bypassResponse).getUrl().toString(), String.valueOf(vul.burp.help.analyzeResponse(bypassResponse.getResponse()).getStatusCode()) + " ", info, lang, bypassResponse);
                            }
                        }
                    }
                }
            }

            // bypass 全部斜杠
            if (vul.burp.Bypass) {
                for (String i : Bypass_List) {
                    byte[] newRequest = threads.edit_Bypass_request(vul.burp.help, request, i,urll);
                    IHttpRequestResponse bypassResponse = vul.burp.call.makeHttpRequest(vul.httpService, newRequest);
                    if (bypassResponse.getResponse() != null && states.contains(new Integer(vul.burp.help.analyzeResponse(bypassResponse.getResponse()).getStatusCode()))) {
                        byte[] resp = bypassResponse.getResponse();
                        Pattern re_rule = Pattern.compile(re, Pattern.CASE_INSENSITIVE);
                        Matcher pipe = re_rule.matcher(vul.burp.help.bytesToString(resp));
                        String lang = String.valueOf(vul.burp.help.bytesToString(resp).length());
                        if (pipe.find()) {
                            synchronized(vul) {
                                vulscan.ir_add(vul.burp.tags, name, vul.burp.help.analyzeRequest(bypassResponse).getMethod(), vul.burp.help.analyzeRequest(bypassResponse).getUrl().toString(), String.valueOf(vul.burp.help.analyzeResponse(bypassResponse.getResponse()).getStatusCode()) + " ", info, lang, bypassResponse);
                            }
                        }
                    }
                }
            }

            // bypass 结尾后缀
            if (vul.burp.BypassEnd) {
                for (String i : Bypass_End_List) {
                    byte[] newRequestEnd = edit_Bypass_request_end(vul.burp.help, request, i);
                    IHttpRequestResponse bypassResponse = vul.burp.call.makeHttpRequest(vul.httpService, newRequestEnd);
                    if (bypassResponse.getResponse() != null && states.contains(new Integer(vul.burp.help.analyzeResponse(bypassResponse.getResponse()).getStatusCode()))) {
                        byte[] resp = bypassResponse.getResponse();
                        Pattern re_rule = Pattern.compile(re, Pattern.CASE_INSENSITIVE);
                        Matcher pipe = re_rule.matcher(vul.burp.help.bytesToString(resp));
                        String lang = String.valueOf(vul.burp.help.bytesToString(resp).length());
                        if (pipe.find()) {
                            synchronized(vul) {
                                vulscan.ir_add(vul.burp.tags, name, vul.burp.help.analyzeRequest(bypassResponse).getMethod(), vul.burp.help.analyzeRequest(bypassResponse).getUrl().toString(), String.valueOf(vul.burp.help.analyzeResponse(bypassResponse.getResponse()).getStatusCode()) + " ", info, lang, bypassResponse);
                            }
                        }
                    }
                }
            }

            synchronized (vul.burp.call) {
                vul.burp.call.printOutput(url.toString());
            }
        }
    }

    private static byte[] edit_Bypass_request_first(IExtensionHelpers help, byte[] request, String str, String payPath) {
        String requests = help.bytesToString(request);
        String[] rows = requests.split("\r\n");
        String path = rows[0].split(" ")[1];
        String prefix = "";

        // 处理协议前缀
        if (path.contains("http://")) {
            prefix = "http://";
            path = path.replace("http://", "");
        } else if (path.contains("https://")) {
            prefix = "https://";
            path = path.replace("https://", "");
        }

        // 移除域名部分（如果存在）
        if (path.contains("/")) {
            path = path.substring(path.indexOf("/"));
        }

        // 构建新路径：当前路径 + bypass + Load_List中的路径
        String newPath = path + "/" + str + payPath;
        
        // 构建新请求
        String newPathFull = prefix + newPath;
        String row1 = rows[0].split(" ")[0] + " " + newPathFull + " " + rows[0].split(" ")[2];
        String newRequest = requests.replace(rows[0], row1);

        return help.stringToBytes(newRequest);
    }

    private static byte[] edit_Bypass_request(IExtensionHelpers help, byte[] request, String str, String payPath) {

        String requests = help.bytesToString(request);
        String[] rows = requests.split("\r\n");
        String path = rows[0].split(" ")[1];
        String prefix = "";
        if (path.contains("http://")) {
            prefix = "http://";
            path = path.replace("http://", "");
        }
        if (path.contains("https://")) {
            path = path.replace("http://", "");
            prefix = "https://";
        }

        String newpath = path.replace(payPath,"") + payPath.replace("/", "/" + str + "/");
        if (path.endsWith("/")) {
            newpath = newpath.substring(0, newpath.lastIndexOf(str + "/"));
        }
        newpath = prefix + newpath;
        String row1 = rows[0].split(" ")[0] + " " + newpath + " " + rows[0].split(" ")[2];
        String newRequest = requests.replace(rows[0], row1);
        return help.stringToBytes(newRequest);
    }

    private static byte[] edit_Bypass_request_end(IExtensionHelpers help, byte[] request, String bypassEnd) {
        String requests = help.bytesToString(request);
        String[] rows = requests.split("\r\n");
        String path = rows[0].split(" ")[1];
        String prefix = "";

        if (path.contains("http://")) {
            prefix = "http://";
            path = path.replace("http://", "");
        } else if (path.contains("https://")) {
            prefix = "https://";
            path = path.replace("https://", "");
        }

        String newPathEnd = prefix + path + bypassEnd;
        String row1End = rows[0].split(" ")[0] + " " + newPathEnd + " " + rows[0].split(" ")[2];
        String newRequestEnd = requests.replace(rows[0], row1End);

        return help.stringToBytes(newRequestEnd);
    }


}



