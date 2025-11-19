/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.utils;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import APIKit.BurpExtenderAdapter;

public class CommonUtils {
    public static String combineURLs(String baseUrl, String relativeUrl) {
        String[] baseUrlParts;
        String lastSegment;
        if (baseUrl == null || baseUrl.trim().isEmpty() || baseUrl.equals("/")) {
            baseUrl = "/";
        } else if (!baseUrl.endsWith("/")) {
            baseUrl = baseUrl + "/";
        }
        if (baseUrl.equals("/")) {
            return "/" + relativeUrl;
        }
        String Protocol = "";
        int protocolEndIndex = baseUrl.indexOf("://");
        if (protocolEndIndex != -1) {
            Protocol = baseUrl.substring(0, protocolEndIndex += 3);
            baseUrl = baseUrl.substring(protocolEndIndex);
        }
        if ((relativeUrl = relativeUrl.replaceFirst("^/+", "")).startsWith(lastSegment = (baseUrlParts = baseUrl.split("/"))[baseUrlParts.length - 1])) {
            relativeUrl = relativeUrl.substring(lastSegment.length());
        }
        if (!relativeUrl.startsWith("/")) {
            relativeUrl = "/" + relativeUrl;
        }
        return Protocol + (baseUrl + relativeUrl).replaceAll("/{2,}", "/");
    }

    public static String getUrlPath(URL url) {
        String path = url.getPath();
        while (path.startsWith("/")) {
            path = path.substring(1);
        }
        return path;
    }

    public static String getUrlRootPath(URL url) {
        return url.getProtocol() + "://" + url.getHost() + ":" + url.getPort();
    }

    public static String GetLowestPath(URL url) {
        String path = url.getPath();
        path = path.length() == 0 || path.endsWith("/") ? "/" : path.substring(path.lastIndexOf("/") + 1);
        return path;
    }

    public static String getUrlWithoutFilename(URL url) {
        String urlRootPath = CommonUtils.getUrlRootPath(url);
        String path = url.getPath();
        if (path.length() == 0) {
            path = "/";
        }
        if (url.getFile().endsWith("/?format=openapi")) {
            return urlRootPath + url.getFile();
        }
        if (path.endsWith("/")) {
            return urlRootPath + path;
        }
        return urlRootPath + path.substring(0, path.lastIndexOf("/") + 1);
    }

    public static Set<String> getUrlPathListWithCrossDir(URL url) {
        int i2;
        String urlRootPath = CommonUtils.getUrlRootPath(url);
        String path = url.getPath();
        ArrayList<String> pathParts = new ArrayList<String>(Arrays.asList(path.split("/")));
        if (!pathParts.isEmpty() && pathParts.get(0).isEmpty()) {
            pathParts.remove(0);
        }
        LinkedHashSet<String> UrlPathList = new LinkedHashSet<String>();
        for (i2 = 1; i2 < pathParts.size(); ++i2) {
            String partialPath = String.join((CharSequence) "/", pathParts.subList(0, i2));
            UrlPathList.add(urlRootPath + "/" + partialPath);
        }
        for (i2 = pathParts.size() - 1; i2 > 0; --i2) {
            for (int j = 0; j < i2; ++j) {
                String partialPath = String.join((CharSequence) "/", pathParts.subList(0, i2));
                String backPath = String.join((CharSequence) "", Collections.nCopies(j + 1, "/..;"));
                UrlPathList.add(urlRootPath + "/" + partialPath + backPath);
            }
        }
        UrlPathList.add(urlRootPath);
        return UrlPathList;
    }

    public static Set<String> getUrlPathList(URL url) {
        String path;
        String urlRootPath = CommonUtils.getUrlRootPath(url);
        String tmppath = path = url.getPath();
        HashSet<String> UrlPathList = new HashSet<String>();
        while (tmppath.length() != 0 || tmppath.equals("/")) {
            tmppath = tmppath.substring(0, tmppath.lastIndexOf("/"));
            UrlPathList.add(urlRootPath + tmppath);
        }
        return UrlPathList;
    }

    public static String getCurrentDateTime() {
        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(d);
    }

    public static byte[] getHttpRequestBody(byte[] request) {
        int bodyOffset = -1;
        IRequestInfo analyzeRequest = BurpExtenderAdapter.getHelpers().analyzeRequest(request);
        bodyOffset = analyzeRequest.getBodyOffset();
        return Arrays.copyOfRange(request, bodyOffset, request.length);
    }

    public static byte[] getHttpResponseBody(byte[] response) {
        int bodyOffset = -1;
        IResponseInfo analyzeResponse = BurpExtenderAdapter.getHelpers().analyzeResponse(response);
        bodyOffset = analyzeResponse.getBodyOffset();
        return Arrays.copyOfRange(response, bodyOffset, response.length);
    }

    @SuppressWarnings("unchecked")
    public static <E> E randomChoice(Collection<? extends E> input) {
        if (input == null || input.isEmpty()) {
            return null;
        }

        int idx = new SecureRandom().nextInt(input.size());

        if (input instanceof List) {
            return ((List<E>) input).get(idx);
        }

        // 如果不是 List，则转换为 ArrayList 后再获取
        return new ArrayList<>(input).get(idx);
    }

    public static String exceptionToString(Throwable throwable) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        return sw.toString();
    }

    public static Boolean isUnAuthResponse(IHttpRequestResponse httpRequestResponse) {
        short statusCode = BurpExtenderAdapter.getHelpers().analyzeResponse(httpRequestResponse.getResponse()).getStatusCode();
        return statusCode == 200 || statusCode == 405 || statusCode == 500;
    }

    public static String getContentLength(IHttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null || httpRequestResponse.getResponse() == null) {
            return "0";
        }
        
        byte[] response = httpRequestResponse.getResponse();
        String responseString = new String(response);
        String contentLength = "0";
        
        // 首先尝试从响应头中获取Content-Length
        Pattern contentLengthPattern = Pattern.compile("Content-Length: (\\d+)", Pattern.CASE_INSENSITIVE);
        Matcher contentLengthMatcher = contentLengthPattern.matcher(responseString);
        if (contentLengthMatcher.find()) {
            contentLength = contentLengthMatcher.group(1);
        } else {
            // 如果响应头中没有Content-Length，计算实际响应体长度
            try {
                byte[] responseBody = getHttpResponseBody(response);
                if (responseBody != null) {
                    contentLength = String.valueOf(responseBody.length);
                }
            } catch (Exception e) {
                // 如果无法获取响应体，使用整个响应的长度
                contentLength = String.valueOf(response.length);
            }
        }
        
        return contentLength;
    }

    public static <E> List<E> removeDuplicateElement(List<E> list) {
        if (list.size() < 2) {
            return list;
        }
        ArrayList<E> result = new ArrayList<E>();
        HashSet<E> seen = new HashSet<E>();
        for (E element : list) {
            if (element == null || !seen.add(element)) continue;
            result.add(element);
        }
        return result;
    }

    public static List<String> formatHeaders(String headers) {
        String[] lines;
        if (headers == null || headers.trim().isEmpty()) {
            return new ArrayList<String>();
        }
        ArrayList<String> headerList = new ArrayList<String>();
        for (String line : lines = headers.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            headerList.add(trimmed);
        }
        return headerList;
    }
}

