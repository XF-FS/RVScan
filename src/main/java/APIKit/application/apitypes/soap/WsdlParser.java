/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.soap;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import APIKit.application.apitypes.ApiEndpoint;
import APIKit.utils.HttpRequestFormator;
import APIKit.utils.HttpRequestResponse;
import com.predic8.wsdl.BindingOperation;
import com.predic8.wsdl.Definitions;
import com.predic8.wsdl.Port;
import com.predic8.wsdl.Service;
import com.predic8.wsdl.WSDLParser;
import com.predic8.wstool.creator.RequestTemplateCreator;
import com.predic8.wstool.creator.SOARequestCreator;
import groovy.xml.MarkupBuilder;

import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;
import APIKit.BurpExtenderAdapter;

public class WsdlParser {
    public static ArrayList<ApiEndpoint> parseWsdl(IHttpRequestResponse apiDocument, IHttpRequestResponse basePath, boolean isTargetScan) {
        IExtensionHelpers helpers = BurpExtenderAdapter.getHelpers();
        WSDLParser parser = new WSDLParser();
        String APIdocumenturl = helpers.analyzeRequest(apiDocument).getUrl().toString();
        if (!APIdocumenturl.endsWith("?wsdl")) {
            APIdocumenturl = APIdocumenturl + "?wsdl";
        }
        Definitions definitions = parser.parse(APIdocumenturl);
        List<Service> services = definitions.getServices();
        ArrayList<ApiEndpoint> apiEndpoints = new ArrayList<ApiEndpoint>();
        List<String> headers = basePath == null ? helpers.analyzeRequest(apiDocument.getRequest()).getHeaders() : helpers.analyzeRequest(basePath.getRequest()).getHeaders();
        List<String> httpFirstLine = Arrays.asList(headers.get(0).split(" "));
        httpFirstLine.set(0, "POST");
        headers.set(0, String.join((CharSequence) " ", httpFirstLine));
        HashSet<String> deleteHeader = new HashSet<String>(Arrays.asList("soapaction", "content-type"));
        ArrayList<String> newHeaders = new ArrayList<String>();
        newHeaders.add(String.join((CharSequence) " ", httpFirstLine));
        newHeaders.addAll(headers.subList(1, headers.size()).stream().filter(header -> !deleteHeader.contains(header.toLowerCase().split(":", 2)[0])).collect(Collectors.toList()));
        newHeaders.add("Content-Type: text/xml;charset=UTF-8");
        for (Service service : services) {
            for (Port port : service.getPorts()) {
                URL location;
                try {
                    location = new URL(port.getAddress().getLocation());
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                    return new ArrayList<ApiEndpoint>();
                }
                String locationPath = location.getPath();
                List<String> httpfirstline = Arrays.asList(((String) newHeaders.get(0)).split(" "));
                if (basePath == null) {
                    httpfirstline.set(1, locationPath);
                } else {
                    String basepathurl = helpers.analyzeRequest(basePath).getUrl().getPath();
                    if (!basepathurl.equals("/") && basepathurl.endsWith("/")) {
                        basepathurl = basepathurl.substring(0, basepathurl.length() - 1);
                    }
                    httpfirstline.set(1, basepathurl);
                }
                newHeaders.set(0, String.join((CharSequence) " ", httpfirstline));
                for (BindingOperation operation : port.getBinding().getOperations()) {
                    byte[] apiRequest = null;
                    try {
                        StringWriter writer = new StringWriter();
                        SOARequestCreator creator = new SOARequestCreator(definitions, new RequestTemplateCreator(), new MarkupBuilder(writer));
                        creator.createRequest(port.getName(), operation.getName(), port.getBinding().getName());
                        ArrayList<String> tempHeaders = new ArrayList<String>(newHeaders);
                        tempHeaders.add("SOAPAction: " + operation.getOperation().getSoapAction());
                        if (isTargetScan) {
                            HttpRequestFormator.TrimDupHeader(tempHeaders);
                        }
                        apiRequest = helpers.buildHttpMessage(tempHeaders, writer.toString().getBytes());
                    } catch (Exception e) {
                        continue;
                    }
                    HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
                    if (basePath == null) {
                        tempRequestResponse.setHttpService(apiDocument.getHttpService());
                    } else {
                        tempRequestResponse.setHttpService(basePath.getHttpService());
                    }
                    tempRequestResponse.setRequest(apiRequest);
                    tempRequestResponse.sendRequest();
                    apiEndpoints.add(new ApiEndpoint(operation.getName(), tempRequestResponse));
                }
            }
        }
        return apiEndpoints;
    }
}

