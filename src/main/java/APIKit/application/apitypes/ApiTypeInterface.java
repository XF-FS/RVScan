/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes;

import burp.IScanIssue;
import java.util.List;

public interface ApiTypeInterface {
    String getApiTypeName();
    Boolean urlAddPath(String apiDocumentUrl);
    Boolean isFingerprintMatch();
    List<IScanIssue> exportIssues();
    String exportConsole();
}