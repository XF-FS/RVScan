/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.utils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;

public class HttpRequestFormator {
    public static void TrimDupHeader(List<String> headers) {
        HashSet<String> tmpSet = new HashSet<String>();
        HashSet<Integer> dupIndex = new HashSet<Integer>();
        for (int i2 = 0; i2 < headers.size(); ++i2) {
            String header = headers.get(i2);
            String[] kv = header.split(":");
            String HeaderName = kv[0].toLowerCase(Locale.ROOT);
            int oldSize = tmpSet.size();
            tmpSet.add(HeaderName);
            int newSize = tmpSet.size();
            if (oldSize != newSize) continue;
            dupIndex.add(i2);
        }
        ArrayList dupIndexlist = new ArrayList(dupIndex);
        int size = dupIndex.size();
        for (int i3 = 0; i3 < size; ++i3) {
            headers.remove((Integer) dupIndexlist.get(size - 1 - i3));
        }
    }
}

