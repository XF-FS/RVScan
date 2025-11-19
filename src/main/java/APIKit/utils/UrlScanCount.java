/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.utils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class UrlScanCount {
    private final ConcurrentHashMap<String, Integer> countMap = new ConcurrentHashMap();

    public Map<String, Integer> getStringMap() {
        return this.countMap;
    }

    public Integer get(String key) {
        Integer ret = this.countMap.get(key);
        if (ret == null) {
            return 0;
        }
        return ret;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void add(String key) {
        Map<String, Integer> map;
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("Key \u4e0d\u80fd\u4e3a\u7a7a");
        }
        Map<String, Integer> map2 = map = this.getStringMap();
        synchronized (map2) {
            this.countMap.put(key, this.get(key) + 1);
        }
    }

    public void del(String key) {
        if (this.countMap.get(key) != null) {
            this.countMap.remove(key);
        }
    }

    public void clear() {
        this.countMap.clear();
    }
}

