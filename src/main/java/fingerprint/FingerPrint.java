package fingerprint;

import java.util.List;

/**
 * 指纹识别数据结构
 * 基于EHole项目的指纹格式
 */
public class FingerPrint {
    private String cms;           // CMS名称
    private String method;        // 请求方法 (GET/POST)
    private String location;      // 匹配位置 (body/header/title)
    private List<String> keyword; // 关键词列表
    private int status;          // HTTP状态码
    
    public FingerPrint() {}
    
    public FingerPrint(String cms, String method, String location, List<String> keyword, int status) {
        this.cms = cms;
        this.method = method;
        this.location = location;
        this.keyword = keyword;
        this.status = status;
    }
    
    // Getters and Setters
    public String getCms() {
        return cms;
    }
    
    public void setCms(String cms) {
        this.cms = cms;
    }
    
    public String getMethod() {
        return method;
    }
    
    public void setMethod(String method) {
        this.method = method;
    }
    
    public String getLocation() {
        return location;
    }
    
    public void setLocation(String location) {
        this.location = location;
    }
    
    public List<String> getKeyword() {
        return keyword;
    }
    
    public void setKeyword(List<String> keyword) {
        this.keyword = keyword;
    }
    
    public int getStatus() {
        return status;
    }
    
    public void setStatus(int status) {
        this.status = status;
    }
    
    @Override
    public String toString() {
        return "FingerPrint{" +
                "cms='" + cms + '\'' +
                ", method='" + method + '\'' +
                ", location='" + location + '\'' +
                ", keyword=" + keyword +
                ", status=" + status +
                '}';
    }
}