public class StaticResourceFilterTest {
    
    /**
     * 测试shouldSkipSensitiveScan方法的逻辑
     */
    public static void main(String[] args) {
        // 测试用例
        String[] testPaths = {
            "/favicon.ico",           // 应该跳过
            "/static/js/app.js",      // 应该跳过
            "/css/bootstrap.css",     // 应该跳过
            "/images/logo.png",       // 应该跳过
            "/jquery-3.6.0.min.js",  // 应该跳过
            "/admin/login.php",       // 不应该跳过
            "/api/users",             // 不应该跳过
            "/",                      // 不应该跳过
            "/admin/",                // 不应该跳过
            "/uploads/shell.php",     // 应该跳过（uploads目录）
            "/assets/vue.min.js",     // 应该跳过
            "/node_modules/react/index.js", // 应该跳过
        };
        
        System.out.println("静态资源过滤测试结果：");
        System.out.println("路径\t\t\t\t是否跳过\t预期结果");
        System.out.println("="*60);
        
        for (String path : testPaths) {
            boolean shouldSkip = shouldSkipSensitiveScan(path);
            String expected = getExpectedResult(path);
            String status = shouldSkip == Boolean.parseBoolean(expected) ? "✅" : "❌";
            
            System.out.printf("%-30s\t%s\t\t%s\t%s%n", 
                path, shouldSkip, expected, status);
        }
    }
    
    // 复制shouldSkipSensitiveScan逻辑用于测试
    private static boolean shouldSkipSensitiveScan(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        String lowerPath = path.toLowerCase();
        
        // 明确排除 /favicon.ico
        if (lowerPath.equals("/favicon.ico")) {
            return true;
        }
        
        // 静态资源扩展名
        String[] staticExtensions = {
            ".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".avi", 
            ".mov", ".wmv", ".flv", ".pdf", ".doc", ".docx", ".xls", ".xlsx", 
            ".ppt", ".pptx", ".zip", ".rar", ".7z", ".tar", ".gz", ".swf", 
            ".fla", ".map"
        };
        
        for (String ext : staticExtensions) {
            if (lowerPath.endsWith(ext)) {
                return true;
            }
        }
        
        // 静态资源路径模式
        String[] staticPathPatterns = {
            "/static/", "/assets/", "/public/", "/resources/", "/img/", "/images/", 
            "/css/", "/js/", "/fonts/", "/media/", "/uploads/", "/files/",
            "/themes/", "/template/", "/skin/", "/style/", "/libs/", "/lib/",
            "/node_modules/", "/bower_components/", "/vendor/"
        };
        
        for (String pattern : staticPathPatterns) {
            if (lowerPath.contains(pattern)) {
                return true;
            }
        }
        
        // 常见库文件名模式
        String[] staticFilePatterns = {
            "jquery", "bootstrap", "angular", "react", "vue", "lodash", 
            "moment", "chart", "d3.js", "three.js", "axios", "zepto"
        };
        
        for (String pattern : staticFilePatterns) {
            if (lowerPath.contains(pattern) && (lowerPath.endsWith(".js") || lowerPath.endsWith(".css"))) {
                return true;
            }
        }
        
        return false;
    }
    
    // 获取预期结果
    private static String getExpectedResult(String path) {
        switch (path) {
            case "/favicon.ico":
            case "/static/js/app.js":
            case "/css/bootstrap.css":
            case "/images/logo.png":
            case "/jquery-3.6.0.min.js":
            case "/uploads/shell.php":
            case "/assets/vue.min.js":
            case "/node_modules/react/index.js":
                return "true";
            default:
                return "false";
        }
    }
} 