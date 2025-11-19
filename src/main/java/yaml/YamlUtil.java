package yaml;

import burp.BurpExtender;
import func.init_Yaml_thread;
import org.yaml.snakeyaml.Yaml;

import javax.swing.*;
import java.io.*;
import java.util.*;

public class YamlUtil {

    public static void init_Yaml(BurpExtender burp, JPanel one) {
        new init_Yaml_thread(burp, one).start();

    }

    public static Map<String, Object> readYaml(String file_path) {
        File file = new File(file_path);
        Map<String, Object> data = null;
        try {
            if (!file.exists()) {
                return null;
            }
            InputStream inputStream = new FileInputStream(file);
            Yaml yaml = new Yaml();
            data = yaml.load(inputStream);
            inputStream.close();
        } catch (FileNotFoundException e) {
            System.err.println("YAML文件未找到: " + file_path);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("读取YAML文件时发生错误: " + file_path);
            e.printStackTrace();
        }
        return data;
    }

    public static void writeYaml(Map<String, Object> data, String filePath) {
        // 读取原始配置文件
        Map<String, Object> originalYaml = readYaml(filePath);
        
        // 如果原始配置为空，创建默认配置
        if (originalYaml == null) {
            originalYaml = createDefaultConfig();
        }
        
        // 合并新数据和原始配置
        for (String key : data.keySet()) {
            originalYaml.put(key, data.get(key));
        }
        
        Yaml yaml = new Yaml();
        try {
            PrintWriter writer = new PrintWriter(new File(filePath));
            yaml.dump(originalYaml, writer);
            writer.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * 创建默认配置
     */
    private static Map<String, Object> createDefaultConfig() {
        Map<String, Object> defaultConfig = new HashMap<>();
        
        // 创建默认的 Load_List
        List<Map<String, Object>> defaultLoadList = new ArrayList<>();
        
        // 添加一些基本的默认规则
        Map<String, Object> rule1 = new HashMap<>();
        rule1.put("id", 1);
        rule1.put("name", "Nacos");
        rule1.put("method", "GET");
        rule1.put("url", "/nacos/index.html");
        rule1.put("state", "200");
        rule1.put("re", "nacos");
        rule1.put("info", "Nacos Find!!!");
        rule1.put("type", "default");
        rule1.put("loaded", true);
        defaultLoadList.add(rule1);
        
        Map<String, Object> rule2 = new HashMap<>();
        rule2.put("id", 2);
        rule2.put("name", "Druid Monitor");
        rule2.put("method", "GET");
        rule2.put("url", "/druid/index.html");
        rule2.put("state", "200");
        rule2.put("re", "druid");
        rule2.put("info", "Druid Monitor Find!!!");
        rule2.put("type", "default");
        rule2.put("loaded", true);
        defaultLoadList.add(rule2);
        
        Map<String, Object> rule3 = new HashMap<>();
        rule3.put("id", 3);
        rule3.put("name", "Swagger-UI");
        rule3.put("method", "GET");
        rule3.put("url", "/swagger-ui.html");
        rule3.put("state", "200");
        rule3.put("re", "(Swagger 2\\.0)|(\"swagger\"\\:)|(Swagger UI)|(\\<title\\>Swagger UI)|(swaggerVersion)|(id\\=\"swagger\\-ui)|swagger|api-docs|openapi|apiVersion");
        rule3.put("info", "【Swagger-UI Find】");
        rule3.put("type", "ApiDoc");
        rule3.put("loaded", true);
        defaultLoadList.add(rule3);
        
        Map<String, Object> rule4 = new HashMap<>();
        rule4.put("id", 4);
        rule4.put("name", "Spring Actuator");
        rule4.put("method", "GET");
        rule4.put("url", "/actuator");
        rule4.put("state", "200");
        rule4.put("re", "\\{\"_links\"\\:\\{\"self\"\\:\\{");
        rule4.put("info", "actuator Find !!!");
        rule4.put("type", "Spring");
        rule4.put("loaded", true);
        defaultLoadList.add(rule4);
        
        Map<String, Object> rule5 = new HashMap<>();
        rule5.put("id", 5);
        rule5.put("name", "登录接口");
        rule5.put("method", "GET");
        rule5.put("url", "/login");
        rule5.put("state", "200");
        rule5.put("re", "type=\"password\"");
        rule5.put("info", "login interface found");
        rule5.put("type", "常用");
        rule5.put("loaded", true);
        defaultLoadList.add(rule5);
        
        defaultConfig.put("Load_List", defaultLoadList);
        
        // 创建默认的 Bypass_List
        List<String> defaultBypassList = new ArrayList<>();
        defaultBypassList.add("%2f");
        defaultBypassList.add("%2e");
        defaultConfig.put("Bypass_List", defaultBypassList);
        
        // 创建默认的 Bypass_First_List
        List<String> defaultBypassFirstList = new ArrayList<>();
        defaultBypassFirstList.add("css/..;/..;");
        defaultBypassFirstList.add("..;");
        defaultBypassFirstList.add("js/..;/..;");
        defaultConfig.put("Bypass_First_List", defaultBypassFirstList);
        
        // 创建默认的 Bypass_End_List
        List<String> defaultBypassEndList = new ArrayList<>();
        defaultBypassEndList.add(";.js");
        defaultBypassEndList.add(".json");
        defaultBypassEndList.add(".js");
        defaultConfig.put("Bypass_End_List", defaultBypassEndList);
        
        // 创建默认的 Fingerprint_Paths
        List<String> defaultFingerprintPaths = new ArrayList<>();
        defaultFingerprintPaths.add("/");
        defaultConfig.put("Fingerprint_Paths", defaultFingerprintPaths);
        
        return defaultConfig;
    }

    public static void removeYaml(String id, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        if (Yaml_Map == null) {
            Yaml_Map = createDefaultConfig();
        }
        
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        if (List1 == null) {
            List1 = new ArrayList<>();
        }
        
        ArrayList<Map<String, Object>> List2 = new ArrayList<>();
        for (Map<String, Object> zidian : List1) {
            if (zidian.get("id") != null && !zidian.get("id").toString().equals(id)) {
                List2.add(zidian);
            }
        }
        Map<String, Object> save = new HashMap<>(Yaml_Map);
        save.put("Load_List", List2);
        YamlUtil.writeYaml(save, filePath);
    }

    public static void updateYaml(Map<String, Object> up, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        if (Yaml_Map == null) {
            Yaml_Map = createDefaultConfig();
        }
        
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        if (List1 == null) {
            List1 = new ArrayList<>();
        }
        
        List<Map<String, Object>> List2 = new ArrayList<>();
        for (Map<String, Object> zidian : List1) {
            if (zidian.get("id") != null && up.get("id") != null && 
                zidian.get("id").toString().equals(up.get("id").toString())) {
                List2.add(up);
            } else {
                List2.add(zidian);
            }
        }
        Map<String, Object> save = new HashMap<>(Yaml_Map);
        save.put("Load_List", List2);
        YamlUtil.writeYaml(save, filePath);
    }

    public static void addYaml(Map<String, Object> add, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        if (Yaml_Map == null) {
            Yaml_Map = createDefaultConfig();
        }
        
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        if (List1 == null) {
            List1 = new ArrayList<>();
            Yaml_Map.put("Load_List", List1);
        }
        
        int panduan = 0;
        if (add.get("id") != null) {
            for (Map<String, Object> zidian : List1) {
                if (zidian.get("id") != null && zidian.get("id").toString().equals(add.get("id").toString())) {
                    panduan += 1;
                }
            }
        }
        
        if (panduan == 0) {
            Map<String, Object> save = new HashMap<>(Yaml_Map);
            List1.add(add);
            save.put("Load_List", List1);
            YamlUtil.writeYaml(save, filePath);
        }
    }

    public static Map<String, Object> readStrYaml(String str){
        Map<String, Object> data = null;
        Yaml yaml = new Yaml();
        data = yaml.load(str);
        return data;
    }


    public static void MergerUpdateYamlFunc(Map<String, Object> newYaml){
        Map<String, Object> oldYaml = YamlUtil.readYaml(BurpExtender.Yaml_Path);
        
        // 如果旧配置为空，使用默认配置
        if (oldYaml == null) {
            oldYaml = createDefaultConfig();
        }
        
        List<Map<String, Object>> oldYamlList = (List<Map<String, Object>>)oldYaml.get("Load_List");
        List<Map<String, Object>> newYamlList = (List<Map<String, Object>>)newYaml.get("Load_List");
        
        // 确保列表不为空
        if (oldYamlList == null) {
            oldYamlList = new ArrayList<>();
            oldYaml.put("Load_List", oldYamlList);
        }
        if (newYamlList == null) {
            newYamlList = new ArrayList<>();
        }
        
        for (Map<String, Object> i : newYamlList){
            if (!YamlUtil.inYamlList(oldYamlList,i)){
                int id = 0;
                Map<String, Object> currentYaml = YamlUtil.readYaml(BurpExtender.Yaml_Path);
                if (currentYaml != null && currentYaml.get("Load_List") != null) {
                    for (Map<String, Object> zidian : (List<Map<String, Object>>)currentYaml.get("Load_List")) {
                        if (zidian.get("id") != null && (int) zidian.get("id") > id) {
                            id = (int) zidian.get("id");
                        }
                    }
                }
                id += 1;
                i.remove("id");
                i.put("id",id);
                YamlUtil.addYaml(i,BurpExtender.Yaml_Path);
            }
        }
        
        List<String> oldBypassList = (List<String>)oldYaml.get("Bypass_List");
        List<String> newBypassList = (List<String>)newYaml.get("Bypass_List");
        if (oldBypassList == null){
            oldBypassList = newBypassList != null ? newBypassList : new ArrayList<>();
        }else {
            if (newBypassList != null) {
                for (String i : newBypassList){
                    if (!oldBypassList.contains(i)){
                        oldBypassList.add(i);
                    }
                }
            }
        }

        List<String> oldBypassFirstList = (List<String>)oldYaml.get("Bypass_First_List");
        List<String> newBypassFirstList = (List<String>)newYaml.get("Bypass_First_List");
        if (oldBypassFirstList == null){
            oldBypassFirstList = newBypassFirstList != null ? newBypassFirstList : new ArrayList<>();
        }else {
            if (newBypassFirstList != null) {
                for (String i : newBypassFirstList){
                    if (!oldBypassFirstList.contains(i)){
                        oldBypassFirstList.add(i);
                    }
                }
            }
        }

        List<String> oldBypassEndList = (List<String>)oldYaml.get("Bypass_End_List");
        List<String> newBypassEndList = (List<String>)newYaml.get("Bypass_End_List");
        if (oldBypassEndList == null){
            oldBypassEndList = newBypassEndList != null ? newBypassEndList : new ArrayList<>();
        }else {
            if (newBypassEndList != null) {
                for (String i : newBypassEndList){
                    if (!oldBypassEndList.contains(i)){
                        oldBypassEndList.add(i);
                    }
                }
            }
        }

        Map<String, Object> save = new HashMap<>();
        Map<String, Object> finalYaml = YamlUtil.readYaml(BurpExtender.Yaml_Path);
        if (finalYaml == null) {
            finalYaml = createDefaultConfig();
        }
        save.put("Load_List", (List<Map<String, Object>>) finalYaml.get("Load_List"));
        save.put("Bypass_List", oldBypassList);
        save.put("Bypass_First_List", oldBypassFirstList);
        save.put("Bypass_End_List", oldBypassEndList);
        YamlUtil.writeYaml(save,BurpExtender.Yaml_Path);
    }

    public static boolean inYamlList(List<Map<String, Object>> mapList,Map<String, Object> oneMap){
        if (mapList == null || oneMap == null) {
            return false;
        }
        
        for (Map<String, Object> i : mapList){
            if (YamlUtil.ifmapEqual(i,oneMap)){
                return true;
            }
        }
        return false;
    }

    public static boolean ifmapEqual(Map<String, Object> i, Map<String, Object> oneMap){
        if (i == null || oneMap == null) {
            return false;
        }
        
        boolean mapEqual = true;
        for (String key : i.keySet()){
            if (!key.equals("loaded") && !key.equals("id") && !key.equals("type")){
                Object value1 = i.get(key);
                Object value2 = oneMap.get(key);
                if (value1 == null && value2 == null) {
                    continue;
                } else if (value1 == null || value2 == null) {
                    mapEqual = false;
                    break;
                } else if (!value1.equals(value2)){
                    mapEqual = false;
                    break;
                }
            }
        }
        return mapEqual;
    }



}


