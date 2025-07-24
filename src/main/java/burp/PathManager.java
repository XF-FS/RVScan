package burp;

import yaml.YamlUtil;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 路径管理器 - 图形化管理各种绕过路径和指纹识别路径
 */
public class PathManager {
    private BurpExtender burp;
    private JPanel mainPanel;
    
    // 路径列表模型
    private DefaultListModel<String> bypassEndListModel;
    private DefaultListModel<String> bypassListModel;
    private DefaultListModel<String> bypassFirstListModel;
    private DefaultListModel<String> fingerprintPathsModel;
    
    // 路径列表组件
    private JList<String> bypassEndList;
    private JList<String> bypassList;
    private JList<String> bypassFirstList;
    private JList<String> fingerprintPathsList;
    
    public PathManager(BurpExtender burp) {
        this.burp = burp;
        initializeComponents();
        loadPathsFromConfig();
    }
    
    /**
     * 初始化界面组件
     */
    private void initializeComponents() {
        mainPanel = new JPanel(new BorderLayout());
        
        // 创建四个路径管理面板
        JPanel pathPanelsContainer = new JPanel(new GridLayout(2, 2, 10, 10));
        pathPanelsContainer.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 创建各个路径管理面板
        pathPanelsContainer.add(createBypassEndPanel());
        pathPanelsContainer.add(createBypassPanel());
        pathPanelsContainer.add(createBypassFirstPanel());
        pathPanelsContainer.add(createFingerprintPathsPanel());
        
        // 创建底部操作面板
        JPanel bottomPanel = createBottomPanel();
        
        mainPanel.add(pathPanelsContainer, BorderLayout.CENTER);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);
    }
    
    /**
     * 创建后缀绕过路径管理面板
     */
    private JPanel createBypassEndPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("后缀绕过路径 (Bypass_End_List)"));
        
        bypassEndListModel = new DefaultListModel<>();
        bypassEndList = new JList<>(bypassEndListModel);
        bypassEndList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        JScrollPane scrollPane = new JScrollPane(bypassEndList);
        scrollPane.setPreferredSize(new Dimension(250, 150));
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton addButton = new JButton("添加");
        JButton editButton = new JButton("编辑");
        JButton deleteButton = new JButton("删除");
        
        addButton.addActionListener(e -> addPathItem(bypassEndListModel, "后缀绕过路径"));
        editButton.addActionListener(e -> editPathItem(bypassEndList, bypassEndListModel, "后缀绕过路径"));
        deleteButton.addActionListener(e -> deletePathItem(bypassEndList, bypassEndListModel));
        
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建路径绕过管理面板
     */
    private JPanel createBypassPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("路径绕过 (Bypass_List)"));
        
        bypassListModel = new DefaultListModel<>();
        bypassList = new JList<>(bypassListModel);
        bypassList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        JScrollPane scrollPane = new JScrollPane(bypassList);
        scrollPane.setPreferredSize(new Dimension(250, 150));
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton addButton = new JButton("添加");
        JButton editButton = new JButton("编辑");
        JButton deleteButton = new JButton("删除");
        
        addButton.addActionListener(e -> addPathItem(bypassListModel, "路径绕过"));
        editButton.addActionListener(e -> editPathItem(bypassList, bypassListModel, "路径绕过"));
        deleteButton.addActionListener(e -> deletePathItem(bypassList, bypassListModel));
        
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建前缀绕过路径管理面板
     */
    private JPanel createBypassFirstPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("前缀绕过路径 (Bypass_First_List)"));
        
        bypassFirstListModel = new DefaultListModel<>();
        bypassFirstList = new JList<>(bypassFirstListModel);
        bypassFirstList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        JScrollPane scrollPane = new JScrollPane(bypassFirstList);
        scrollPane.setPreferredSize(new Dimension(250, 150));
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton addButton = new JButton("添加");
        JButton editButton = new JButton("编辑");
        JButton deleteButton = new JButton("删除");
        
        addButton.addActionListener(e -> addPathItem(bypassFirstListModel, "前缀绕过路径"));
        editButton.addActionListener(e -> editPathItem(bypassFirstList, bypassFirstListModel, "前缀绕过路径"));
        deleteButton.addActionListener(e -> deletePathItem(bypassFirstList, bypassFirstListModel));
        
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建指纹识别路径管理面板
     */
    private JPanel createFingerprintPathsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("指纹识别路径 (Fingerprint_Paths)"));
        
        fingerprintPathsModel = new DefaultListModel<>();
        fingerprintPathsList = new JList<>(fingerprintPathsModel);
        fingerprintPathsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        JScrollPane scrollPane = new JScrollPane(fingerprintPathsList);
        scrollPane.setPreferredSize(new Dimension(250, 150));
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton addButton = new JButton("添加");
        JButton editButton = new JButton("编辑");
        JButton deleteButton = new JButton("删除");
        
        addButton.addActionListener(e -> addPathItem(fingerprintPathsModel, "指纹识别路径"));
        editButton.addActionListener(e -> editPathItem(fingerprintPathsList, fingerprintPathsModel, "指纹识别路径"));
        deleteButton.addActionListener(e -> deletePathItem(fingerprintPathsList, fingerprintPathsModel));
        
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建底部操作面板
     */
    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new FlowLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));
        
        JButton saveButton = new JButton("保存配置");
        JButton reloadButton = new JButton("重新加载");
        JButton resetButton = new JButton("恢复默认");
        
        saveButton.setPreferredSize(new Dimension(100, 30));
        reloadButton.setPreferredSize(new Dimension(100, 30));
        resetButton.setPreferredSize(new Dimension(100, 30));
        
        saveButton.addActionListener(e -> savePathsToConfig());
        reloadButton.addActionListener(e -> loadPathsFromConfig());
        resetButton.addActionListener(e -> resetToDefault());
        
        panel.add(saveButton);
        panel.add(reloadButton);
        panel.add(resetButton);
        
        return panel;
    }
    
    /**
     * 添加路径项
     */
    private void addPathItem(DefaultListModel<String> model, String type) {
        String input = JOptionPane.showInputDialog(
            mainPanel,
            "请输入" + type + ":",
            "添加" + type,
            JOptionPane.PLAIN_MESSAGE
        );
        
        if (input != null && !input.trim().isEmpty()) {
            String path = input.trim();
            if (!model.contains(path)) {
                model.addElement(path);
                if (burp != null && burp.call != null) {
                    burp.call.printOutput("[PathManager] 添加" + type + ": " + path);
                }
            } else {
                JOptionPane.showMessageDialog(
                    mainPanel,
                    "该路径已存在！",
                    "重复路径",
                    JOptionPane.WARNING_MESSAGE
                );
            }
        }
    }
    
    /**
     * 编辑路径项
     */
    private void editPathItem(JList<String> list, DefaultListModel<String> model, String type) {
        int selectedIndex = list.getSelectedIndex();
        if (selectedIndex == -1) {
            JOptionPane.showMessageDialog(
                mainPanel,
                "请先选择要编辑的" + type + "！",
                "未选择项目",
                JOptionPane.WARNING_MESSAGE
            );
            return;
        }
        
        String currentValue = model.getElementAt(selectedIndex);
        String input = JOptionPane.showInputDialog(
            mainPanel,
            "请修改" + type + ":",
            currentValue
        );
        
        if (input != null && !input.trim().isEmpty()) {
            String newPath = input.trim();
            if (!newPath.equals(currentValue) && model.contains(newPath)) {
                JOptionPane.showMessageDialog(
                    mainPanel,
                    "该路径已存在！",
                    "重复路径",
                    JOptionPane.WARNING_MESSAGE
                );
                return;
            }
            
            model.setElementAt(newPath, selectedIndex);
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[PathManager] 修改" + type + ": " + currentValue + " -> " + newPath);
            }
        }
    }
    
    /**
     * 删除路径项
     */
    private void deletePathItem(JList<String> list, DefaultListModel<String> model) {
        int selectedIndex = list.getSelectedIndex();
        if (selectedIndex == -1) {
            JOptionPane.showMessageDialog(
                mainPanel,
                "请先选择要删除的项目！",
                "未选择项目",
                JOptionPane.WARNING_MESSAGE
            );
            return;
        }
        
        String selectedItem = model.getElementAt(selectedIndex);
        int result = JOptionPane.showConfirmDialog(
            mainPanel,
            "确定要删除路径 \"" + selectedItem + "\" 吗？",
            "确认删除",
            JOptionPane.YES_NO_OPTION
        );
        
        if (result == JOptionPane.YES_OPTION) {
            model.removeElementAt(selectedIndex);
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[PathManager] 删除路径: " + selectedItem);
            }
        }
    }
    
    /**
     * 从配置文件加载路径
     */
    private void loadPathsFromConfig() {
        try {
            Map<String, Object> config = YamlUtil.readYaml(BurpExtender.Yaml_Path);
            
            // 清空现有数据
            bypassEndListModel.clear();
            bypassListModel.clear();
            bypassFirstListModel.clear();
            fingerprintPathsModel.clear();
            
            // 加载Bypass_End_List
            List<String> bypassEndList = (List<String>) config.get("Bypass_End_List");
            if (bypassEndList != null) {
                for (String path : bypassEndList) {
                    bypassEndListModel.addElement(path);
                }
            }
            
            // 加载Bypass_List
            List<String> bypassList = (List<String>) config.get("Bypass_List");
            if (bypassList != null) {
                for (String path : bypassList) {
                    bypassListModel.addElement(path);
                }
            }
            
            // 加载Bypass_First_List
            List<String> bypassFirstList = (List<String>) config.get("Bypass_First_List");
            if (bypassFirstList != null) {
                for (String path : bypassFirstList) {
                    bypassFirstListModel.addElement(path);
                }
            }
            
            // 加载Fingerprint_Paths
            List<String> fingerprintPaths = (List<String>) config.get("Fingerprint_Paths");
            if (fingerprintPaths != null) {
                for (String path : fingerprintPaths) {
                    fingerprintPathsModel.addElement(path);
                }
            }
            
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[PathManager] 已从配置文件加载路径配置");
            }
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(
                mainPanel,
                "加载配置文件失败: " + e.getMessage(),
                "加载失败",
                JOptionPane.ERROR_MESSAGE
            );
            
            if (burp != null && burp.call != null) {
                burp.call.printError("[PathManager] 加载配置失败: " + e.getMessage());
            }
        }
    }
    
    /**
     * 保存路径到配置文件
     */
    private void savePathsToConfig() {
        try {
            Map<String, Object> config = YamlUtil.readYaml(BurpExtender.Yaml_Path);
            
            // 如果config为null，创建新的配置对象
            if (config == null) {
                config = new HashMap<>();
            }
            
            // 保存Bypass_End_List
            List<String> bypassEndList = new ArrayList<>();
            for (int i = 0; i < bypassEndListModel.size(); i++) {
                bypassEndList.add(bypassEndListModel.getElementAt(i));
            }
            config.put("Bypass_End_List", bypassEndList);
            
            // 保存Bypass_List
            List<String> bypassList = new ArrayList<>();
            for (int i = 0; i < bypassListModel.size(); i++) {
                bypassList.add(bypassListModel.getElementAt(i));
            }
            config.put("Bypass_List", bypassList);
            
            // 保存Bypass_First_List
            List<String> bypassFirstList = new ArrayList<>();
            for (int i = 0; i < bypassFirstListModel.size(); i++) {
                bypassFirstList.add(bypassFirstListModel.getElementAt(i));
            }
            config.put("Bypass_First_List", bypassFirstList);
            
            // 保存Fingerprint_Paths
            List<String> fingerprintPaths = new ArrayList<>();
            for (int i = 0; i < fingerprintPathsModel.size(); i++) {
                fingerprintPaths.add(fingerprintPathsModel.getElementAt(i));
            }
            config.put("Fingerprint_Paths", fingerprintPaths);
            
            // 写入配置文件 - 这会保留所有现有的配置项，包括Load_List
            YamlUtil.writeYaml(config, BurpExtender.Yaml_Path);
            
            JOptionPane.showMessageDialog(
                mainPanel,
                "路径配置已成功保存到配置文件！",
                "保存成功",
                JOptionPane.INFORMATION_MESSAGE
            );
            
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[PathManager] 路径配置已保存到配置文件");
            }
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(
                mainPanel,
                "保存配置文件失败: " + e.getMessage(),
                "保存失败",
                JOptionPane.ERROR_MESSAGE
            );
            
            if (burp != null && burp.call != null) {
                burp.call.printError("[PathManager] 保存配置失败: " + e.getMessage());
            }
        }
    }
    
    /**
     * 恢复默认配置
     */
    private void resetToDefault() {
        int result = JOptionPane.showConfirmDialog(
            mainPanel,
            "确定要恢复默认路径配置吗？这将清除所有自定义路径！",
            "确认恢复默认",
            JOptionPane.YES_NO_OPTION
        );
        
        if (result == JOptionPane.YES_OPTION) {
            // 清空所有列表
            bypassEndListModel.clear();
            bypassListModel.clear();
            bypassFirstListModel.clear();
            fingerprintPathsModel.clear();
            
            // 设置默认值
            // Bypass_End_List默认值
            bypassEndListModel.addElement(";.js");
            bypassEndListModel.addElement(".json");
            bypassEndListModel.addElement(".js");
            
            // Bypass_List默认值
            bypassListModel.addElement("%2f");
            bypassListModel.addElement("%2e");
            
            // Bypass_First_List默认值
            bypassFirstListModel.addElement("css/..;/..;");
            bypassFirstListModel.addElement("..;");
            bypassFirstListModel.addElement("js/..;/..;");
            
            // Fingerprint_Paths默认值
            fingerprintPathsModel.addElement("/");
            fingerprintPathsModel.addElement("/admin");
            fingerprintPathsModel.addElement("/login");
            fingerprintPathsModel.addElement("/index.php");
            fingerprintPathsModel.addElement("/index.html");
            fingerprintPathsModel.addElement("/console");
            
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[PathManager] 已恢复默认路径配置");
            }
        }
    }
    
    /**
     * 获取主面板
     */
    public JPanel getMainPanel() {
        return mainPanel;
    }
} 