package fingerprint;

import burp.BurpExtender;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.List;
import java.util.Arrays;

/**
 * 指纹识别配置界面
 */
public class FingerprintConfig {
    private BurpExtender burp;
    private FingerprintScanner scanner;
    private JPanel configPanel;
    private JButton enableButton;
    private JButton updateButton;
    private JButton loadFileButton;
    private JButton clearCacheButton;
    private JLabel statusLabel;
    private JLabel statisticsLabel;
    private JTextField rulePathField;
    private JTable fingerprintTable;
    private DefaultTableModel tableModel;
    
    public FingerprintConfig(BurpExtender burp, FingerprintScanner scanner) {
        this.burp = burp;
        this.scanner = scanner;
        initializeUI();
    }
    
    /**
     * 初始化用户界面
     */
    private void initializeUI() {
        configPanel = new JPanel();
        configPanel.setLayout(new BorderLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("指纹识别配置"));
        
        // 顶部面板：规则路径和统计信息
        JPanel topPanel = new JPanel(new BorderLayout());
        
        // 规则路径面板
        JPanel rulePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        rulePanel.add(new JLabel("规则路径: "));
        rulePathField = new JTextField(new File("finger.json").getAbsolutePath(), 30);
        rulePanel.add(rulePathField);
        
        JButton loadButton = new JButton("加载");
        loadButton.addActionListener(e -> loadRules());
        rulePanel.add(loadButton);
        
        // 保留更新按钮但禁用功能
        updateButton = new JButton("更新");
        updateButton.setEnabled(false); // 禁用按钮
        updateButton.setToolTipText("远程更新功能已禁用");
        updateButton.addActionListener(e -> {
            JOptionPane.showMessageDialog(configPanel, 
                "远程更新功能已禁用\n请手动更新指纹库文件", 
                "功能禁用", 
                JOptionPane.INFORMATION_MESSAGE);
        });
        rulePanel.add(updateButton);
        
        topPanel.add(rulePanel, BorderLayout.NORTH);
        
        // 控制按钮面板（只保留清除缓存和统计信息）
        JPanel controlPanel = createControlPanel();
        topPanel.add(controlPanel, BorderLayout.CENTER);
        
        configPanel.add(topPanel, BorderLayout.NORTH);
        
        // 左侧面板：规则管理
        JPanel leftPanel = createRuleManagementPanel();
        configPanel.add(leftPanel, BorderLayout.WEST);
        
        // 中央面板：指纹列表
        JPanel centerPanel = createFingerprintListPanel();
        configPanel.add(centerPanel, BorderLayout.CENTER);
        
        // 初始化统计信息
        updateStatistics();
        refreshFingerprintTable();
    }
    
    /**
     * 创建控制按钮面板（移除启用禁用按钮）
     */
    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createTitledBorder("控制"));
        
        // 清除缓存按钮
        clearCacheButton = new JButton("清除缓存");
        clearCacheButton.addActionListener(e -> clearCache());
        
        panel.add(clearCacheButton);
        
        // 统计信息标签
        statisticsLabel = new JLabel("指纹库: 0, 已识别: 0");
        panel.add(statisticsLabel);
        
        return panel;
    }
    
    /**
     * 创建规则管理面板
     */
    private JPanel createRuleManagementPanel() {
        JPanel panel = new JPanel();
        panel.setPreferredSize(new Dimension(200, 0));
        panel.setBorder(BorderFactory.createTitledBorder("规则管理"));
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        
        // 创建按钮面板，使用垂直布局
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
        
        // Add按钮
        JButton addButton = new JButton("Add");
        addButton.setPreferredSize(new Dimension(80, 30));
        addButton.setMaximumSize(new Dimension(80, 30));
        addButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        addButton.addActionListener(e -> showAddFingerprintDialog());
        
        // Edit按钮
        JButton editButton = new JButton("Edit");
        editButton.setPreferredSize(new Dimension(80, 30));
        editButton.setMaximumSize(new Dimension(80, 30));
        editButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        editButton.addActionListener(e -> showEditFingerprintDialog());
        
        // Del按钮
        JButton delButton = new JButton("Del");
        delButton.setPreferredSize(new Dimension(80, 30));
        delButton.setMaximumSize(new Dimension(80, 30));
        delButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        delButton.addActionListener(e -> deleteSelectedFingerprint());
        
        // 垂直排列按钮，每个按钮之间有间距
        buttonPanel.add(addButton);
        buttonPanel.add(Box.createVerticalStrut(8)); // 8像素间距
        buttonPanel.add(editButton);
        buttonPanel.add(Box.createVerticalStrut(8)); // 8像素间距
        buttonPanel.add(delButton);
        
        panel.add(buttonPanel);
        
        // 添加一些说明文本
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setBorder(BorderFactory.createTitledBorder("操作说明"));
        
        JLabel info1 = new JLabel("• Add: 添加新指纹规则");
        JLabel info2 = new JLabel("• Edit: 编辑选中的规则");
        JLabel info3 = new JLabel("• Del: 删除选中的规则");
        
        info1.setFont(info1.getFont().deriveFont(12f));
        info2.setFont(info2.getFont().deriveFont(12f));
        info3.setFont(info3.getFont().deriveFont(12f));
        
        infoPanel.add(info1);
        infoPanel.add(Box.createVerticalStrut(5));
        infoPanel.add(info2);
        infoPanel.add(Box.createVerticalStrut(5));
        infoPanel.add(info3);
        
        panel.add(Box.createVerticalStrut(15)); // 按钮和说明之间的间距
        panel.add(infoPanel);
        panel.add(Box.createVerticalGlue()); // 底部填充
        
        return panel;
    }
    
    /**
     * 创建指纹列表面板
     */
    private JPanel createFingerprintListPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("指纹列表"));
        
        // 创建表格模型
        String[] columnNames = {"CMS", "方法", "位置", "关键词", "状态码"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        // 创建表格
        fingerprintTable = new JTable(tableModel);
        fingerprintTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // 设置表格列宽
        if (fingerprintTable.getColumnModel().getColumnCount() >= 5) {
            fingerprintTable.getColumnModel().getColumn(0).setPreferredWidth(120);  // CMS
            fingerprintTable.getColumnModel().getColumn(1).setPreferredWidth(80);   // 方法
            fingerprintTable.getColumnModel().getColumn(2).setPreferredWidth(80);   // 位置
            fingerprintTable.getColumnModel().getColumn(3).setPreferredWidth(200);  // 关键词
            fingerprintTable.getColumnModel().getColumn(4).setPreferredWidth(60);   // 状态码
        }
        
        // 添加搜索功能
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField searchField = new JTextField(20);
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                String text = searchField.getText().toLowerCase();
                TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
                sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
                fingerprintTable.setRowSorter(sorter);
            }
        });
        searchPanel.add(new JLabel("搜索: "));
        searchPanel.add(searchField);
        
        panel.add(searchPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(fingerprintTable), BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 加载规则
     */
    private void loadRules() {
        try {
            String path = rulePathField.getText().trim();
            scanner.loadFingerprintsFromFile(path);
            refreshFingerprintTable();
            JOptionPane.showMessageDialog(configPanel, 
                "规则加载成功！\n" + scanner.getStatistics(),
                "加载成功", 
                JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(configPanel, 
                "规则加载失败: " + e.getMessage(),
                "加载失败", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 更新规则
     */
    private void updateRules() {
        try {
            scanner.updateFingerprintsFromOnline();
            refreshFingerprintTable();
            JOptionPane.showMessageDialog(configPanel, 
                "规则更新成功！\n" + scanner.getStatistics(),
                "更新成功", 
                JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(configPanel, 
                "规则更新失败: " + e.getMessage(),
                "更新失败", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 删除选中的指纹
     */
    private void deleteSelectedFingerprint() {
        int selectedRow = fingerprintTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(configPanel,
                "请先选择要删除的指纹规则",
                "未选择规则",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // 确认删除
        int result = JOptionPane.showConfirmDialog(configPanel,
            "确定要删除选中的指纹规则吗？",
            "确认删除",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE);
            
        if (result == JOptionPane.YES_OPTION) {
            int modelRow = fingerprintTable.convertRowIndexToModel(selectedRow);
            scanner.deleteFingerprint(modelRow);
            refreshFingerprintTable();
            JOptionPane.showMessageDialog(configPanel, 
                "指纹规则删除成功！",
                "删除成功", 
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 刷新指纹表格
     */
    private void refreshFingerprintTable() {
        tableModel.setRowCount(0);
        List<FingerPrint> fingerprints = scanner.getFingerprints();
        for (FingerPrint fp : fingerprints) {
            tableModel.addRow(new Object[]{
                fp.getCms(),
                fp.getMethod(),
                fp.getLocation(),
                String.join(",", fp.getKeyword()),
                fp.getStatus()
            });
        }
    }
    
    /**
     * 清除缓存
     */
    private void clearCache() {
        scanner.clearCache();
        updateStatistics();
        JOptionPane.showMessageDialog(configPanel, 
            "指纹识别缓存已清除",
            "缓存清除", 
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * 更新统计信息显示
     */
    private void updateStatistics() {
        statisticsLabel.setText(scanner.getStatistics());
    }
    
    /**
     * 获取配置面板
     */
    public JPanel getConfigPanel() {
        return configPanel;
    }
    
    /**
     * 定时更新统计信息
     */
    public void refreshStatistics() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                updateStatistics();
            }
        });
    }

    /**
     * 显示添加指纹对话框
     */
    private void showAddFingerprintDialog() {
        FingerprintDialog dialog = new FingerprintDialog(
            SwingUtilities.getWindowAncestor(configPanel),
            "添加指纹规则",
            null  // 新增时传入null
        );
        
        dialog.setVisible(true);
        
        if (dialog.isConfirmed()) {
            FingerPrint newFingerprint = dialog.getFingerprint();
            if (newFingerprint != null) {
                scanner.addFingerprint(newFingerprint);
                refreshFingerprintTable();
                JOptionPane.showMessageDialog(configPanel, 
                    "指纹规则添加成功！",
                    "添加成功", 
                    JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }
    
    /**
     * 显示编辑指纹对话框
     */
    private void showEditFingerprintDialog() {
        int selectedRow = fingerprintTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(configPanel,
                "请先选择要编辑的指纹规则",
                "未选择规则",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // 转换为模型索引
        int modelRow = fingerprintTable.convertRowIndexToModel(selectedRow);
        List<FingerPrint> fingerprints = scanner.getFingerprints();
        
        if (modelRow >= 0 && modelRow < fingerprints.size()) {
            FingerPrint selectedFingerprint = fingerprints.get(modelRow);
            
            FingerprintDialog dialog = new FingerprintDialog(
                SwingUtilities.getWindowAncestor(configPanel),
                "编辑指纹规则",
                selectedFingerprint  // 编辑时传入现有指纹
            );
            
            dialog.setVisible(true);
            
            if (dialog.isConfirmed()) {
                FingerPrint editedFingerprint = dialog.getFingerprint();
                if (editedFingerprint != null) {
                    // 删除旧的，添加新的（简单的编辑实现）
                    scanner.deleteFingerprint(modelRow);
                    scanner.addFingerprint(editedFingerprint);
                    refreshFingerprintTable();
                    JOptionPane.showMessageDialog(configPanel, 
                        "指纹规则编辑成功！",
                        "编辑成功", 
                        JOptionPane.INFORMATION_MESSAGE);
                }
            }
        }
    }
    
    /**
     * 指纹规则编辑对话框
     */
    private static class FingerprintDialog extends JDialog {
        private JTextField cmsField;
        private JTextField methodField;
        private JTextField locationField;
        private JTextArea keywordArea;
        private JTextField statusField;
        private boolean confirmed = false;
        
        public FingerprintDialog(Window parent, String title, FingerPrint existingFingerprint) {
            super(parent, title, ModalityType.APPLICATION_MODAL);
            initComponents(existingFingerprint);
            setupLayout();
            pack();
            setLocationRelativeTo(parent);
        }
        
        private void initComponents(FingerPrint existing) {
            cmsField = new JTextField(20);
            methodField = new JTextField(20);
            locationField = new JTextField(20);
            keywordArea = new JTextArea(4, 20);
            keywordArea.setLineWrap(true);
            keywordArea.setWrapStyleWord(true);
            statusField = new JTextField("200", 20);
            
            // 如果是编辑模式，填充现有数据
            if (existing != null) {
                cmsField.setText(existing.getCms());
                methodField.setText(existing.getMethod());
                locationField.setText(existing.getLocation());
                keywordArea.setText(String.join(",", existing.getKeyword()));
                statusField.setText(String.valueOf(existing.getStatus()));
            }
        }
        
        private void setupLayout() {
            setLayout(new BorderLayout());
            
            // 主面板
            JPanel mainPanel = new JPanel(new GridBagLayout());
            mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
            
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(5, 5, 5, 5);
            gbc.anchor = GridBagConstraints.WEST;
            
            // CMS名称
            gbc.gridx = 0; gbc.gridy = 0;
            mainPanel.add(new JLabel("CMS名称:"), gbc);
            gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
            mainPanel.add(cmsField, gbc);
            
            // 匹配方法
            gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
            mainPanel.add(new JLabel("匹配方法:"), gbc);
            gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
            mainPanel.add(methodField, gbc);
            
            // 匹配位置
            gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
            mainPanel.add(new JLabel("匹配位置:"), gbc);
            gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
            mainPanel.add(locationField, gbc);
            
            // 关键词
            gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
            mainPanel.add(new JLabel("关键词:"), gbc);
            gbc.gridx = 1; gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 1.0;
            mainPanel.add(new JScrollPane(keywordArea), gbc);
            
            // 状态码
            gbc.gridx = 0; gbc.gridy = 4; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0; gbc.weighty = 0;
            mainPanel.add(new JLabel("状态码:"), gbc);
            gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
            mainPanel.add(statusField, gbc);
            
            add(mainPanel, BorderLayout.CENTER);
            
            // 按钮面板
            JPanel buttonPanel = new JPanel(new FlowLayout());
            JButton okButton = new JButton("确定");
            JButton cancelButton = new JButton("取消");
            
            okButton.addActionListener(e -> {
                if (validateInput()) {
                    confirmed = true;
                    dispose();
                }
            });
            
            cancelButton.addActionListener(e -> {
                confirmed = false;
                dispose();
            });
            
            buttonPanel.add(okButton);
            buttonPanel.add(cancelButton);
            add(buttonPanel, BorderLayout.SOUTH);
        }
        
        private boolean validateInput() {
            if (cmsField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "CMS名称不能为空", "输入错误", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            if (methodField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "匹配方法不能为空", "输入错误", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            if (locationField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "匹配位置不能为空", "输入错误", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            if (keywordArea.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "关键词不能为空", "输入错误", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            
            try {
                Integer.parseInt(statusField.getText().trim());
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(this, "状态码必须是数字", "输入错误", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            
            return true;
        }
        
        public boolean isConfirmed() {
            return confirmed;
        }
        
        public FingerPrint getFingerprint() {
            if (!confirmed) return null;
            
            String cms = cmsField.getText().trim();
            String method = methodField.getText().trim();
            String location = locationField.getText().trim();
            String keywordText = keywordArea.getText().trim();
            int status = Integer.parseInt(statusField.getText().trim());
            
            // 处理关键词列表
            List<String> keywords = Arrays.asList(keywordText.split(","));
            for (int i = 0; i < keywords.size(); i++) {
                keywords.set(i, keywords.get(i).trim());
            }
            
            return new FingerPrint(cms, method, location, keywords, status);
        }
    }
}