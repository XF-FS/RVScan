/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JToolBar;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.BorderFactory;
import javax.swing.border.Border;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import burp.BurpExtender;
import java.nio.charset.StandardCharsets;
import APIKit.BurpExtenderAdapter;

public class ConfigPanel
        extends JPanel {
    JButton autoSendRequestButton = new JButton("Auto Request: OFF");
    JButton includeCookieButton = new JButton("Cookie: OFF");
    private boolean autoSendRequestEnabled = false;
    private boolean includeCookieEnabled = false;
    private boolean scannerEnabled = false; // 由Start/Stop按钮控制
    JButton clearHistoryButton = new JButton("Clear history");
    JButton Button_one = new JButton("Start");
    
    // 新增的输入框
    JTextField filterHostField = new JTextField("*", 15);
    JTextField filterPathField = new JTextField("/add,/delet,/logout", 15);
    
    private Color Primary; // 默认颜色（从按钮获取）
    private Object burp; // 需要引用burp对象

    public ConfigPanel() {
        // 获取默认按钮颜色
        Primary = this.Button_one.getBackground();
        
        // 设置按钮边框和样式
        setupButtonStyle(this.Button_one);
        setupButtonStyle(this.autoSendRequestButton);
        setupButtonStyle(this.includeCookieButton);
        setupButtonStyle(this.clearHistoryButton);
        
        // 设置布局 - 所有元素放在同一行
        this.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        
        // 按钮顺序：Start, Auto Request, Cookie
        this.add(this.Button_one);
        this.add(this.autoSendRequestButton);
        this.add(this.includeCookieButton);
        
        // 添加分隔符
        this.add(Box.createHorizontalStrut(15));
        
        // 添加过滤器输入框
        this.add(new JLabel("Filter Host:"));
        this.add(filterHostField);
        this.add(Box.createHorizontalStrut(10));
        this.add(new JLabel("Filter Path:"));
        this.add(filterPathField);
        
        // 添加弹性空间，将Clear history推到右侧
        this.add(Box.createHorizontalGlue());
        this.add(this.clearHistoryButton);
        
        // 为输入框添加文档监听器，当配置变化时输出日志
        addFilterConfigListener();
        
        // Auto Request按钮事件监听器
        this.autoSendRequestButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (autoSendRequestEnabled) {
                    autoSendRequestEnabled = false;
                    autoSendRequestButton.setText("Auto Request: OFF");
                    autoSendRequestButton.setBackground(Primary);
                    autoSendRequestButton.setBorder(new RoundedBorder(8));
                } else {
                    autoSendRequestEnabled = true;
                    autoSendRequestButton.setText("Auto Request: ON");
                    autoSendRequestButton.setBackground(Color.green);
                    autoSendRequestButton.setBorder(new RoundedBorder(8));
                }
            }
        });
        
        // Cookie按钮事件监听器
        this.includeCookieButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (includeCookieEnabled) {
                    includeCookieEnabled = false;
                    includeCookieButton.setText("Cookie: OFF");
                    includeCookieButton.setBackground(Primary);
                    includeCookieButton.setBorder(new RoundedBorder(8));
                } else {
                    includeCookieEnabled = true;
                    includeCookieButton.setText("Cookie: ON");
                    includeCookieButton.setBackground(Color.green);
                    includeCookieButton.setBorder(new RoundedBorder(8));
                }
            }
        });
        
        // Start/Stop按钮事件监听器 - 控制被动扫描（参考Config.java的on_off_Button_action）
        this.Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (scannerEnabled) {
                    scannerEnabled = false;
                    Button_one.setText("Start");
                    Button_one.setBackground(Primary);
                    Button_one.setBorder(new RoundedBorder(8));
                    setBurpOnOffStatus(false);
                } else {
                    scannerEnabled = true;
                    Button_one.setText("Stop");
                    Button_one.setBackground(Color.green);
                    Button_one.setBorder(new RoundedBorder(8));
                    setBurpOnOffStatus(true);
                }
            }
        });
    }

    public Boolean getAutoSendRequest() {
        return this.autoSendRequestEnabled;
    }

    public Boolean getIncludeCookie() {
        return this.includeCookieEnabled;
    }

    public Boolean getScannerEnabled() {
        return this.scannerEnabled;
    }
    
    // 获取Filter Host值
    public String getFilterHost() {
        return this.filterHostField.getText().trim();
    }
    
    // 获取Filter Path值
    public String getFilterPath() {
        return this.filterPathField.getText().trim();
    }
    
    // 检查主机是否应该被过滤
    public boolean shouldFilterHost(String host) {
        String filterHost = getFilterHost();
        if (filterHost.isEmpty() || "*".equals(filterHost)) {
            return false; // 不过滤
        }
        
        String[] hosts = filterHost.split(",");
        for (String h : hosts) {
            h = h.trim();
            if (h.isEmpty()) continue;
            if (host.contains(h)) {
                return false; // 匹配到允许的主机，不过滤
            }
        }
        return true; // 过滤掉
    }
    
    // 检查路径是否应该被过滤（不发送请求）
    public boolean shouldFilterPath(String path) {
        String filterPath = getFilterPath();
        if (filterPath.isEmpty()) {
            return false; // 不过滤
        }
        
        // 移除 URL 中的协议和域名部分
        path = path.replaceFirst("^https?://[^/]+", "");
        
        // 移除查询参数
        int queryIndex = path.indexOf('?');
        if (queryIndex != -1) {
            path = path.substring(0, queryIndex);
        }
        
        // 确保路径以 '/' 开头
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        
        String[] paths = filterPath.split(",");
        for (String p : paths) {
            p = p.trim();
            // 移除可能的单引号或双引号
            if (p.startsWith("'") && p.endsWith("'")) {
                p = p.substring(1, p.length() - 1);
            }
            if (p.startsWith("\"") && p.endsWith("\"")) {
                p = p.substring(1, p.length() - 1);
            }
            if (p.isEmpty()) continue;
            
            // 调试输出
            System.out.println("[Filter Debug] Comparing path '" + path + "' with filter '" + p + "'");
            
            // 精确匹配和包含匹配
            if (path.equals(p) || path.contains(p)) {
                System.out.println("[Filter Debug] Match found! Filtering path: " + path);
                return true; // 匹配到过滤路径，需要过滤
            }
        }
        return false; // 不过滤
    }

    // 为被过滤的路径生成一个模拟响应
    public byte[] generateFilteredPathResponse(String path) {
        String responseBody = "Filter Path list Dont sed to Reques";
        String response = "HTTP/1.1 403 Forbidden\r\n" +
                          "Content-Type: text/plain\r\n" +
                          "Content-Length: " + responseBody.length() + "\r\n" +
                          "\r\n" +
                          responseBody;
        return response.getBytes(StandardCharsets.UTF_8);
    }

    public void addClearHistoryCallback(Runnable callback) {
        this.clearHistoryButton.addActionListener(actionEvent -> callback.run());
    }
    
    // 设置burp对象引用
    public void setBurpReference(Object burpInstance) {
        this.burp = burpInstance;
    }
    
    // 获取burp的on_off状态的方法（需要根据实际burp对象的结构调整）
    private boolean getBurpOnOffStatus() {
        // 这里需要根据实际的burp对象结构来获取on_off字段
        // 示例：return ((YourBurpClass) burp).on_off;
        return this.scannerEnabled; // 返回当前扫描器状态
    }
    
    // 设置burp的on_off状态的方法
    private void setBurpOnOffStatus(boolean status) {
        // 输出扫描器状态变化的日志
        BurpExtenderAdapter.getStdout().println("[Scanner Status] " + (status ? "Enabled" : "Disabled"));
        
        // 如果需要，可以在这里添加其他状态切换的逻辑
        // 例如：通知其他组件扫描器状态已改变
    }
    
    // 设置按钮样式的辅助方法
    private void setupButtonStyle(JButton button) {
        button.setBorder(new RoundedBorder(8)); // 使用圆角边框
        button.setOpaque(true);
        button.setFocusPainted(false); // 去除焦点边框
        button.setContentAreaFilled(true); // 确保背景填充
    }
    
    // 圆角边框类
    private static class RoundedBorder implements Border {
        private int radius;
        
        public RoundedBorder(int radius) {
            this.radius = radius;
        }
        
        @Override
        public Insets getBorderInsets(Component c) {
            return new Insets(2, 8, 2, 8); // 上下2像素，左右8像素的内边距
        }
        
        @Override
        public boolean isBorderOpaque() {
            return false;
        }
        
        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Graphics2D g2d = (Graphics2D) g.create();
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2d.setColor(Color.GRAY);
            g2d.drawRoundRect(x, y, width - 1, height - 1, radius, radius);
            g2d.dispose();
        }
    }
    
    // 添加过滤器配置监听器
    private void addFilterConfigListener() {
        DocumentListener configChangeListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                logFilterConfig();
            }
            
            @Override
            public void removeUpdate(DocumentEvent e) {
                logFilterConfig();
            }
            
            @Override
            public void changedUpdate(DocumentEvent e) {
                logFilterConfig();
            }
        };
        
        filterHostField.getDocument().addDocumentListener(configChangeListener);
        filterPathField.getDocument().addDocumentListener(configChangeListener);
    }
    
    // 输出过滤器配置日志
    private void logFilterConfig() {
        String filterHost = getFilterHost();
        String filterPath = getFilterPath();
        BurpExtenderAdapter.getStdout().println("[Filter Config Updated] Host: '" + filterHost + "', Path: '" + filterPath + "'");
    }
}

