package burp;


import yaml.YamlUtil;
import fingerprint.FingerprintConfig;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Config {
    private JPanel one;
    private JTextField txtfield1;
    public String yaml_path = BurpExtender.Yaml_Path;
    public JSpinner spinner1;
    private BurpExtender burp;
    public JTabbedPane ruleTabbedPane;
    public TabTitleEditListener ruleSwitch;
    protected static JPopupMenu tabMenu = new JPopupMenu();
    private JMenuItem closeTabMenuItem = new JMenuItem("Delete");
    private static int RulesInt = 0;

    public static String new_Rules() {
        RulesInt += 1;
        return "New " + RulesInt;
    }


    public void newTab() {
        Object[][] data = new Object[][]{{false, "New Name", "(New Regex)", "gray", "any", "nfa", false}};
        insertTab(ruleTabbedPane, Config.new_Rules(), data);
    }

    public void insertTab(JTabbedPane pane, String title, Object[][] data) {
        pane.addTab(title, new JLabel());
        pane.remove(pane.getSelectedIndex());
        pane.addTab("...", new JLabel());
    }

    public void closeTabActionPerformed(ActionEvent e) {

        if (ruleTabbedPane.getTabCount() > 2) {
            Dialog frame = new JDialog();//构造一个新的JFrame，作为新窗口。
            frame.setBounds(
                    new Rectangle(
                            // 让新窗口与SwingTest窗口示例错开50像素。
                            620,
                            300,
                            // 窗口总大小-500像素
                            200,
                            100
                    )
            );


            JPanel xin = new JPanel();
            xin.setLayout(null);

            JLabel Tips = new JLabel("Are you sure you want to delete");
            Tips.setBounds(20, 10, 200, 20);
            xin.add(Tips);

            // Ok
            JButton Ok_button = new JButton("Yes");
            Ok_button.setBounds(120, 40, 60, 20);
            xin.add(Ok_button);
            Ok_button.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String type = ruleTabbedPane.getTitleAt(ruleTabbedPane.getSelectedIndex());
                    View Remove_view = burp.views.get(type);
                    if (Remove_view != null) {
                        for (View.LogEntry l : Remove_view.log) {
                            YamlUtil.removeYaml(l.id, BurpExtender.Yaml_Path);
                        }
                    }
                    ruleTabbedPane.remove(ruleTabbedPane.getSelectedIndex());
                    frame.dispose();

                }
            });

            // no
            JButton No_button = new JButton("NO");
            No_button.setBounds(30, 40, 60, 20);
            xin.add(No_button);
            No_button.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    frame.dispose();

                }
            });


            ((JDialog) frame).getContentPane().add(xin);
            frame.setModalityType(Dialog.ModalityType.APPLICATION_MODAL);    // 设置模式类型。
            frame.setVisible(true);


        }
    }

    public Config(BurpExtender burp) {
        this.burp = burp;
        tabMenu.add(closeTabMenuItem);
        closeTabMenuItem.addActionListener(e -> closeTabActionPerformed(e));
    }
    
    /**
     * 创建指纹识别配置面板
     */
    private JPanel createFingerprintPanel() {
        if (burp.fingerprintConfig != null) {
            return burp.fingerprintConfig.getConfigPanel();
        }
        return new JPanel(); // 返回空面板作为备选
    }

    /**
     * 使用布局管理器设置UI界面
     */
    private void $$$setupUI$$$() {
        one = new JPanel(new BorderLayout());
        
        // 创建顶部控制面板
        JPanel topPanel = createTopControlPanel();
        
        // 创建中间配置面板
        JPanel middlePanel = createMiddleConfigPanel();
        
        // 创建规则面板
        JPanel rulePanel = createRulePanel();
        
        // 创建指纹识别配置面板
        JPanel fingerprintPanel = createFingerprintPanel();
        
        // 创建北部面板，包含控制面板和配置面板
        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.add(topPanel, BorderLayout.NORTH);
        northPanel.add(middlePanel, BorderLayout.CENTER);
        
        // 创建路径管理面板
        PathManager pathManager = new PathManager(burp);
        JPanel pathPanel = pathManager.getMainPanel();
        
        // 创建中央面板，包含规则面板、指纹识别面板和路径管理面板
        JTabbedPane centralTabbedPane = new JTabbedPane();
        centralTabbedPane.addTab("规则配置", rulePanel);
        centralTabbedPane.addTab("指纹识别", fingerprintPanel);
        centralTabbedPane.addTab("路径管理", pathPanel);
        
        // 组装主面板
        one.add(northPanel, BorderLayout.NORTH);   // 北部包含控制和配置面板
        one.add(centralTabbedPane, BorderLayout.CENTER);   // 中央区域使用选项卡面板
    }

    /**
     * 创建顶部控制按钮面板
     */
    private JPanel createTopControlPanel() {
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        topPanel.setBorder(BorderFactory.createTitledBorder("Control Panel"));
        
        // 开关按钮
        JButton onOffButton = new JButton("Stop");
        Color primaryColor = onOffButton.getBackground();
        on_off_Button_action(onOffButton, primaryColor);
        
        // 携带头部按钮
        JButton carryHeadButton = new JButton("Head_On");
        carry_head_Button_action(carryHeadButton, primaryColor);
        
        // 域名扫描按钮
        JButton domainScanButton = new JButton("DomainScan_On");
        DomainScan_Button_action(domainScanButton, domainScanButton.getBackground());
        
        // 绕过按钮
        JButton bypassButton = new JButton("Bypass_On");
        bypass_Button_action(bypassButton, bypassButton.getBackground());
        
        // 前缀绕过按钮
        JButton bypassFirstButton = new JButton("Bypass_First_On");
        bypass_first_button_action(bypassFirstButton, bypassFirstButton.getBackground());
        
        // 后缀绕过按钮
        JButton bypassEndButton = new JButton("Bypass_End_On");
        bypass_end_button_action(bypassEndButton, bypassEndButton.getBackground());
        
        // EHole指纹扫描按钮 - 初始状态设置为启用状态
        JButton fingerprintButton = new JButton("EHole_Off");
        fingerprintButton.setBackground(Color.green);
        fingerprint_button_action(fingerprintButton, primaryColor);
        
        // 线程池状态按钮
        JButton threadStatusButton = new JButton("Thread Status");
        thread_status_button_action(threadStatusButton);
        
        // 速率限制开关按钮
        JButton rateLimitButton = new JButton("RateLimit_On");
        rateLimitButton.setBackground(Color.GREEN);
        rate_limit_button_action(rateLimitButton, primaryColor);
        
        // 添加所有按钮到面板
        topPanel.add(onOffButton);
        topPanel.add(carryHeadButton);
        topPanel.add(domainScanButton);
        topPanel.add(bypassButton);
        topPanel.add(bypassFirstButton);
        topPanel.add(bypassEndButton);
        topPanel.add(fingerprintButton);
        topPanel.add(threadStatusButton);
        topPanel.add(rateLimitButton);
        
        return topPanel;
    }
    
    /**
     * EHole指纹扫描按钮动作
     */
    private void fingerprint_button_action(JButton button, Color primary) {
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.fingerprintScanner != null) {
                    boolean currentState = burp.fingerprintScanner.isEnabled();
                    burp.fingerprintScanner.setEnabled(!currentState);
                    
                    // 更新按钮状态
                    if (currentState) {
                        // 当前是启用状态，点击后变为禁用
                        button.setText("EHole_On");
                        button.setBackground(primary);  // 默认颜色表示禁用
                    } else {
                        // 当前是禁用状态，点击后变为启用
                        button.setText("EHole_Off");
                        button.setBackground(Color.green);  // 绿色表示启用
                    }
                }
            }
        });
    }

    /**
     * 创建中间配置面板
     */
    private JPanel createMiddleConfigPanel() {
        JPanel middlePanel = new JPanel();
        middlePanel.setLayout(new BoxLayout(middlePanel, BoxLayout.Y_AXIS));
        
        // YAML路径配置面板
        JPanel yamlPanel = createYamlConfigPanel();
        yamlPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, yamlPanel.getPreferredSize().height));
        
        // 线程和过滤器配置面板
        JPanel configPanel = createThreadAndFilterPanel();
        
        middlePanel.add(yamlPanel);
        middlePanel.add(Box.createVerticalStrut(5)); // 间距
        middlePanel.add(configPanel);
        middlePanel.add(Box.createVerticalGlue()); // 底部填充，防止拉伸
        
        return middlePanel;
    }

    /**
     * 创建YAML配置面板
     */
    private JPanel createYamlConfigPanel() {
        JPanel yamlPanel = new JPanel(new BorderLayout(5, 5));
        yamlPanel.setBorder(BorderFactory.createTitledBorder("YAML Configuration"));
        
        // 左侧标签
        JLabel yamlLabel = new JLabel("Yaml File Path:");
        
        // 中间文本框
        txtfield1 = new JTextField(yaml_path);
        txtfield1.setEditable(false);
        
        // 右侧按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        // 暂时不使用更新功能
        //JButton updateButton = new JButton("Update");
        JButton loadButton = new JButton("Load Yaml");
        
        //Online_Update_Yaml(updateButton);
        load_button_Yaml(loadButton);
        
        //buttonPanel.add(updateButton);
        buttonPanel.add(loadButton);
        
        yamlPanel.add(yamlLabel, BorderLayout.WEST);
        yamlPanel.add(txtfield1, BorderLayout.CENTER);
        yamlPanel.add(buttonPanel, BorderLayout.EAST);
        
        return yamlPanel;
    }

    /**
     * 创建线程和过滤器配置面板
     */
    private JPanel createThreadAndFilterPanel() {
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("Thread & Filter Configuration"));
        
        // 设置面板的首选高度，避免过度拉伸
        configPanel.setPreferredSize(new Dimension(0, 120));
        configPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 120));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // 线程数配置
        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("Thread Numbers:"), gbc);
        
        SpinnerNumberModel model = new SpinnerNumberModel(10, 1, 500, 3);
        spinner1 = new JSpinner(model);
        ((JSpinner.DefaultEditor) spinner1.getEditor()).getTextField().setEditable(false);
        gbc.gridx = 1;
        configPanel.add(spinner1, gbc);
        
        // 速率限制配置
        gbc.gridx = 2;
        configPanel.add(new JLabel("Rate Limit (req/s):"), gbc);
        
        SpinnerNumberModel rateLimitModel = new SpinnerNumberModel(20, 1, 100, 1);
        JSpinner rateLimitSpinner = new JSpinner(rateLimitModel);
        ((JSpinner.DefaultEditor) rateLimitSpinner.getEditor()).getTextField().setEditable(false);
        
        // 添加速率限制变更监听器
        rateLimitSpinner.addChangeListener(e -> {
            int rateLimit = (Integer) rateLimitSpinner.getValue();
            if (burp.threadPoolManager != null) {
                burp.threadPoolManager.setRateLimit(rateLimit);
                burp.call.printOutput("[RateLimit] 速率限制已设置为每秒 " + rateLimit + " 个请求");
            }
        });
        
        gbc.gridx = 3;
        configPanel.add(rateLimitSpinner, gbc);
        
        // 主机过滤配置（移到第二行）
        gbc.gridx = 0; gbc.gridy = 1;
        configPanel.add(new JLabel("Filter Host:"), gbc);
        
        JTextField hostTextField = new JTextField("*", 20);
        burp.Host_txtfield = hostTextField;
        gbc.gridx = 1;
        gbc.gridwidth = 3; // 跨3列
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        configPanel.add(hostTextField, gbc);
        
        // 重置gridwidth
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        
        return configPanel;
    }



    /**
     * 创建规则面板
     */
    private JPanel createRulePanel() {
        JPanel rulePanel = new JPanel(new BorderLayout());
        rulePanel.setBorder(BorderFactory.createTitledBorder("Rules"));
        
        // 创建左侧操作按钮面板
        JPanel leftButtonPanel = createRuleOperationPanel();
        
        // 创建规则标签页
        ruleTabbedPane = new JTabbedPane();
        ruleSwitch = new TabTitleEditListener(ruleTabbedPane, burp);
        ruleTabbedPane.addMouseListener(ruleSwitch);
        
        Bfunc.show_yaml(burp);
        
        // 将按钮面板放在左侧，规则标签页放在中央
        rulePanel.add(leftButtonPanel, BorderLayout.WEST);
        rulePanel.add(ruleTabbedPane, BorderLayout.CENTER);
        
        return rulePanel;
    }

    /**
     * 创建规则操作按钮面板（垂直排列）
     */
    private JPanel createRuleOperationPanel() {
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
        buttonPanel.setBorder(BorderFactory.createTitledBorder("Operations"));
        
        // 创建按钮
        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton delButton = new JButton("Del");
        
        // 设置按钮大小一致
        Dimension buttonSize = new Dimension(80, 30);
        addButton.setPreferredSize(buttonSize);
        addButton.setMaximumSize(buttonSize);
        editButton.setPreferredSize(buttonSize);
        editButton.setMaximumSize(buttonSize);
        delButton.setPreferredSize(buttonSize);
        delButton.setMaximumSize(buttonSize);
        
        // 绑定事件
        Add_Button_Yaml(addButton, yaml_path);
        Edit_Button_Yaml(editButton, yaml_path);
        Del_Button_Yaml(delButton, yaml_path);
        
        // 添加按钮到面板，垂直排列
        buttonPanel.add(Box.createVerticalStrut(10)); // 顶部间距
        buttonPanel.add(addButton);
        buttonPanel.add(Box.createVerticalStrut(5));  // 按钮间距
        buttonPanel.add(editButton);
        buttonPanel.add(Box.createVerticalStrut(5));  // 按钮间距
        buttonPanel.add(delButton);
        buttonPanel.add(Box.createVerticalGlue());    // 底部填充
        
        return buttonPanel;
    }

    private void carry_head_Button_action(JButton Button_one, Color Primary) {

        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.Carry_head) {
                    burp.Carry_head = false;
                    Button_one.setText("Head_On");
                    Button_one.setBackground(Primary);
                } else {
                    burp.Carry_head = true;
                    Button_one.setText("Head_Off");
                    Button_one.setBackground(Color.green);
                }

            }
        });
    }


    private void on_off_Button_action(JButton Button_one, Color Primary) {

        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.on_off) {
                    burp.on_off = false;
                    Button_one.setText("Start");
                    Button_one.setBackground(Primary);
                } else {
                    burp.on_off = true;
                    Button_one.setText("Stop");
                    Button_one.setBackground(Color.green);
                }

            }
        });
    }


    private void bypass_Button_action(JButton Button_one, Color Primary) {

        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.Bypass) {
                    burp.Bypass = false;
                    Button_one.setText("Bypass_On");
                    Button_one.setBackground(Primary);
                } else {
                    burp.Bypass = true;
                    Button_one.setText("Bypass_Off");
                    Button_one.setBackground(Color.green);
                }

            }
        });
    }

    private void bypass_first_button_action(final JButton button, final Color primary) {
        button.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                if (Config.this.burp.BypassFirst) {
                    Config.this.burp.BypassFirst = false;
                    button.setText("Bypass_First_On");
                    button.setBackground(primary);
                } else {
                    Config.this.burp.BypassFirst = true;
                    button.setText("Bypass_First_Off");
                    button.setBackground(Color.green);
                }
            }
        });
    }

    private void bypass_end_button_action(final JButton button, final Color primary) {
        button.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                if (Config.this.burp.BypassEnd) {
                    Config.this.burp.BypassEnd = false;
                    button.setText("Bypass_End_On");
                    button.setBackground(primary);
                } else {
                    Config.this.burp.BypassEnd = true;
                    button.setText("Bypass_End_Off");
                    button.setBackground(Color.green);
                }
            }
        });
    }

    private void DomainScan_Button_action(JButton Button_one, Color Primary) {

        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.DomainScan) {
                    burp.DomainScan = false;
                    Button_one.setText("DomainScan_On");
                    Button_one.setBackground(Primary);
                } else {
                    burp.DomainScan = true;
                    Button_one.setText("DomainScan_Off");
                    Button_one.setBackground(Color.green);
                }

            }
        });
    }

    private void thread_status_button_action(JButton Button_one) {
        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.threadPoolManager != null) {
                    String status = burp.threadPoolManager.getStatus();
                    String rateLimitStatus = burp.threadPoolManager.getRateLimitStatus();
                    
                    String fullStatus = status + "\n\n速率限制状态:\n" + rateLimitStatus;
                    
                    JOptionPane.showMessageDialog(Button_one, fullStatus, "线程池和速率限制状态", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(Button_one, "线程池未初始化", "线程池状态", JOptionPane.WARNING_MESSAGE);
                }
            }
        });
    }

    private void rate_limit_button_action(JButton Button_one, Color Primary) {
        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (burp.threadPoolManager != null) {
                    boolean currentState = burp.threadPoolManager.isRateLimitEnabled();
                    
                    // 切换速率限制状态
                    if (currentState) {
                        burp.threadPoolManager.disableRateLimit();
                    } else {
                        burp.threadPoolManager.enableRateLimit();
                    }
                    
                    // 更新按钮状态
                    if (currentState) {
                        // 当前是启用状态，点击后变为禁用
                        Button_one.setText("RateLimit_Off");
                        Button_one.setBackground(Primary);  // 默认颜色表示禁用
                        burp.call.printOutput("[RateLimit] 速率限制已禁用");
                    } else {
                        // 当前是禁用状态，点击后变为启用
                        Button_one.setText("RateLimit_On");
                        Button_one.setBackground(Color.GREEN);  // 绿色表示启用
                        burp.call.printOutput("[RateLimit] 速率限制已启用");
                    }
                }
            }
        });
    }


    private void Online_Update_Yaml(JButton Button_one) {

        Button_one.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                YamlUtil.init_Yaml(burp, one);
            }
        });
    }


     private void Edit_Button_Yaml(JButton Button_one, String yaml_path1) {
        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JDialog frame = new JDialog();//构造一个新的JFrame，作为新窗口。
                frame.setBounds(
                        new Rectangle(
                                // 让新窗口与SwingTest窗口示例错开50像素。
                                620,
                                300,
                                // 窗口总大小-500像素
                                300,
                                400  // 增加高度
                        )
                );
                String type = ruleTabbedPane.getTitleAt(ruleTabbedPane.getSelectedIndex());
                View view_class = burp.views.get(type);

                JPanel xin = new JPanel();
                xin.setLayout(null);
                // Name
                JLabel Name_field = new JLabel("Name :");
                JTextField Name_text = new JTextField();
                Name_text.setText(view_class.Choice.name);
                Name_field.setBounds(10, 5, 40, 20);
                Name_text.setBounds(65, 5, 200, 20);
                xin.add(Name_field);
                xin.add(Name_text);

                // Method
                JLabel Method_field = new JLabel("Method :");
//                JTextField Method_text = new JTextField();
                JComboBox Method_text = new JComboBox();    //创建JComboBox
                Method_text.addItem("GET");    //向下拉列表中添加一项
                Method_text.addItem("POST");    //向下拉列表中添加一项
                Method_text.setSelectedItem(view_class.Choice.method);
                Method_field.setBounds(10, 45, 40, 20);
                Method_text.setBounds(65, 45, 200, 20);
                xin.add(Method_field);
                xin.add(Method_text);

                // Url
                JLabel Url_field = new JLabel("Url :");
                JTextField Url_text = new JTextField();
                Url_text.setText(view_class.Choice.url);
                Url_field.setBounds(10, 85, 40, 20);
                Url_text.setBounds(65, 85, 200, 20);
                xin.add(Url_field);
                xin.add(Url_text);

                // Re
                JLabel Re_field = new JLabel("Re :");
                JTextField Re_text = new JTextField();
                Re_text.setText(view_class.Choice.re);
                Re_field.setBounds(10, 125, 40, 20);
                Re_text.setBounds(65, 125, 200, 20);
                xin.add(Re_field);
                xin.add(Re_text);

                // Info
                JLabel Info_field = new JLabel("Info :");
                JTextField Info_text = new JTextField();
                Info_text.setText(view_class.Choice.info);
                Info_field.setBounds(10, 165, 40, 20);
                Info_text.setBounds(65, 165, 200, 20);
                xin.add(Info_field);
                xin.add(Info_text);

                // state
                JLabel State_field = new JLabel("state :");
                JTextField State_text = new JTextField();
                State_text.setText(view_class.Choice.state);
                State_field.setBounds(10, 205, 40, 20);
                State_text.setBounds(65, 205, 200, 20);
                xin.add(State_field);
                xin.add(State_text);

                // Body（仅POST显示）
                JLabel Body_field = new JLabel("Body :");
                JTextArea Body_text = new JTextArea();  // 改为JTextArea
                Body_text.setText(view_class.Choice.body != null ? view_class.Choice.body : "");
                Body_text.setLineWrap(true);  // 启用自动换行
                Body_text.setWrapStyleWord(true);  // 按单词换行
                Body_field.setBounds(10, 245, 40, 20);

                // 创建带滚动条的JScrollPane
                JScrollPane scrollPane = new JScrollPane(Body_text);
                scrollPane.setBounds(65, 245, 200, 60);  // 设置滚动面板的位置和大小
                scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);  // 需要时显示垂直滚动条
                scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);  // 需要时显示水平滚动条

                xin.add(Body_field);
                xin.add(scrollPane);  // 添加滚动面板而不是直接添加文本区域
                Body_field.setVisible("POST".equals(view_class.Choice.method));
                scrollPane.setVisible("POST".equals(view_class.Choice.method));

                // 添加Method选择监听器来控制Body字段显示
                Method_text.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String method = (String) Method_text.getSelectedItem();
                        boolean isPost = "POST".equals(method);
                        Body_field.setVisible(isPost);
                        scrollPane.setVisible(isPost);  // 控制滚动面板的显示
                    }
                });

                // Ok
                JButton Ok_button = new JButton("OK");
                Ok_button.setBounds(200, 325, 60, 20);  // Y坐标改为325，确保在body字段下方
                xin.add(Ok_button);
                Ok_button.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String name = Name_text.getText();
                        String url = Url_text.getText();
                        String method = (String) Method_text.getSelectedItem();
                        String re = Re_text.getText();
                        String info = Info_text.getText();
                        String state = State_text.getText();
                        String body = Body_text.getText();  // 获取body字段内容
                        Map<String, Object> add_map = new HashMap<String, Object>();
                        add_map.put("id", Integer.parseInt(view_class.Choice.id));
                        add_map.put("type", type);
                        add_map.put("loaded", view_class.Choice.loaded);
                        add_map.put("name", name);
                        add_map.put("method", method);
                        add_map.put("url", url);
                        add_map.put("re", re);
                        add_map.put("info", info);
                        add_map.put("state", state);
                        add_map.put("body", body);  // 添加body字段到YAML
                        YamlUtil.updateYaml(add_map, yaml_path1);
                        Bfunc.show_yaml_view(burp, view_class, type);
                        frame.dispose();
                    }
                });

                // no - 修改Y坐标，让NO和OK在同一行
                JButton No_button = new JButton("NO");
                No_button.setBounds(130, 325, 60, 20);  // Y坐标改为325，与OK按钮一致
                xin.add(No_button);
                No_button.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        frame.dispose();
                    }
                });


                frame.getContentPane().add(xin);
                frame.setModalityType(Dialog.ModalityType.APPLICATION_MODAL);    // 设置模式类型。
                frame.setVisible(true);

            }
        });

    }


    private void Del_Button_Yaml(JButton Button_one, String yaml_path1) {

        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String type = ruleTabbedPane.getTitleAt(ruleTabbedPane.getSelectedIndex());
                View view_class = burp.views.get(type);
                if (view_class.Choice != null) {
                    JDialog frame = new JDialog();//构造一个新的JFrame，作为新窗口。
                    frame.setBounds(
                            new Rectangle(
                                    // 让新窗口与SwingTest窗口示例错开50像素。
                                    620,
                                    300,
                                    // 窗口总大小-500像素
                                    200,
                                    100
                            )
                    );


                    JPanel xin = new JPanel();
                    xin.setLayout(null);

                    JLabel Tips = new JLabel("Are you sure you want to delete");
                    Tips.setBounds(20, 10, 200, 20);
                    xin.add(Tips);

                    // Ok
                    JButton Ok_button = new JButton("Yes");
                    Ok_button.setBounds(120, 40, 60, 20);
                    xin.add(Ok_button);
                    Ok_button.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            YamlUtil.removeYaml(view_class.Choice.id, yaml_path1);
//                            burp.views = Bfunc.Get_Views();
                            Bfunc.show_yaml_view(burp, view_class, type);
                            frame.dispose();

                        }
                    });

                    // no
                    JButton No_button = new JButton("NO");
                    No_button.setBounds(30, 40, 60, 20);
                    xin.add(No_button);
                    No_button.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            frame.dispose();

                        }
                    });


                    frame.getContentPane().add(xin);
                    frame.setModalityType(Dialog.ModalityType.APPLICATION_MODAL);    // 设置模式类型。
                    frame.setVisible(true);

                }

            }
        });
    }


    private void Add_Button_Yaml(JButton Button_one, String yaml_path1) {

        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
//                burp.call.printOutput(ruleSwitch.ruleEditTextField.getText().trim());
                JDialog frame = new JDialog();//构造一个新的JFrame，作为新窗口。
                frame.setBounds(
                        new Rectangle(
                                // 让新窗口与SwingTest窗口示例错开50像素。
                                620,
                                300,
                                // 窗口总大小-500像素
                                300,
                                400
                        )
                );
                String type = ruleTabbedPane.getTitleAt(ruleTabbedPane.getSelectedIndex());
                JPanel xin = new JPanel();
                xin.setLayout(null);
                // Name
                JLabel Name_field = new JLabel("Name :");
                JTextField Name_text = new JTextField();
                Name_field.setBounds(10, 5, 40, 20);
                Name_text.setBounds(65, 5, 200, 20);
                xin.add(Name_field);
                xin.add(Name_text);

                // Method
                JLabel Method_field = new JLabel("Method :");
                JComboBox Method_text = new JComboBox();    //创建JComboBox
                Method_text.addItem("GET");    //向下拉列表中添加一项
                Method_text.addItem("POST");    //向下拉列表中添加一项
                Method_field.setBounds(10, 45, 40, 20);
                Method_text.setBounds(65, 45, 200, 20);
                xin.add(Method_field);
                xin.add(Method_text);

                // Url
                JLabel Url_field = new JLabel("Url :");
                JTextField Url_text = new JTextField();
                Url_field.setBounds(10, 85, 40, 20);
                Url_text.setBounds(65, 85, 200, 20);
                xin.add(Url_field);
                xin.add(Url_text);

                // Re
                JLabel Re_field = new JLabel("Re :");
                JTextField Re_text = new JTextField();
                Re_field.setBounds(10, 125, 40, 20);
                Re_text.setBounds(65, 125, 200, 20);
                xin.add(Re_field);
                xin.add(Re_text);

                // Info
                JLabel Info_field = new JLabel("Info :");
                JTextField Info_text = new JTextField();
                Info_field.setBounds(10, 165, 40, 20);
                Info_text.setBounds(65, 165, 200, 20);
                xin.add(Info_field);
                xin.add(Info_text);

                // State
                JLabel State_field = new JLabel("State :");
                JTextField State_text = new JTextField();
                State_field.setBounds(10, 205, 40, 20);
                State_text.setBounds(65, 205, 200, 20);
                xin.add(State_field);
                xin.add(State_text);

                // Body（仅POST显示）
                JLabel Body_field = new JLabel("Body :");
                JTextArea Body_text = new JTextArea();  // 改为JTextArea
                Body_text.setLineWrap(true);  // 启用自动换行
                Body_text.setWrapStyleWord(true);  // 按单词换行
                Body_field.setBounds(10, 245, 40, 20);

                // 创建带滚动条的JScrollPane
                JScrollPane scrollPane = new JScrollPane(Body_text);
                scrollPane.setBounds(65, 245, 200, 60);  // 设置滚动面板的位置和大小
                scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);  // 需要时显示垂直滚动条
                scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);  // 需要时显示水平滚动条

                xin.add(Body_field);
                xin.add(scrollPane);  // 添加滚动面板而不是直接添加文本区域
                Body_field.setVisible(false);
                scrollPane.setVisible(false);
                Method_text.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String method = (String) Method_text.getSelectedItem();
                        boolean isPost = "POST".equals(method);
                        Body_field.setVisible(isPost);
                        scrollPane.setVisible(isPost);
                    }
                });

                // Ok - 调整位置，确保不被body字段遮挡
                JButton Ok_button = new JButton("OK");
                Ok_button.setBounds(200, 325, 60, 20);  // Y坐标改为325，确保在body字段下方
                xin.add(Ok_button);
                Ok_button.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int id = 0;
                        Map<String, Object> Yaml_Map = YamlUtil.readYaml(yaml_path1);
                        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
                        for (Map<String, Object> zidian : List1) {
                            if ((int) zidian.get("id") > id) {
                                id = (int) zidian.get("id");
                            }
                        }
                        id += 1;
                        String name = Name_text.getText();
                        String url = Url_text.getText();
                        String method = (String) Method_text.getSelectedItem();
                        String re = Re_text.getText();
                        String info = Info_text.getText();
                        String state = State_text.getText();
                        String body = Body_text.getText();  // 获取body字段内容
                        String type = ruleTabbedPane.getTitleAt(ruleTabbedPane.getSelectedIndex());
                        if ("POST".equals(method)) {
                            // POST指纹直接新建，无需查重
                            Map<String, Object> add_map = new HashMap<String, Object>();
                            add_map.put("type", type);
                            add_map.put("id", id);
                            add_map.put("loaded", true);
                            add_map.put("name", name);
                            add_map.put("method", method);
                            add_map.put("url", url);
                            add_map.put("re", re); // 只用当前输入的re
                            add_map.put("info", info);
                            add_map.put("state", state);
                            add_map.put("body", body);  // 添加body字段
                            YamlUtil.addYaml(add_map, yaml_path1);
                            Bfunc.show_yaml_view(burp, burp.views.get(type), type);
                            frame.dispose();
                            return;
                        }
                        // 查找是否有相同url|state|method的规则
                        Map<String, Object> existRule = null;
                        for (Map<String, Object> rule : List1) {
                            if (url.equals(rule.get("url")) && method.equals(rule.get("method")) && state.equals(rule.get("state"))) {
                                existRule = rule;
                                break;
                            }
                        }
                        if (existRule != null) {
                            // 弹窗选择前先关闭旧弹窗，避免叠加
                            frame.dispose();
                            Object[] options = {"新建", "追加"};
                            int choice = JOptionPane.showOptionDialog(null,
                                    "当前路径已存在规则，是否新建一条规则，或追加到已有规则后？\n" +
                                    "新建：新建一条规则，使用当前输入的re,新建多个规则会访问多次\n" +
                                    "追加：追加到已有规则后，使用已有规则的re+当前输入的re\n",
                                    "提示",
                                    JOptionPane.YES_NO_OPTION,
                                    JOptionPane.QUESTION_MESSAGE,
                                    null,
                                    options,
                                    options[0]);
                            if (choice == 1) { // 追加
                                // name和info用/追加，re用|追加
                                String oldName = (String) existRule.get("name");
                                String oldInfo = (String) existRule.get("info");
                                String oldRe = (String) existRule.get("re");
                                if (oldName == null) oldName = "";
                                if (oldInfo == null) oldInfo = "";
                                if (oldRe == null) oldRe = "";
                                String newName = oldName.isEmpty() ? name : oldName + "/" + name;
                                String newInfo = oldInfo.isEmpty() ? info : oldInfo + "/" + info;
                                String newRe = oldRe.isEmpty() ? re : oldRe + "|" + re;
                                existRule.put("name", newName);
                                existRule.put("info", newInfo);
                                existRule.put("re", newRe);
                                YamlUtil.updateYaml(existRule, yaml_path1);
                                Bfunc.show_yaml_view(burp, burp.views.get(type), type);
                                return;
                            } else if (choice == 0) { // 新建
                                // 新建时只用当前输入的re，不拼接历史re
                                Map<String, Object> add_map = new HashMap<String, Object>();
                                add_map.put("type", type);
                                add_map.put("id", id);
                                add_map.put("loaded", true);
                                add_map.put("name", name);
                                add_map.put("method", method);
                                add_map.put("url", url);
                                add_map.put("re", re); // 只用当前输入的re
                                add_map.put("info", info);
                                add_map.put("state", state);
                                add_map.put("body", body);  // 添加body字段
                                YamlUtil.addYaml(add_map, yaml_path1);
                                Bfunc.show_yaml_view(burp, burp.views.get(type), type);
                                return;
                            } else {
                                // 用户关闭弹窗
                                return;
                            }
                        }
                        // 无重复，直接添加
                        Map<String, Object> add_map = new HashMap<String, Object>();
                        add_map.put("type", type);
                        add_map.put("id", id);
                        add_map.put("loaded", true);
                        add_map.put("name", name);
                        add_map.put("method", method);
                        add_map.put("url", url);
                        add_map.put("re", re);
                        add_map.put("info", info);
                        add_map.put("state", state);
                        add_map.put("body", body);  // 添加body字段
                        YamlUtil.addYaml(add_map, yaml_path1);
                        Bfunc.show_yaml_view(burp, burp.views.get(type), type);
                        frame.dispose();
                    }
                });

                // no - 修改Y坐标，让NO和OK在同一行
                JButton No_button = new JButton("NO");
                No_button.setBounds(130, 325, 60, 20);  // Y坐标改为325，与OK按钮一致
                xin.add(No_button);
                No_button.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        frame.dispose();
                    }
                });


                frame.getContentPane().add(xin);
                frame.setModalityType(Dialog.ModalityType.APPLICATION_MODAL);    // 设置模式类型。
                frame.setVisible(true);

            }
        });
    }


    private void load_button_Yaml(JButton Button_one) {
        Button_one.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Bfunc.show_yaml(burp);
            }
        });


    }


    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        $$$setupUI$$$();
        return one;
    }

}

