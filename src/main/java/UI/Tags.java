package UI;

import burp.*;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.net.URL;

public class Tags extends AbstractTableModel implements ITab, IMessageEditorController {
    public IBurpExtenderCallbacks callbacks;

    private JSplitPane top;
    private JTabbedPane tabs; // 保存为成员变量

    public List<TablesData> Udatas = new ArrayList<>();
    public List<FingerprintData> FingerprintDatas = new ArrayList<>(); // 指纹识别数据

    public IMessageEditor HRequestTextEditor;
    public IMessageEditor HResponseTextEditor;
    
    // 指纹识别的请求/响应编辑器
    public IMessageEditor FingerprintRequestTextEditor;
    public IMessageEditor FingerprintResponseTextEditor;

    private IHttpRequestResponse currentlyDisplayedItem;
    public IHttpRequestResponse currentlyDisplayedFingerprintItem; // 指纹识别当前显示项

    public URLTable Utable;
    public FingerprintTable FingerprintTable; // 指纹识别表格

    private JScrollPane UscrollPane;
    private JScrollPane FingerprintScrollPane; // 指纹识别滚动面板

    private JSplitPane HjSplitPane;
    private JSplitPane FingerprintSplitPane; // 指纹识别分割面板

    private JTabbedPane Ltable;
    private JTabbedPane Rtable;
    
    // 指纹识别的请求/响应面板
    private JTabbedPane FingerprintLtable;
    private JTabbedPane FingerprintRtable;

    private JSplitPane splitPane;
    private JSplitPane fingerprintMainSplitPane; // 指纹识别主分割面板

    private JPopupMenu m_popupMenu;
    public JPopupMenu fingerprintPopupMenu; // 指纹识别右键菜单

    public List<String> Get_URL_list() {
        List<String> Urls = new ArrayList<>();
        for (TablesData data : this.Udatas) {
            Urls.add(data.url);
        }
        return Urls;
    }


    public Tags(IBurpExtenderCallbacks callbacks, Config Config_l) {
        this.callbacks = callbacks;

//        this.tagName = name;
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                // 创建最上面的一层
                Tags.this.top = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                // 创建容器，容器可以加入多个页面
                tabs = new JTabbedPane();
                // 创建主拆分窗格
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);


                // 日志条目表
                URLTable URLTab = new URLTable(Tags.this);
//                URLTable URLTab = new URLTable();
//                JXTable URLTab = new JXTable();
                URLTab.setModel(Tags.this);
//                URLTab.addMouseListener(new Right_click_menu(Tags.this));

                m_popupMenu = new JPopupMenu();
                JMenuItem delMenItem = new JMenuItem();
                delMenItem.setText("Delete item");
                delMenItem.addActionListener(new Remove_action(Tags.this));
                JMenuItem delAllMenItem = new JMenuItem();
                delAllMenItem.setText("Clear all history");
                delAllMenItem.addActionListener(new Remove_All(Tags.this));
                JMenuItem dedupMenItem = new JMenuItem();
                dedupMenItem.setText("Delete Duplicate");
                dedupMenItem.addActionListener(new Remove_Duplicate(Tags.this));
                JMenuItem del_Select_Duplicate = new JMenuItem();
                del_Select_Duplicate.setText("Delete Select item");
                del_Select_Duplicate.addActionListener(new Remove_Select_Duplicate(Tags.this));

                m_popupMenu.add(delMenItem);
                m_popupMenu.add(delAllMenItem);
                m_popupMenu.add(dedupMenItem);
                m_popupMenu.add(del_Select_Duplicate);
                URLTab.addMouseListener(new java.awt.event.MouseAdapter() {
                    public void mouseClicked(java.awt.event.MouseEvent evt) {
                        jTable1MouseClicked(evt);
                    }
                });



                Tags.this.Utable = URLTab;
                Tags.this.UscrollPane = new JScrollPane(Tags.this.Utable);


                //创建请求和响应的展示窗
                Tags.this.HjSplitPane = new JSplitPane();
                Tags.this.HjSplitPane.setDividerLocation(0.5D);

                // 创建请求/响应的子选项卡
                Tags.this.Ltable = new JTabbedPane();
                Tags.this.Rtable = new JTabbedPane();
                Tags.this.HRequestTextEditor = Tags.this.callbacks.createMessageEditor(Tags.this, false);
                Tags.this.HResponseTextEditor = Tags.this.callbacks.createMessageEditor(Tags.this, false);


                Tags.this.Ltable.addTab("Request", Tags.this.HRequestTextEditor.getComponent());
                Tags.this.Rtable.addTab("Response", Tags.this.HResponseTextEditor.getComponent());

                // 将子选项卡添加进主选项卡
                Tags.this.HjSplitPane.setResizeWeight(0.5D);
                Tags.this.HjSplitPane.setDividerSize(3);
                Tags.this.HjSplitPane.add(Tags.this.Ltable, "left");
                Tags.this.HjSplitPane.add(Tags.this.Rtable, "right");

                // 将日志条目表和展示窗添加到主拆分窗格
                Tags.this.splitPane.add(Tags.this.UscrollPane, "left");
                Tags.this.splitPane.add(Tags.this.HjSplitPane, "right");

                // 将两个页面插入容器
                tabs.addTab("VulDisplay", Tags.this.splitPane);
//                JTabbedPane ConfigView = new JTabbedPane();
//                ConfigView.addTab("Rules",);
                
                // 创建指纹识别标签页
                createFingerprintTab();
                
                tabs.addTab("Config",Config_l.$$$getRootComponent$$$());

                // 添加切换监听，切到VulDisplay时恢复黑色
                tabs.addChangeListener(e -> {
                    if (tabs.getSelectedIndex() == 0) {
                        tabs.setForegroundAt(0, Color.BLACK);
                    }
                    if (tabs.getSelectedIndex() == 1) {
                        tabs.setForegroundAt(1, Color.BLACK);
                    }
                });

                // 将容器置于顶层
                top.setTopComponent(tabs);

                // 定制我们的UI组件
                Tags.this.callbacks.customizeUiComponent(Tags.this.top);

                // 将自定义选项卡添加到Burp的UI
                Tags.this.callbacks.addSuiteTab(Tags.this);
            }
        });
    }
    
    /**
     * 创建指纹识别标签页
     */
    private void createFingerprintTab() {
        // 创建指纹识别表格
        FingerprintTable = new FingerprintTable(this);
        FingerprintScrollPane = new JScrollPane(FingerprintTable);
        
        // 创建指纹识别的请求/响应编辑器
        FingerprintRequestTextEditor = callbacks.createMessageEditor(new FingerprintMessageEditorController(this), false);
        FingerprintResponseTextEditor = callbacks.createMessageEditor(new FingerprintMessageEditorController(this), false);
        
        // 创建指纹识别的请求/响应面板
        FingerprintLtable = new JTabbedPane();
        FingerprintRtable = new JTabbedPane();
        
        FingerprintLtable.addTab("Request", FingerprintRequestTextEditor.getComponent());
        FingerprintRtable.addTab("Response", FingerprintResponseTextEditor.getComponent());
        
        // 创建指纹识别的分割面板
        FingerprintSplitPane = new JSplitPane();
        FingerprintSplitPane.setDividerLocation(0.5D);
        FingerprintSplitPane.setResizeWeight(0.5D);
        FingerprintSplitPane.setDividerSize(3);
        FingerprintSplitPane.add(FingerprintLtable, "left");
        FingerprintSplitPane.add(FingerprintRtable, "right");
        
        // 创建指纹识别主分割面板
        fingerprintMainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        fingerprintMainSplitPane.add(FingerprintScrollPane, "left");
        fingerprintMainSplitPane.add(FingerprintSplitPane, "right");
        
        // 创建右键菜单
        createFingerprintPopupMenu();
        
        // 添加到标签页
        tabs.addTab("Fingerprint", fingerprintMainSplitPane);
    }
    
    /**
     * 创建指纹识别右键菜单
     */
    private void createFingerprintPopupMenu() {
        fingerprintPopupMenu = new JPopupMenu();
        
        JMenuItem delFingerprint = new JMenuItem("Delete item");
        delFingerprint.addActionListener(e -> deleteFingerprintItem());
        
        JMenuItem clearAllFingerprint = new JMenuItem("Delete all");
        clearAllFingerprint.addActionListener(e -> clearAllFingerprints());
        
        JMenuItem removeDuplicateFingerprint = new JMenuItem("Delete duplicates");
        removeDuplicateFingerprint.addActionListener(e -> removeDuplicateFingerprints());
        
        fingerprintPopupMenu.add(delFingerprint);
        fingerprintPopupMenu.add(clearAllFingerprint);
        fingerprintPopupMenu.add(removeDuplicateFingerprint);
    }
    
    /**
     * 删除选中的指纹识别项
     */
    private void deleteFingerprintItem() {
        int[] selectedRows = FingerprintTable.getSelectedRows();
        Arrays.sort(selectedRows);
        for (int i = selectedRows.length - 1; i >= 0; i--) {
            int modelRow = FingerprintTable.convertRowIndexToModel(selectedRows[i]);
            FingerprintDatas.remove(modelRow);
        }
        FingerprintTable.fireTableDataChanged();
        clearFingerprintEditors();
    }
    
    /**
     * 清空所有指纹识别结果
     */
    private void clearAllFingerprints() {
        FingerprintDatas.clear();
        FingerprintTable.fireTableDataChanged();
        clearFingerprintEditors();
    }
    
    /**
     * 清空指纹识别编辑器
     */
    private void clearFingerprintEditors() {
        if (FingerprintRequestTextEditor != null) {
            FingerprintRequestTextEditor.setMessage(new byte[]{}, true);
        }
        if (FingerprintResponseTextEditor != null) {
            FingerprintResponseTextEditor.setMessage(new byte[]{}, false);
        }
    }
    
    /**
     * 去除重复的指纹识别结果
     * 根据fingerprintName、method、status和URL的基础部分进行去重
     */
    private void removeDuplicateFingerprints() {
        if (FingerprintDatas.isEmpty()) {
            return;
        }
        
        // 使用LinkedHashMap保持插入顺序，只保留第一个
        Map<String, FingerprintData> uniqueFingerprints = new LinkedHashMap<>();
        int removedCount = 0;
        
        for (FingerprintData data : FingerprintDatas) {
            // 提取URL的基础部分（不带路径）
            String baseUrl = extractBaseUrl(data.url);
            
            // 创建唯一键：fingerprintName + method + status + baseUrl
            String uniqueKey = data.fingerprintName + "|" + data.method + "|" + data.statusCode + "|" + baseUrl;
            
            if (!uniqueFingerprints.containsKey(uniqueKey)) {
                uniqueFingerprints.put(uniqueKey, data);
            } else {
                removedCount++;
            }
        }
        
        // 更新数据列表
        FingerprintDatas.clear();
        FingerprintDatas.addAll(uniqueFingerprints.values());
        
        // 重新设置ID
        for (int i = 0; i < FingerprintDatas.size(); i++) {
            FingerprintData oldData = FingerprintDatas.get(i);
            FingerprintDatas.set(i, new FingerprintData(
                i,
                oldData.fingerprintName,
                oldData.method,
                oldData.url,
                oldData.statusCode,
                oldData.details,
                oldData.size,
                oldData.requestResponse,
                oldData.timestamp
            ));
        }
        
        // 刷新表格
        FingerprintTable.fireTableDataChanged();
        clearFingerprintEditors();
        
        // 显示去重结果
        if (callbacks != null) {
            callbacks.printOutput("[Fingerprint] 去重完成，移除了 " + removedCount + " 个重复项，剩余 " + FingerprintDatas.size() + " 个唯一项");
        }
    }
    
    /**
     * 从完整URL中提取基础URL（协议+主机+端口）
     * 例如：http://192.168.8.247:8091/test10/filter1 -> http://192.168.8.247:8091/
     */
    private String extractBaseUrl(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            String protocol = url.getProtocol();
            String host = url.getHost();
            int port = url.getPort();
            
            if (port == -1) {
                // 使用默认端口
                if ("https".equals(protocol)) {
                    port = 443;
                } else if ("http".equals(protocol)) {
                    port = 80;
                }
                return protocol + "://" + host + "/";
            } else {
                return protocol + "://" + host + ":" + port + "/";
            }
        } catch (Exception e) {
            // 如果URL解析失败，返回原始URL
            return fullUrl;
        }
    }

    public String getTabCaption() {
        return "RVScan";
    }

    public Component getUiComponent() {
        return this.top;
    }

    public int getRowCount() {
        return this.Udatas.size();
    }

    public int getColumnCount() {
        return 9;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "VulName";
            case 2:
                return "Method";
            case 3:
                return "Url";
            case 4:
                return "Status";
            case 5:
                return "Info";
            case 6:
                return "Size";
            case 7:
                return "startTime";
            case 8:
                return "endTime";
        }
        return null;
    }

    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return Integer.valueOf(datas.id);
            case 1:
                return datas.VulName;
            case 2:
                return datas.Method;
            case 3:
                return datas.url;
            case 4:
                return datas.status;
            case 5:
                return datas.Info;
            case 6:
                return datas.Size;
            case 7:
                return datas.startTime;
            case 8:
                return datas.endTime;
        }
        return null;
    }

    public byte[] getRequest() {
        return this.currentlyDisplayedItem.getRequest();
    }

    public byte[] getResponse() {
        return this.currentlyDisplayedItem.getResponse();
    }

    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem.getHttpService();
    }

    public int add(String VulName, String Method, String url, String status, String Info, String Size, IHttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
//            this.callbacks.printOutput(url + "    " + Info);
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String startTime = sdf.format(d);
            int id = this.Udatas.size();
            this.Udatas.add(
                    new TablesData(
                            id,
                            VulName,
                            Method,
                            url,
                            status,
                            Info,
                            Size,
                            requestResponse,
                            startTime,
                            ""));
            fireTableRowsInserted(id, id);
            // 有新内容时将VulDisplay标签设为红色
            if (tabs != null) {
                tabs.setForegroundAt(0, Color.RED);
            }
            return id;
        }
    }

    /**
     * 添加指纹识别结果到表格中
     */
    public static void ir_add(Tags tags, String title, String method, String url, String statusCode, String notes, String size, IHttpRequestResponse requestResponse) {
        if (tags != null) {
            tags.add(title, method, url, statusCode, notes, size, requestResponse);
        }
    }
    
    /**
     * 添加指纹识别结果
     */
    public int addFingerprintResult(String fingerprintName, String method, String url, String statusCode, String details, String size, IHttpRequestResponse requestResponse) {
        synchronized (this.FingerprintDatas) {
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String startTime = sdf.format(d);
            int id = this.FingerprintDatas.size();
            this.FingerprintDatas.add(new FingerprintData(
                    id,
                    fingerprintName,
                    method,
                    url,
                    statusCode,
                    details,
                    size,
                    requestResponse,
                    startTime
            ));
            
            // 通知指纹识别表格数据已更新
            if (FingerprintTable != null) {
                FingerprintTable.fireTableRowsInserted(id, id);
                // 有新内容时将Fingerprint标签设为红色
                if (tabs != null) {
                    tabs.setForegroundAt(1, Color.RED);
                }
            }
            return id;
        }
    }


    public class URLTable extends JTable {
        private TableRowSorter<TableModel> sorter;

        public URLTable(TableModel tableModel) {
            super(tableModel);
            sorter = new TableRowSorter<TableModel>(tableModel) {
                @Override
                public Comparator<?> getComparator(int column) {
                    TableColumnModel columnModel = getColumnModel();
                    int numberColumnIndex = -1;
                    for (int i = 0; i < columnModel.getColumnCount(); i++) {
                        if (columnModel.getColumn(i).getHeaderValue().toString().equals("#")) {
                            numberColumnIndex = i;
                            break;
                        }
                    }

                    if (column == numberColumnIndex) {
                        return Comparator.comparingInt((Object o) -> {
                            int modelRow = ((TableRowSorter<TableModel>) this).convertRowIndexToModel(((Integer) o).intValue());
                            return (Integer) getModel().getValueAt(convertRowIndexToView(modelRow), column);
                        });
                    }
                    return super.getComparator(column);
                }
            };
            setRowSorter(sorter);

            // 设置每列宽度
            TableColumnModel columnModel = getColumnModel();
            if (columnModel.getColumnCount() >= 9) {
                columnModel.getColumn(0).setPreferredWidth(40);   // #
                columnModel.getColumn(1).setPreferredWidth(120);  // VulName
                columnModel.getColumn(2).setPreferredWidth(60);   // Method
                columnModel.getColumn(3).setPreferredWidth(320);  // Url
                columnModel.getColumn(4).setPreferredWidth(60);   // Status
                columnModel.getColumn(5).setPreferredWidth(120);  // Info
                columnModel.getColumn(6).setPreferredWidth(60);   // Size
                columnModel.getColumn(7).setPreferredWidth(120);  // startTime
                columnModel.getColumn(8).setPreferredWidth(120);  // endTime
            }

            // 添加鼠标监听器
            getTableHeader().addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        int columnIndex = getColumnModel().getColumnIndexAtX(e.getX());
                        toggleSortOrder(columnIndex);
                    }
                }
            });
        }
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = Tags.this.Udatas.get(convertRowIndexToModel(row));
            Tags.this.HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            Tags.this.HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            Tags.this.currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }

        public void sortColumn(int columnIndex, SortOrder sortOrder) {
            List<RowSorter.SortKey> sortKeys = new ArrayList<>();
            sortKeys.add(new RowSorter.SortKey(columnIndex, sortOrder));
            try {
                sorter.setSortKeys(sortKeys);
            }catch (Exception a){
                String x = a.toString();
                System.out.println(x);
            }

        }

        public void toggleSortOrder(int columnIndex) {
            List<? extends RowSorter.SortKey> sortKeys = sorter.getSortKeys();
            if (sortKeys.isEmpty()) {
                sortColumn(columnIndex, SortOrder.ASCENDING);
            } else {
                RowSorter.SortKey sortKey = sortKeys.get(0);
                if (sortKey.getColumn() == columnIndex) {
                    sortColumn(columnIndex, sortKey.getSortOrder() == SortOrder.ASCENDING ? SortOrder.DESCENDING : SortOrder.ASCENDING);
                } else {
                    sortColumn(columnIndex, SortOrder.ASCENDING);
                }
            }

            // 根据列名设置比较器
            String columnName = getColumnModel().getColumn(columnIndex).getHeaderValue().toString();
            if (columnName.equals("Size") || columnName.equals("Status") ){
                sorter.setComparator(columnIndex, new Comparator<String>() {
                    @Override
                    public int compare(String o1, String o2) {
                        return Integer.compare(Integer.parseInt(o1), Integer.parseInt(o2));
                    }
                });
            } else if (columnName.equals("#")) {
                TableColumnModel columnModel = getColumnModel();
                int numberColumnIndex = -1;
                for (int i = 0; i < columnModel.getColumnCount(); i++) {
                    if (columnModel.getColumn(i).getHeaderValue().toString().equals("#")) {
                        numberColumnIndex = i;
                        break;
                    }
                }
                final int retNumber = numberColumnIndex;
                sorter.setComparator(numberColumnIndex, Comparator.comparingInt((Object o) -> {
                    int modelRow = ((TableRowSorter<TableModel>) sorter).convertRowIndexToModel(((Integer) o).intValue());
                    return (Integer) getModel().getValueAt(convertRowIndexToView(modelRow), retNumber);
                }));
            }else if (columnName.equals("startTime")) {
                sorter.setComparator(columnIndex, new Comparator<String>() {
                    @Override
                    public int compare(String o1, String o2) {
                        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                        try {
                            Date date1 = format.parse(o1);
                            Date date2 = format.parse(o2);
                            return date1.compareTo(date2);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        return 0;
                    }
                });
            } else {
                sorter.setComparator(columnIndex, new Comparator<String>() {
                    @Override
                    public int compare(String o1, String o2) {
                        return o1.compareTo(o2);
                    }
                });
            }
        }
    }


    public static class TablesData {
        final int id;

        final String VulName;

        final String Method;

        final String url;

        final String status;

        final String Info;

        final String Size;

        final IHttpRequestResponse requestResponse;

        final String startTime;

        final String endTime;

        public TablesData(int id, String VulName, String Method, String url, String status, String Info, String Size, IHttpRequestResponse requestResponse, String startTime, String endTime) {
            this.id = id;
            this.VulName = VulName;
            this.Method = Method;
            this.url = url;
            this.status = status;
            this.Info = Info;
            this.Size = Size;
            this.requestResponse = requestResponse;
            this.startTime = startTime;
            this.endTime = endTime;
        }
    }


    private void jTable1MouseClicked(java.awt.event.MouseEvent evt) {
        mouseRightButtonClick(evt);
    }


    private void mouseRightButtonClick(java.awt.event.MouseEvent evt) {
        //判断是否为鼠标的BUTTON3按钮，BUTTON3为鼠标右键
        if (evt.getButton() == java.awt.event.MouseEvent.BUTTON3) {
            //经过点击位置找到点击为表格中的行
            int focusedRowIndex = this.Utable.rowAtPoint(evt.getPoint());
            if (focusedRowIndex == -1) {
                return;
            }
            //将表格所选项设为当前右键点击的行
//            this.Utable.setRowSelectionInterval(focusedRowIndex, focusedRowIndex);
            //弹出菜单
            m_popupMenu.show(this.Utable, evt.getX(), evt.getY());
        }

    }


}


class Remove_All implements ActionListener {
    private Tags tag;

    public Remove_All(Tags tag) {
        this.tag = tag;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
//        tag.Udatas.clear();
        while (tag.Udatas.size() != 0){
            tag.Udatas.remove(0);
            tag.fireTableRowsDeleted(0, 0);
        }
        tag.HRequestTextEditor.setMessage(new byte[]{},true);
        tag.HResponseTextEditor.setMessage(new byte[]{},false);
    }

}


class Remove_action implements ActionListener {
    private Tags tag;

    public Remove_action(Tags tag) {
        this.tag = tag;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        int[] RemId = tag.Utable.getSelectedRows();
        for (int i : reversal(RemId)) {
            tag.Udatas.remove(i);
            tag.fireTableRowsDeleted(i, i);
            tag.HRequestTextEditor.setMessage(new byte[]{},true);
            tag.HResponseTextEditor.setMessage(new byte[]{},false);
        }
    }

    public Integer[] reversal(int[] int_array) {
        Integer newScores[] = new Integer[int_array.length];
        for (int i = 0; i < int_array.length; i++) {
            newScores[i] = new Integer(int_array[i]);
        }

        Arrays.sort(newScores, Collections.reverseOrder());
        return newScores;

    }
}


class Remove_Duplicate implements ActionListener {
    private Tags tag;

    public Remove_Duplicate(Tags tag) {
        this.tag = tag;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        List<Tags.TablesData> toRemove = new ArrayList<>();

        for (int i = 0; i < tag.Udatas.size(); i++) {
            Tags.TablesData currentData = tag.Udatas.get(i);
            try {
                // 解析 URL 以提取主机
                URL url = new URL(currentData.url);
                String host = url.getHost();
                int currentSize = Integer.parseInt(currentData.Size);

                for (int j = i + 1; j < tag.Udatas.size(); j++) {
                    Tags.TablesData compareData = tag.Udatas.get(j);
                    URL compareUrl = new URL(compareData.url);
                    String compareHost = compareUrl.getHost();
                    int compareSize = Integer.parseInt(compareData.Size);

                    // 判断 host、status 和 size 范围
                    if (host.equals(compareHost) &&
                            currentData.status.equals(compareData.status) &&
                            (Math.abs(currentSize - compareSize) <= 10)) {
                        toRemove.add(compareData); // 标记为待删除
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        // 移除标记的条目
        tag.Udatas.removeAll(toRemove);

        // 通知表格模型更改
        tag.fireTableDataChanged();

        // 清空请求和响应编辑器
        tag.HRequestTextEditor.setMessage(new byte[]{}, true);
        tag.HResponseTextEditor.setMessage(new byte[]{}, false);
    }
}



class Remove_Select_Duplicate implements ActionListener {
    private Tags tag;

    public Remove_Select_Duplicate(Tags tag) {
        this.tag = tag;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        // 获取右键选中的条目
        int selectedRow = tag.Utable.getSelectedRow();
        if (selectedRow == -1) {
            return; // 如果没有选择的条目，直接返回
        }

        Tags.TablesData selectedData = tag.Udatas.get(tag.Utable.convertRowIndexToModel(selectedRow));
        List<Tags.TablesData> toRemove = new ArrayList<>();

        try {
            // 解析选中的条目的 URL 以提取主机和大小
            URL selectedUrl = new URL(selectedData.url);
            String selectedHost = selectedUrl.getHost();
            int selectedSize = Integer.parseInt(selectedData.Size);

            // 遍历 Udatas 列表进行比较
            for (Tags.TablesData compareData : tag.Udatas) {
                if (compareData != selectedData) { // 确保不比较自己
                    URL compareUrl = new URL(compareData.url);
                    String compareHost = compareUrl.getHost();
                    int compareSize = Integer.parseInt(compareData.Size);

                    // 判断 host、status 和 size 范围
                    if (selectedHost.equals(compareHost) &&
                            selectedData.status.equals(compareData.status) &&
                            (Math.abs(selectedSize - compareSize) <= 100)) {
                        toRemove.add(compareData); // 标记为待删除
                    }
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        // 移除标记的条目
        tag.Udatas.removeAll(toRemove);

        // 通知表格模型更改
        tag.fireTableDataChanged();

        // 清空请求和响应编辑器
        tag.HRequestTextEditor.setMessage(new byte[]{}, true);
        tag.HResponseTextEditor.setMessage(new byte[]{}, false);
    }
}


/**
 * 指纹识别数据类
 */
class FingerprintData {
    final int id;
    final String fingerprintName;
    final String method;
    final String url;
    final String statusCode;
    final String details;
    final String size;
    final IHttpRequestResponse requestResponse;
    final String timestamp;

    public FingerprintData(int id, String fingerprintName, String method, String url, 
                          String statusCode, String details, String size, 
                          IHttpRequestResponse requestResponse, String timestamp) {
        this.id = id;
        this.fingerprintName = fingerprintName;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.details = details;
        this.size = size;
        this.requestResponse = requestResponse;
        this.timestamp = timestamp;
    }
}

/**
 * 指纹识别表格类
 */
class FingerprintTable extends JTable {
    private Tags tags;
    private TableRowSorter<TableModel> sorter;

    public FingerprintTable(Tags tags) {
        super(new FingerprintTableModel(tags));
        this.tags = tags;
        
        sorter = new TableRowSorter<>(getModel());
        setRowSorter(sorter);

        // 设置每列宽度
        TableColumnModel columnModel = getColumnModel();
        if (columnModel.getColumnCount() >= 7) {
            columnModel.getColumn(0).setPreferredWidth(40);   // #
            columnModel.getColumn(1).setPreferredWidth(150);  // Fingerprint
            columnModel.getColumn(2).setPreferredWidth(60);   // Method
            columnModel.getColumn(3).setPreferredWidth(320);  // URL
            columnModel.getColumn(4).setPreferredWidth(60);   // Status
            columnModel.getColumn(5).setPreferredWidth(200);  // Details
            columnModel.getColumn(6).setPreferredWidth(120);  // Time
        }

        // 添加鼠标监听器
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getButton() == MouseEvent.BUTTON3) {
                    // 右键菜单
                    int row = rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        setRowSelectionInterval(row, row);
                        tags.fingerprintPopupMenu.show(FingerprintTable.this, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        if (row >= 0 && row < tags.FingerprintDatas.size()) {
            int modelRow = convertRowIndexToModel(row);
            FingerprintData data = tags.FingerprintDatas.get(modelRow);
            
            tags.FingerprintRequestTextEditor.setMessage(data.requestResponse.getRequest(), true);
            tags.FingerprintResponseTextEditor.setMessage(data.requestResponse.getResponse(), false);
            tags.currentlyDisplayedFingerprintItem = data.requestResponse;
        }
        super.changeSelection(row, col, toggle, extend);
    }
    
    public void fireTableRowsInserted(int firstRow, int lastRow) {
        ((AbstractTableModel) getModel()).fireTableRowsInserted(firstRow, lastRow);
    }
    
    public void fireTableDataChanged() {
        ((AbstractTableModel) getModel()).fireTableDataChanged();
    }
}

/**
 * 指纹识别表格模型
 */
class FingerprintTableModel extends AbstractTableModel {
    private Tags tags;

    public FingerprintTableModel(Tags tags) {
        this.tags = tags;
    }

    @Override
    public int getRowCount() {
        return tags.FingerprintDatas.size();
    }

    @Override
    public int getColumnCount() {
        return 7;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0: return "#";
            case 1: return "Fingerprint";
            case 2: return "Method";
            case 3: return "URL";
            case 4: return "Status";
            case 5: return "Details";
            case 6: return "Time";
            default: return "";
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex >= tags.FingerprintDatas.size()) {
            return "";
        }
        
        FingerprintData data = tags.FingerprintDatas.get(rowIndex);
        switch (columnIndex) {
            case 0: return data.id;
            case 1: return data.fingerprintName;
            case 2: return data.method;
            case 3: return data.url;
            case 4: return data.statusCode;
            case 5: return data.details;
            case 6: return data.timestamp;
            default: return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }
}

/**
 * 指纹识别消息编辑器控制器
 */
class FingerprintMessageEditorController implements IMessageEditorController {
    private Tags tags;

    public FingerprintMessageEditorController(Tags tags) {
        this.tags = tags;
    }

    @Override
    public byte[] getRequest() {
        return tags.currentlyDisplayedFingerprintItem != null ? 
               tags.currentlyDisplayedFingerprintItem.getRequest() : new byte[]{};
    }

    @Override
    public byte[] getResponse() {
        return tags.currentlyDisplayedFingerprintItem != null ? 
               tags.currentlyDisplayedFingerprintItem.getResponse() : new byte[]{};
    }

    @Override
    public IHttpService getHttpService() {
        return tags.currentlyDisplayedFingerprintItem != null ? 
               tags.currentlyDisplayedFingerprintItem.getHttpService() : null;
    }
}


