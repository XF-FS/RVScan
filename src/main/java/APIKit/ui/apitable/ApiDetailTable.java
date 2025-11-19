/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui.apitable;

import APIKit.ui.apitable.ApiDetailEntity;
import APIKit.ui.apitable.ApiDocumentEntity;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

public class ApiDetailTable
        extends JTable {
    private static final List<ApiDetailEntity> EMPTY_LIST = new ArrayList<ApiDetailEntity>(0);
    private final ApiDetailTableModel model;
    private final Consumer<ApiDetailEntity> onSelectedCallback;

    public ApiDetailTable(Consumer<ApiDetailEntity> onSelectedCallback) {
        this.onSelectedCallback = onSelectedCallback;
        this.model = new ApiDetailTableModel();
        this.setModel(this.model);
        this.setSelectionMode(2);
        this.setEnabled(true);
        this.setDoubleBuffered(true);
        this.getTableHeader().setReorderingAllowed(false);
        this.setShowGrid(false);
        this.setRowHeight(20);
        this.setIntercellSpacing(new Dimension(0, 0));
        this.setAutoCreateRowSorter(true);
        // 设置序号列的宽度
        this.getColumnModel().getColumn(0).setMaxWidth(50);
        this.getSelectionModel().addListSelectionListener(e -> {
            int modelRow;
            ApiDetailEntity selected;
            int selectedRow;
            if (!e.getValueIsAdjusting() && (selectedRow = this.getSelectedRow()) != -1 && (selected = this.model.getEntityAt(modelRow = this.convertRowIndexToModel(selectedRow))) != null && this.onSelectedCallback != null) {
                SwingUtilities.invokeLater(() -> this.onSelectedCallback.accept(selected));
            }
        });
        this.addKeyListener(new KeyAdapter() {

            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == 67 && (e.getModifiers() & Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()) != 0) {
                    ApiDetailTable.this.copySelectedRows();
                }
            }
        });
    }

    public void setApiDetail(ApiDocumentEntity apiDocument) {
        if (apiDocument == null || apiDocument.details == null) {
            this.model.setEntities(EMPTY_LIST);
            this.setEnabled(true);
            return;
        }
        ArrayList<ApiDetailEntity> details = new ArrayList<ApiDetailEntity>(apiDocument.details);
        SwingUtilities.invokeLater(() -> {
            this.model.setEntities(details);
            this.setEnabled(true);
        });
    }

    public void clear() {
        this.model.clear();
        this.setEnabled(true);
    }

    private void copySelectedRows() {
        int[] rows = this.getSelectedRows();
        if (rows.length == 0) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < this.getColumnCount(); ++col) {
            sb.append(this.getColumnName(col));
            if (col >= this.getColumnCount() - 1) continue;
            sb.append("\t");
        }
        sb.append("\n");
        for (int row : rows) {
            for (int col = 0; col < this.getColumnCount(); ++col) {
                Object value = this.getValueAt(row, col);
                if (value != null) {
                    sb.append(value.toString());
                }
                if (col >= this.getColumnCount() - 1) continue;
                sb.append("\t");
            }
            sb.append("\n");
        }
        StringSelection selection = new StringSelection(sb.toString());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    public static class ApiDetailTableModel
            extends AbstractTableModel {
        private volatile List<ApiDetailEntity> tableData = new ArrayList<ApiDetailEntity>();

        public synchronized void setEntities(List<ApiDetailEntity> entities) {
            if (entities == null) {
                entities = EMPTY_LIST;
            }
            this.tableData = new ArrayList<ApiDetailEntity>(entities);
            this.fireTableDataChanged();
        }

        public ApiDetailEntity getEntityAt(int rowIndex) {
            try {
                return this.tableData.get(rowIndex);
            } catch (IndexOutOfBoundsException e) {
                return null;
            }
        }

        @Override
        public int getRowCount() {
            return this.tableData.size();
        }

        @Override
        public int getColumnCount() {
            return 8;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0: {
                    return Integer.class;
                }
                case 1: {
                    return String.class;
                }
                case 2: {
                    return String.class;
                }
                case 3: {
                    return Integer.class;
                }
                case 4: {
                    return Integer.class;
                }
                case 5: {
                    return String.class;
                }
                case 6: {
                    return String.class;
                }
                case 7: {
                    return String.class;
                }
            }
            return null;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0: {
                    return "#";
                }
                case 1: {
                    return "Name";
                }
                case 2: {
                    return "Method";
                }
                case 3: {
                    return "Status Code";
                }
                case 4: {
                    return "Content Length";
                }
                case 5: {
                    return "Unauth";
                }
                case 6: {
                    return "API Type";
                }
                case 7: {
                    return "Scan Time";
                }
            }
            return null;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ApiDetailEntity entity = this.tableData.get(rowIndex);
            switch (columnIndex) {
                case 0: {
                    return rowIndex + 1;
                }
                case 1: {
                    return entity.name;
                }
                case 2: {
                    return entity.method;
                }
                case 3: {
                    return entity.statusCode;
                }
                case 4: {
                    return entity.contentLength;
                }
                case 5: {
                    return entity.unAuth;
                }
                case 6: {
                    return entity.apiType;
                }
                case 7: {
                    return entity.scanTime;
                }
            }
            return null;
        }

        public synchronized void setApiDetail(ApiDocumentEntity apiDocument) {
            if (apiDocument != null && apiDocument.details != null) {
                this.setEntities(apiDocument.details);
            } else {
                this.setEntities(new ArrayList<ApiDetailEntity>(0));
            }
        }

        public synchronized void clear() {
            this.setEntities(new ArrayList<ApiDetailEntity>());
        }
    }
}

