/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui.apitable;

import APIKit.ui.apitable.ApiDocumentEntity;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

public class ApiDocumentTable
        extends JTable {
    private final ApiDocumentTableModel model;
    private final Consumer<ApiDocumentEntity> onSelectedCallback;

    public ApiDocumentTable(Consumer<ApiDocumentEntity> onSelectedCallback) {
        this.onSelectedCallback = onSelectedCallback;
        this.model = new ApiDocumentTableModel();
        this.setModel(this.model);
        this.setSelectionMode(2);
        this.setEnabled(true);
        this.setAutoCreateRowSorter(true);
        this.getColumnModel().getColumn(0).setMaxWidth(50);
        this.getSelectionModel().addListSelectionListener(e -> {
            ApiDocumentEntity selected;
            int selectedRow;
            if (!e.getValueIsAdjusting() && (selectedRow = this.getSelectedRow()) != -1 && (selected = this.model.getEntityAt(this.convertRowIndexToModel(selectedRow))) != null && this.onSelectedCallback != null) {
                this.onSelectedCallback.accept(selected);
            }
        });
        this.addKeyListener(new KeyAdapter() {

            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == 67 && (e.getModifiers() & Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()) != 0) {
                    ApiDocumentTable.this.copySelectedRows();
                }
            }
        });
    }

    public void append(ApiDocumentEntity apiDocument) {
        this.model.append(apiDocument);
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

    public static class ApiDocumentTableModel
            extends AbstractTableModel {
        private final List<ApiDocumentEntity> tableData = new ArrayList<ApiDocumentEntity>();

        /*
         * WARNING - Removed try catching itself - possible behaviour change.
         */
        public void append(ApiDocumentEntity entity) {
            ApiDocumentTableModel apiDocumentTableModel;
            ApiDocumentTableModel apiDocumentTableModel2 = apiDocumentTableModel = this;
            synchronized (apiDocumentTableModel2) {
                this.tableData.add(entity);
                int _id = this.tableData.size();
                this.fireTableRowsInserted(_id - 1, _id - 1);
            }
        }

        /*
         * WARNING - Removed try catching itself - possible behaviour change.
         */
        public synchronized void clear() {
            ApiDocumentTableModel apiDocumentTableModel;
            ApiDocumentTableModel apiDocumentTableModel2 = apiDocumentTableModel = this;
            synchronized (apiDocumentTableModel2) {
                int size = this.tableData.size();
                if (size > 0) {
                    this.tableData.clear();
                    this.fireTableRowsDeleted(0, size - 1);
                }
            }
        }

        public ApiDocumentEntity getEntityAt(int rowIndex) {
            return this.tableData.get(rowIndex);
        }

        @Override
        public int getRowCount() {
            return this.tableData.size();
        }

        @Override
        public int getColumnCount() {
            return 7;
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
                    return Integer.class;
                }
                case 3: {
                    return Integer.class;
                }
                case 4: {
                    return String.class;
                }
                case 5: {
                    return String.class;
                }
                case 6: {
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
                    return "URL";
                }
                case 2: {
                    return "Status Code";
                }
                case 3: {
                    return "Content Length";
                }
                case 4: {
                    return "Unauth";
                }
                case 5: {
                    return "API Type";
                }
                case 6: {
                    return "Scan Time";
                }
            }
            return null;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ApiDocumentEntity entity = this.tableData.get(rowIndex);
            switch (columnIndex) {
                case 0: {
                    return entity.id;
                }
                case 1: {
                    return entity.url;
                }
                case 2: {
                    return entity.statusCode;
                }
                case 3: {
                    return entity.contentLength;
                }
                case 4: {
                    return entity.unAuth;
                }
                case 5: {
                    return entity.apiType;
                }
                case 6: {
                    return entity.scanTime;
                }
            }
            return null;
        }

        public ApiDocumentEntity getApiDocument(int rowIndex) {
            return this.getEntityAt(rowIndex);
        }
    }
}

