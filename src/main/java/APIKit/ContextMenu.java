/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import APIKit.PassiveScanner;
import APIKit.application.apitypes.ApiType;
import APIKit.ui.TargetAPIConfigPanel;
import APIKit.utils.Executor;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import javax.swing.JMenuItem;
import APIKit.BurpExtenderAdapter;

public class ContextMenu
        implements IContextMenuFactory {
    private static final HashSet<Byte> availableToolFlag = new HashSet();

    static {
        availableToolFlag.add((byte) 6);
        availableToolFlag.add((byte) 0);
        availableToolFlag.add((byte) 2);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (availableToolFlag.contains(invocation.getInvocationContext())) {
            ArrayList<JMenuItem> menuItemList = new ArrayList<JMenuItem>();
            JMenuItem AutoAPIScan = new JMenuItem("Do Auto API Scan");
            JMenuItem TargetAPIScan2 = new JMenuItem("Do Target API Scan");
            AutoAPIScan.addActionListener(new ContextMenuActionListener(invocation));
            TargetAPIScan2.addActionListener(new ActionListener() {

                @Override
                public void actionPerformed(ActionEvent arg0) {
                    try {
                        TargetAPIConfigPanel panel = new TargetAPIConfigPanel();
                        BurpExtenderAdapter.getCallbacks().customizeUiComponent(panel);
                        panel.setVisible(true);
                    } catch (Exception e) {
                        e.printStackTrace(BurpExtenderAdapter.getStderr());
                    }
                }
            });
            menuItemList.add(AutoAPIScan);
            menuItemList.add(TargetAPIScan2);
            return menuItemList;
        }
        return null;
    }

    static class ContextMenuActionListener
            implements ActionListener {
        IContextMenuInvocation invocation;

        public ContextMenuActionListener(IContextMenuInvocation invocation) {
            this.invocation = invocation;
        }

        @Override
        public void actionPerformed(ActionEvent actionEvent) {
            CompletableFuture.supplyAsync(() -> {
                IHttpRequestResponse[] httpRequestResponses;
                final PassiveScanner passiveScanner = BurpExtenderAdapter.getPassiveScanner();
                for (final IHttpRequestResponse httpRequestResponse : httpRequestResponses = this.invocation.getSelectedMessages()) {
                    new Thread(new Runnable() {

                        @Override
                        public void run() {
                            ArrayList<ApiType> apiTypes = passiveScanner.getApiScanner().detect(httpRequestResponse, false);
                            passiveScanner.parseApiDocument(apiTypes, null);
                        }
                    }).start();
                }
                return null;
            }, Executor.getExecutor());
        }
    }
}

