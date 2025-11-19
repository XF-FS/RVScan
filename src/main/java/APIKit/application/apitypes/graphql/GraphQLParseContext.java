/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLBaseObject;
import APIKit.utils.Constants;

import java.util.Collections;
import java.util.HashMap;
import java.util.Stack;

public class GraphQLParseContext {
    HashMap<String, GraphQLBaseObject> globalObjects;
    Stack<String> exportToQueryStack = new Stack();

    public GraphQLParseContext(HashMap<String, GraphQLBaseObject> globalObjects) {
        this.globalObjects = globalObjects;
    }

    public String getExportQueryIndent() {
        return String.join((CharSequence) "", Collections.nCopies(this.exportToQueryStack.size() + 1, Constants.GRAPHQL_TAB));
    }

    public Boolean checkExportRecursion(String name) {
        return Collections.frequency(this.exportToQueryStack, name) > 0;
    }

    public Boolean checkStackDepth() {
        return this.exportToQueryStack.size() > 3;
    }
}

