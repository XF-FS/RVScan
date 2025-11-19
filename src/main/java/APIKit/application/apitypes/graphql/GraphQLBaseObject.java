/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLKind;
import APIKit.application.apitypes.graphql.GraphQLParseContext;
import APIKit.application.apitypes.graphql.GraphQLParseError;
import com.google.gson.JsonObject;

public abstract class GraphQLBaseObject {
    public String name;
    public String description;
    public GraphQLKind kind;

    public GraphQLBaseObject() {
    }

    public GraphQLBaseObject(JsonObject inputJson) {
        this.name = inputJson.getAsJsonPrimitive("name").getAsString();
        if (!inputJson.get("description").isJsonNull()) {
            this.description = inputJson.getAsJsonPrimitive("description").getAsString();
        }
    }

    public Boolean enterExport(GraphQLParseContext context) {
        if (context.checkExportRecursion(this.name).booleanValue()) {
            return false;
        }
        context.exportToQueryStack.push(this.name);
        return true;
    }

    public void leaveExport(GraphQLParseContext context) throws GraphQLParseError {
        String popName = context.exportToQueryStack.pop();
        if (!popName.equals(this.name)) {
            throw new GraphQLParseError("Stack unbalanced");
        }
    }

    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        return "";
    }
}

