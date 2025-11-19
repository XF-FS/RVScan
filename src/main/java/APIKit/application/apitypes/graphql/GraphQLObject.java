/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLBaseObject;
import APIKit.application.apitypes.graphql.GraphQLKind;
import APIKit.application.apitypes.graphql.GraphQLObjectField;
import APIKit.application.apitypes.graphql.GraphQLParseContext;
import APIKit.application.apitypes.graphql.GraphQLParseError;
import APIKit.utils.Constants;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLObject
        extends GraphQLBaseObject {
    public ArrayList<GraphQLObjectField> fields = new ArrayList();

    public GraphQLObject(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.OBJECT;
        for (JsonElement jsonElement : inputJson.getAsJsonArray("fields")) {
            this.fields.add(new GraphQLObjectField(jsonElement.getAsJsonObject()));
        }
    }

    @Override
    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        if (!super.enterExport(context).booleanValue()) {
            throw new GraphQLParseError("Recursion detected, this should not happened");
        }
        StringBuilder result = new StringBuilder("{" + Constants.GRAPHQL_NEW_LINE);
        for (GraphQLObjectField field : this.fields) {
            result.append(context.getExportQueryIndent()).append(field.exportToQuery(context));
            result.append(Constants.GRAPHQL_NEW_LINE);
        }
        result.append(context.getExportQueryIndent()).append("}");
        super.leaveExport(context);
        return result.toString();
    }
}

