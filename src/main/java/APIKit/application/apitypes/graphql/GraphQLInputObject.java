/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLBaseObject;
import APIKit.application.apitypes.graphql.GraphQLInputObjectField;
import APIKit.application.apitypes.graphql.GraphQLKind;
import APIKit.application.apitypes.graphql.GraphQLParseContext;
import APIKit.application.apitypes.graphql.GraphQLParseError;
import APIKit.utils.Constants;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLInputObject
        extends GraphQLBaseObject {
    public ArrayList<GraphQLInputObjectField> inputFields = new ArrayList();

    public GraphQLInputObject(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.INPUT_OBJECT;
        for (JsonElement jsonElement : inputJson.getAsJsonArray("inputFields")) {
            this.inputFields.add(new GraphQLInputObjectField(jsonElement.getAsJsonObject()));
        }
    }

    @Override
    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        if (!super.enterExport(context).booleanValue()) {
            throw new GraphQLParseError("Recursion detected, this should not happened");
        }
        StringBuilder result = new StringBuilder("{").append(Constants.GRAPHQL_SPACE);
        boolean first = true;
        for (GraphQLInputObjectField inputObjectField : this.inputFields) {
            if (context.checkExportRecursion(inputObjectField.type.typeName).booleanValue() || context.checkStackDepth().booleanValue())
                continue;
            if (first) {
                first = false;
            } else {
                result.append(",").append(Constants.GRAPHQL_SPACE);
            }
            result.append(inputObjectField.exportToQuery(context));
        }
        result.append(Constants.GRAPHQL_SPACE).append("}");
        super.leaveExport(context);
        return result.toString();
    }
}

