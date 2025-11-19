/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLBaseObject;
import APIKit.application.apitypes.graphql.GraphQLKind;
import APIKit.application.apitypes.graphql.GraphQLObjectType;
import APIKit.application.apitypes.graphql.GraphQLParseContext;
import APIKit.application.apitypes.graphql.GraphQLParseError;
import APIKit.utils.Constants;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLUnion
        extends GraphQLBaseObject {
    public ArrayList<GraphQLObjectType> possibleTypes = new ArrayList();

    public GraphQLUnion(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.UNION;
        for (JsonElement jsonElement : inputJson.getAsJsonArray("possibleTypes")) {
            this.possibleTypes.add(new GraphQLObjectType(jsonElement.getAsJsonObject()));
        }
    }

    @Override
    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        if (!super.enterExport(context).booleanValue()) {
            throw new GraphQLParseError("Recursion detected, this should not happened");
        }
        StringBuilder result = new StringBuilder();
        result.append("{").append(Constants.GRAPHQL_NEW_LINE);
        for (GraphQLObjectType objectType : this.possibleTypes) {
            if (context.globalObjects.get(objectType.typeName) == null || context.checkExportRecursion(objectType.typeName).booleanValue())
                continue;
            result.append(context.getExportQueryIndent()).append("...").append(Constants.GRAPHQL_SPACE).append("on");
            result.append(Constants.GRAPHQL_SPACE).append(objectType.typeName).append(Constants.GRAPHQL_SPACE);
            result.append(context.globalObjects.get(objectType.typeName).exportToQuery(context));
            result.append(Constants.GRAPHQL_NEW_LINE);
        }
        super.leaveExport(context);
        result.append(context.getExportQueryIndent()).append("}");
        return result.toString();
    }
}

