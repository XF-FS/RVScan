/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLBaseObject;
import APIKit.application.apitypes.graphql.GraphQLKind;
import APIKit.application.apitypes.graphql.GraphQLObjectFieldArgument;
import APIKit.application.apitypes.graphql.GraphQLObjectType;
import APIKit.application.apitypes.graphql.GraphQLParseContext;
import APIKit.application.apitypes.graphql.GraphQLParseError;
import APIKit.utils.Constants;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLObjectField
        extends GraphQLBaseObject {
    public ArrayList<GraphQLObjectFieldArgument> args = new ArrayList();
    public GraphQLObjectType type;

    public GraphQLObjectField(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.OBJECT_FIELD;
        for (JsonElement jsonElement : inputJson.getAsJsonArray("args")) {
            this.args.add(new GraphQLObjectFieldArgument(jsonElement.getAsJsonObject()));
        }
        this.type = new GraphQLObjectType(inputJson.getAsJsonObject("type"));
    }

    @Override
    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        StringBuilder result = new StringBuilder();
        result.append(this.name).append(Constants.GRAPHQL_SPACE);
        if (this.args.size() > 0) {
            result.append("(");
            for (int i2 = 0; i2 < this.args.size(); ++i2) {
                GraphQLObjectFieldArgument arg = this.args.get(i2);
                result.append(arg.exportToQuery(context));
                if (i2 == this.args.size() - 1) continue;
                result.append(",").append(Constants.GRAPHQL_SPACE);
            }
            result.append(")").append(Constants.GRAPHQL_SPACE);
        }
        switch (this.type.kind) {
            case UNION:
            case OBJECT:
            case INTERFACE: {
                if (context.checkExportRecursion(this.type.typeName).booleanValue() || context.checkStackDepth().booleanValue()) {
                    return "";
                }
                result.append(context.globalObjects.get(this.type.typeName).exportToQuery(context));
            }
        }
        return result.toString();
    }
}

