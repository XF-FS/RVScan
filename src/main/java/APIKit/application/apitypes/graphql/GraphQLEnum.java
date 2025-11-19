/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLBaseObject;
import APIKit.application.apitypes.graphql.GraphQLKind;
import APIKit.application.apitypes.graphql.GraphQLParseContext;
import APIKit.application.apitypes.graphql.GraphQLParseError;
import APIKit.utils.CommonUtils;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.HashMap;

public class GraphQLEnum
        extends GraphQLBaseObject {
    public HashMap<String, String> enumValues = new HashMap();

    public GraphQLEnum(JsonObject inputJson) {
        super(inputJson);
        this.kind = GraphQLKind.ENUM;
        for (JsonElement jsonElement : inputJson.getAsJsonArray("enumValues")) {
            JsonObject enumObject = jsonElement.getAsJsonObject();
            String enumName = enumObject.getAsJsonPrimitive("name").getAsString();
            String enumDescription = null;
            if (!enumObject.get("description").isJsonNull()) {
                enumDescription = enumObject.getAsJsonPrimitive("description").getAsString();
            }
            this.enumValues.put(enumName, enumDescription);
        }
    }

    @Override
    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        return CommonUtils.randomChoice(this.enumValues.keySet());
    }
}

