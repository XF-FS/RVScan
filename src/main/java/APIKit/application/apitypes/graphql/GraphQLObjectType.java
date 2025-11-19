/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLKind;
import com.google.gson.JsonObject;

import java.util.ArrayList;

public class GraphQLObjectType {
    public String typeName;
    public GraphQLKind kind;
    public ArrayList<GraphQLKind> modifiers = new ArrayList();

    public GraphQLObjectType(JsonObject jsonInput) {
        GraphQLKind graphQLKind;
        while ((graphQLKind = GraphQLKind.valueOf(jsonInput.getAsJsonPrimitive("kind").getAsString())) == GraphQLKind.NON_NULL || graphQLKind == GraphQLKind.LIST) {
            this.modifiers.add(graphQLKind);
            jsonInput = jsonInput.getAsJsonObject("ofType");
        }
        this.kind = graphQLKind;
        this.typeName = jsonInput.getAsJsonPrimitive("name").getAsString();
    }

    public Boolean isList() {
        return this.modifiers.contains((Object) GraphQLKind.LIST);
    }
}

