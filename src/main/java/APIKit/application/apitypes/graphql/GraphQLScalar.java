/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLBaseObject;
import APIKit.application.apitypes.graphql.GraphQLKind;
import APIKit.application.apitypes.graphql.GraphQLParseContext;
import APIKit.application.apitypes.graphql.GraphQLParseError;

import java.util.HashMap;

public class GraphQLScalar
        extends GraphQLBaseObject {
    public static HashMap<String, String> scalarDefaultValues = new HashMap();

    static {
        scalarDefaultValues.put("String", "\"string\"");
        scalarDefaultValues.put("Int", "1024");
        scalarDefaultValues.put("Float", "1.1");
        scalarDefaultValues.put("Boolean", "true");
        scalarDefaultValues.put("ID", "3");
    }

    String typeName;

    public GraphQLScalar(String typeName) {
        this.kind = GraphQLKind.SCALAR;
        this.typeName = typeName;
    }

    @Override
    public String exportToQuery(GraphQLParseContext context) throws GraphQLParseError {
        String result = "";
        result = scalarDefaultValues.containsKey(this.typeName) ? scalarDefaultValues.get(this.typeName) : String.format("\"undefined scalar type %s\"", this.typeName);
        return result;
    }
}

