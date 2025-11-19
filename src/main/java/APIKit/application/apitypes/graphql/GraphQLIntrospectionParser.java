/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.graphql;

import APIKit.application.apitypes.graphql.GraphQLBaseObject;
import APIKit.application.apitypes.graphql.GraphQLEnum;
import APIKit.application.apitypes.graphql.GraphQLInputObject;
import APIKit.application.apitypes.graphql.GraphQLInterface;
import APIKit.application.apitypes.graphql.GraphQLKind;
import APIKit.application.apitypes.graphql.GraphQLObject;
import APIKit.application.apitypes.graphql.GraphQLObjectField;
import APIKit.application.apitypes.graphql.GraphQLParseContext;
import APIKit.application.apitypes.graphql.GraphQLParseError;
import APIKit.application.apitypes.graphql.GraphQLParseResult;
import APIKit.application.apitypes.graphql.GraphQLScalar;
import APIKit.application.apitypes.graphql.GraphQLUnion;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.HashMap;

public class GraphQLIntrospectionParser {
    GraphQLParseResult parseIntrospection(String introspectionJson) {
        JsonElement mutationTypeJson;
        JsonObject introspection = (JsonObject) JsonParser.parseString(introspectionJson);
        introspection = introspection.getAsJsonObject("data").getAsJsonObject("__schema");
        JsonArray types = introspection.getAsJsonArray("types");
        HashMap<String, GraphQLBaseObject> globalObjects = new HashMap<String, GraphQLBaseObject>();
        GraphQLParseContext context = new GraphQLParseContext(globalObjects);
        block12:
        for (JsonElement element : types) {
            JsonObject object = element.getAsJsonObject();
            GraphQLKind objectKind = GraphQLKind.valueOf(object.getAsJsonPrimitive("kind").getAsString());
            String name = object.getAsJsonPrimitive("name").getAsString();
            switch (objectKind) {
                case OBJECT: {
                    globalObjects.put(name, new GraphQLObject(object));
                    continue block12;
                }
                case INTERFACE: {
                    globalObjects.put(name, new GraphQLInterface(object));
                    continue block12;
                }
                case SCALAR: {
                    globalObjects.put(name, new GraphQLScalar(name));
                    continue block12;
                }
                case ENUM: {
                    globalObjects.put(name, new GraphQLEnum(object));
                    continue block12;
                }
                case UNION: {
                    globalObjects.put(name, new GraphQLUnion(object));
                    continue block12;
                }
                case INPUT_OBJECT: {
                    globalObjects.put(name, new GraphQLInputObject(object));
                    continue block12;
                }
            }
            System.out.println((Object) objectKind);
        }
        GraphQLParseResult parseResult = new GraphQLParseResult();
        JsonElement queryTypeJson = introspection.get("queryType");
        if (!queryTypeJson.isJsonNull()) {
            String queryTypeName = queryTypeJson.getAsJsonObject().getAsJsonPrimitive("name").getAsString();
            GraphQLObject queryObject = (GraphQLObject) globalObjects.get(queryTypeName);
            for (GraphQLObjectField field : queryObject.fields) {
                try {
                    parseResult.queryParseResult.put(field.name, context.getExportQueryIndent() + field.exportToQuery(context));
                } catch (GraphQLParseError e) {
                    e.printStackTrace();
                }
            }
        }
        if (!(mutationTypeJson = introspection.get("mutationType")).isJsonNull()) {
            String mutationTypeName = mutationTypeJson.getAsJsonObject().getAsJsonPrimitive("name").getAsString();
            GraphQLObject mutationObject = (GraphQLObject) globalObjects.get(mutationTypeName);
            for (GraphQLObjectField field : mutationObject.fields) {
                try {
                    parseResult.mutationParseResult.put(field.name, context.getExportQueryIndent() + field.exportToQuery(context));
                } catch (GraphQLParseError e) {
                    e.printStackTrace();
                }
            }
        }
        return parseResult;
    }
}

