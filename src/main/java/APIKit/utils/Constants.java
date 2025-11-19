/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.utils;

import burp.IHttpRequestResponse;
import APIKit.application.apitypes.ApiType;
import APIKit.application.apitypes.actuator.ApiTypeActuator;
import APIKit.application.apitypes.graphql.ApiTypeGraphQL;
import APIKit.application.apitypes.rest.ApiTypeRest;
import APIKit.application.apitypes.soap.ApiTypeSoap;
import APIKit.application.apitypes.swagger.ApiTypeSwagger;

import java.util.HashMap;
import java.util.function.BiFunction;

public class Constants {
    public static final String[] APITypeNames = new String[]{"SpringbootActuator", "GraphQLIntrospection", "SOAP-WSDL", "OpenAPI-Swagger", "REST-WADL"};
    public static final HashMap<String, BiFunction<IHttpRequestResponse, Boolean, ApiType>> APITypeMaps = new HashMap<String, BiFunction<IHttpRequestResponse, Boolean, ApiType>>() {
        {
            this.put("SpringbootActuator", ApiTypeActuator::newInstance);
            this.put("GraphQLIntrospection", ApiTypeGraphQL::newInstance);
            this.put("SOAP-WSDL", ApiTypeSoap::newInstance);
            this.put("OpenAPI-Swagger", ApiTypeSwagger::newInstance);
            this.put("REST-WADL", ApiTypeRest::newInstance);
        }
    };
    public static final String graphQLIntrospectionRequestJSON = "cXVlcnkgUXVlcnkgewogICAgX19zY2hlbWEgewogICAgICBxdWVyeVR5cGUgeyBuYW1lIH0KICAgICAgbXV0YXRpb25UeXBlIHsgbmFtZSB9CiAgICAgIHN1YnNjcmlwdGlvblR5cGUgeyBuYW1lIH0KICAgICAgdHlwZXMgewogICAgICAgIC4uLkZ1bGxUeXBlCiAgICAgIH0KICAgICAgZGlyZWN0aXZlcyB7CiAgICAgICAgbmFtZQogICAgICAgIGRlc2NyaXB0aW9uCiAgICAgICAgbG9jYXRpb25zCiAgICAgICAgYXJncyB7CiAgICAgICAgICAuLi5JbnB1dFZhbHVlCiAgICAgICAgfQogICAgICB9CiAgICB9CiAgfQoKICBmcmFnbWVudCBGdWxsVHlwZSBvbiBfX1R5cGUgewogICAga2luZAogICAgbmFtZQogICAgZGVzY3JpcHRpb24KICAgIGZpZWxkcyhpbmNsdWRlRGVwcmVjYXRlZDogdHJ1ZSkgewogICAgICBuYW1lCiAgICAgIGRlc2NyaXB0aW9uCiAgICAgIGFyZ3MgewogICAgICAgIC4uLklucHV0VmFsdWUKICAgICAgfQogICAgICB0eXBlIHsKICAgICAgICAuLi5UeXBlUmVmCiAgICAgIH0KICAgICAgaXNEZXByZWNhdGVkCiAgICAgIGRlcHJlY2F0aW9uUmVhc29uCiAgICB9CiAgICBpbnB1dEZpZWxkcyB7CiAgICAgIC4uLklucHV0VmFsdWUKICAgIH0KICAgIGludGVyZmFjZXMgewogICAgICAuLi5UeXBlUmVmCiAgICB9CiAgICBlbnVtVmFsdWVzKGluY2x1ZGVEZXByZWNhdGVkOiB0cnVlKSB7CiAgICAgIG5hbWUKICAgICAgZGVzY3JpcHRpb24KICAgICAgaXNEZXByZWNhdGVkCiAgICAgIGRlcHJlY2F0aW9uUmVhc29uCiAgICB9CiAgICBwb3NzaWJsZVR5cGVzIHsKICAgICAgLi4uVHlwZVJlZgogICAgfQogIH0KCiAgZnJhZ21lbnQgSW5wdXRWYWx1ZSBvbiBfX0lucHV0VmFsdWUgewogICAgbmFtZQogICAgZGVzY3JpcHRpb24KICAgIHR5cGUgeyAuLi5UeXBlUmVmIH0KICAgIGRlZmF1bHRWYWx1ZQogIH0KCiAgZnJhZ21lbnQgVHlwZVJlZiBvbiBfX1R5cGUgewogICAga2luZAogICAgbmFtZQogICAgb2ZUeXBlIHsKICAgICAga2luZAogICAgICBuYW1lCiAgICAgIG9mVHlwZSB7CiAgICAgICAga2luZAogICAgICAgIG5hbWUKICAgICAgICBvZlR5cGUgewogICAgICAgICAga2luZAogICAgICAgICAgbmFtZQogICAgICAgICAgb2ZUeXBlIHsKICAgICAgICAgICAga2luZAogICAgICAgICAgICBuYW1lCiAgICAgICAgICAgIG9mVHlwZSB7CiAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgIG5hbWUKICAgICAgICAgICAgICBvZlR5cGUgewogICAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgICAgbmFtZQogICAgICAgICAgICAgICAgb2ZUeXBlIHsKICAgICAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgICAgICBuYW1lCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9CiAgICB9CiAgfQ==";
    public static String TREE_STATUS_EXPAND = "\u25bc";
    public static String TREE_STATUS_COLLAPSE = "\u25b6";
    public static String TAB_COLOR_SELECTED = "0xffc599";
    public static String TAB_COLOR_MAIN_DATA = "0xf2f2f2";
    public static String TAB_COLOR_SUB_DATA = "0xffffff";
    public static String GRAPHQL_SPACE = " ";
    public static String GRAPHQL_NEW_LINE = "\n";
    public static String GRAPHQL_TAB = "    ";
}

