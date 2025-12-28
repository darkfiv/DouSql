/*
 * Copyright (c) 2022-2024. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities.json;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * <p>This interface is used to represent a JSON node, and acts as the base for all other JsonNode types (see subinterfaces).</p>
 * <p>You can create a JsonNode from a raw JSON string using {@link JsonNode#jsonNode(String)}, which will attempt to parse the JSON into a specific JsonNode type.</p>
 * <p>To retrieve the created JsonNode as a JsonArray, or a JsonObject, call {@link #asArray()} or {@link #asObject()} respectively. This provides additional utility for the specific JSON type.</p>
 *
 * <p><em>Note: If you are parsing a JsonObject, you can use {@link JsonObjectNode} and its utility methods. Call {@link #asObject} on your JsonNode.</em></p>
 * <p><em>Note: Attempting to retrieve the JsonNode as the wrong type will throw an {@link IllegalStateException}.</em></p>
 *
 * <pre>
 *     JsonNode jsonNode = JsonNode.create("[]");       // The string parsed, and the underlying type will be {@link JsonArrayNode}.
 *     JsonObjectNode objectNode = jsonNode.asObject(); // Throws IllegalStateException, as the JSON string was parsed as a {@link JsonArrayNode}.
 *     JsonArrayNode arrayNode = jsonNode.asArray();    // Successful
 * </pre>
 *
 * <p>
 *     Each specific JsonNode type has a corresponding factory method:
 * </p>
 *
 * <pre>
 *     // Create a JsonStringNode with the value "foo"
 *     JsonStringNode stringNode = JsonStringNode.jsonStringNode("foo");
 *
 *     // Create a JsonNumberNode with the value 2.5
 *     JsonNumberNode numberNode = JsonNumberNode.jsonNumberNode(2.5);
 *
 *     // Create a JsonArrayNode containing the two above nodes
 *     JsonArrayNode arrayNode = JsonArrayNode.jsonArrayNode(
 *         stringNode,
 *         numberNode
 *     );
 * </pre>
 *
 * <p>
 *     Any JsonNode can return its JSON string representation:
 * </p>
 *
 * <pre>
 *     JsonArrayNode arrayNode = JsonArrayNode.jsonArrayNode(
 *            stringNode,
 *            numberNode
 *     );
 *
 *     String arrayNodeAsJson = arrayNode.toJsonString();
 *
 *     System.out.println(arrayNodeAsJson);
 * </pre>
 *
 * <p>Prints:</p>
 *
 * <pre>
 *     [
 *       "foo",
 *       2.5
 *     ]
 * </pre>
 */
public interface JsonNode
{
    /**
     * Retrieves the value for this {@link JsonNode}.
     *
     * @return The value for this JsonNode.
     */
    Object getValue();

    /**
     * Returns this {@link JsonNode} as its string representation.
     *
     * @return The JsonNode in JSON string format.
     */
    String toJsonString();

    /**
     * Checks if this {@link JsonNode} is an array.
     *
     * @return True if this JsonNode represents a JSON array.
     */
    boolean isArray();

    /**
     * Checks if this {@link JsonNode} is an object.
     *
     * @return True if this JsonNode represents a JSON object.
     */
    boolean isObject();

    /**
     * Checks if this {@link JsonNode} is a string.
     *
     * @return True if this JsonNode represents a JSON string.
     */
    boolean isString();

    /**
     * Checks if this {@link JsonNode} is a number.
     *
     * @return True if this JsonNode represents a JSON number.
     */
    boolean isNumber();

    /**
     * Checks if this {@link JsonNode} is a boolean.
     *
     * @return True if this JsonNode represents a JSON boolean.
     */
    boolean isBoolean();

    /**
     * Checks if this {@link JsonNode} is null.
     *
     * @return True if this JsonNode represents a null value.
     */
    boolean isNull();

    /**
     * Attempts to return this {@link JsonNode} as a boolean.
     *
     * @throws IllegalStateException If this JsonNode is not a boolean type.
     */
    Boolean asBoolean();

    /**
     * Attempts to return this {@link JsonNode} as a string.
     *
     * @throws IllegalStateException If this JsonNode is not a string type.
     */
    String asString();

    /**
     * Attempts to return this {@link JsonNode} as a number.
     *
     * @throws IllegalStateException If this JsonNode is not a number type.
     */
    Number asNumber();

    /**
     * Attempts to return this {@link JsonNode} as a long.
     *
     * @throws IllegalStateException If this JsonNode is not a number type.
     */
    Long asLong();

    /**
     * Attempts to return this {@link JsonNode} as a double.
     *
     * @throws IllegalStateException If this JsonNode is not a number type.
     */
    Double asDouble();

    /**
     * Attempts to return this {@link JsonNode} as a list of nodes.
     *
     * @throws IllegalStateException If this JsonNode is not an array type.
     */
    JsonArrayNode asArray();

    /**
     * Attempts to return this {@link JsonNode} as an object.
     *
     * @throws IllegalStateException If this JsonNode is not an object type.
     */
    JsonObjectNode asObject();

    /**
     * Creates a new instance of {@link JsonNode} from the supplied json string.
     *
     * @param json The JSON string, which may use single quotes in place of double quotes.
     *
     * @return A new {@link JsonNode} instance.
     * @throws JsonParseException If the string is not valid JSON.
     */
    static JsonNode jsonNode(String json)
    {
        return FACTORY.jsonNode(json);
    }
}
