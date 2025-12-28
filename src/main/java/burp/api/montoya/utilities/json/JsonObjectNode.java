/*
 * Copyright (c) 2022-2024. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities.json;

import java.util.Map;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * This interface is used to define a JSON object node.
 *
 * <p><em>Note: The underlying map can be accessed. Changes to this map are shown on the Node. You can operate on a copy of the map to avoid this behavior.</em></p>
 */
public interface JsonObjectNode extends JsonNode
{
    @Override
    Map<String, JsonNode> getValue();

    /**
     * Retrieves the value for this {@link JsonNode}.
     *
     * @return The value for this JsonNode.
     */
    Map<String, JsonNode> asMap();

    /**
     * Puts a {@link JsonNode} into this {@link JsonObjectNode}.
     *
     * @param key The key to use.
     * @param value The JsonNode that the key should point to.
     */
    void put(String key, JsonNode value);

    /**
     * Puts a string into this {@link JsonObjectNode}.
     *
     * @param key The key to use.
     * @param value The string value that the key should point to.
     * @throws NullPointerException if the value is null.
     */
    void putString(String key, String value);

    /**
     * Puts a double into this {@link JsonObjectNode}.
     *
     * @param key The key to use.
     * @param value The boolean value that the key should point to.
     */
    void putBoolean(String key, boolean value);

    /**
     * Puts a long into this {@link JsonObjectNode}.
     *
     * @param key The key to use.
     * @param value The long value that the key should point to.
     */
    void putNumber(String key, long value);

    /**
     * Puts a double into this {@link JsonObjectNode}.
     *
     * @param key The key to use.
     * @param value The double value that the key should point to.
     */
    void putNumber(String key, double value);

    /**
     * Puts a number into this {@link JsonObjectNode}.
     *
     * @param key The key to use.
     * @param value The number value that the key should point to.
     */
    void putNumber(String key, Number value);

    /**
     * Attempts to return the JsonNode for the given key.
     *
     * @param key The key to retrieve.
     *
     * @return The {@link JsonNode} for the given key.
     */
    JsonNode get(String key);

    /**
     * Attempts to return the string for the given key.
     *
     * @param key The key to retrieve.
     *
     * @return The string for the given key, or null if it is not a {@link String}, or if it is not present.
     */
    String getString(String key);

    /**
     * Attempts to return the boolean for the given key.
     *
     * @param key The key to retrieve.
     *
     * @return The boolean for the given key, or null if it is not a {@link Boolean}, or if it is not present.
     */
    Boolean getBoolean(String key);

    /**
     * Attempts to return the number for the given key as a long.
     *
     * @param key The key to retrieve.
     *
     * @return The number at the given key as a long, or null if it is not a {@link Long}, or if it is not present.
     */
    Long getLong(String key);

    /**
     * Attempts to return the number for the given key as a double.
     *
     * @param key The key to retrieve.
     *
     * @return The number for the given key as a double, or null if it is not a {@link Double}, or if it is not present.
     */
    Double getDouble(String key);

    /**
     * Attempts to return the number for the given key.
     *
     * @param key The key to retrieve.
     *
     * @return The number for the given key, or null if it is not a {@link Number}, or if it is not present.
     */
    Number getNumber(String key);

    /**
     * Removes the given key and corresponding JsonNode from the object.
     *
     * @param key The key to remove.
     */
    void remove(String key);

    /**
     * Determines if the object contains the given key.
     *
     * @param key The key to check for.
     *
     * @return True if the object contains the given key.
     */
    boolean has(String key);

    /**
     * Determines if the object contains the given key, and if the corresponding value is a string.
     *
     * @param key The key to check for.
     *
     * @return True if the object contains the given key, and the corresponding value is a string.
     */
    boolean hasString(String key);

    /**
     * Determines if the object contains the given key, and if the corresponding value is a boolean.
     *
     * @param key The key to check for.
     *
     * @return True if the object contains the given key, and the corresponding value is a boolean.
     */
    boolean hasBoolean(String key);

    /**
     * Determines if the object contains the given key, and if the corresponding value is a number.
     *
     * @param key The key to check for.
     *
     * @return True if the object contains the given key, and the corresponding value is a number.
     */
    boolean hasNumber(String key);

    /**
     * Determines if the object contains the given key, and if the corresponding value is an array.
     *
     * @param key The key to check for.
     *
     * @return True if the object contains the given key, and the corresponding value is an array.
     */
    boolean hasArray(String key);

    /**
     * Determines if the object contains the given key, and if the corresponding value is an object.
     *
     * @param key The key to check for.
     *
     * @return True if the object contains the given key, and the corresponding value is an object.
     */
    boolean hasObject(String key);

    /**
     * Creates a new empty instance of {@link JsonObjectNode}.
     *
     * @return A new {@link JsonObjectNode} instance.
     */
    static JsonObjectNode jsonObjectNode()
    {
        return FACTORY.jsonObjectNode();
    }

    /**
     * Creates a new instance of {@link JsonObjectNode} from the supplied map of String to {@link JsonNode}.
     *
     * @param value The map of String to {@link JsonNode}.
     *
     * @return A new {@link JsonNode} instance.
     */
    static JsonObjectNode jsonObjectNode(Map<String, ? extends JsonNode> value)
    {
        return FACTORY.jsonObjectNode(value);
    }
}
