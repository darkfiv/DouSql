/*
 * Copyright (c) 2022-2024. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities.json;

import java.util.List;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * This interface is used to define a JSON array node.
 *
 * <p><em>Note: The underlying list can be accessed. Changes to this list are shown on the Node. You can operate on a copy of the list to avoid this behavior.</em></p>
 */
public interface JsonArrayNode extends JsonNode
{
    @Override
    List<JsonNode> getValue();

    /**
     * Retrieves the value for this {@link JsonNode}.
     *
     * @return The value for this JsonNode.
     */
    List<JsonNode> asList();

    /**
     * Adds a {@link JsonNode} to this {@link JsonArrayNode}.
     *
     * @param value The node to add.
     */
    void add(JsonNode value);

    /**
     * Adds a string to this {@link JsonArrayNode}.
     *
     * @param value The string to add.
     * @throws NullPointerException if the value is null.
     */
    void addString(String value);

    /**
     * Adds a boolean to this {@link JsonArrayNode}.
     *
     * @param value The boolean to add.
     */
    void addBoolean(boolean value);

    /**
     * Adds a long to this {@link JsonArrayNode}.
     *
     * @param value The long to add.
     */
    void addNumber(long value);

    /**
     * Adds a double to this {@link JsonArrayNode}.
     *
     * @param value The double to add.
     */
    void addNumber(double value);

    /**
     * Adds a number to this {@link JsonArrayNode}.
     *
     * @param value The number to add.
     */
    void addNumber(Number value);

    /**
     * Attempts to return the JsonNode at the given index.
     *
     * @param index The index to retrieve.
     *
     * @return The {@link JsonNode} at the given index.
     */
    JsonNode get(int index);

    /**
     * Attempts to return the string at the given index.
     *
     * @param index The index to retrieve.
     *
     * @return The string at the given index or null if it is not a {@link String}.
     */
    String getString(int index);

    /**
     * Attempts to return the boolean at the given index.
     *
     * @param index The index to retrieve.
     *
     * @return The boolean at the given index or null if it is not a {@link Boolean}.
     */
    Boolean getBoolean(int index);

    /**
     * Attempts to return the number at the given index as a long.
     *
     * @param index The index to retrieve.
     *
     * @return The number at the given index as a long or null if it is not a {@link Long}.
     */
    Long getLong(int index);

    /**
     * Attempts to return the number at the given index as a double.
     *
     * @param index The index to retrieve.
     *
     * @return The number at the given index as a double or null if it is not a {@link Double}.
     */
    Double getDouble(int index);

    /**
     * Attempts to return the number at the given index.
     *
     * @param index The index to retrieve.
     *
     * @return The number at the given index or null if it is not a {@link Number}.
     */
    Number getNumber(int index);

    /**
     * Removes the JsonNode at the given index.
     *
     * @param index The index for the JsonNode to remove.
     */
    void remove(int index);

    /**
     * Creates a new empty instance of {@link JsonArrayNode}.
     *
     * @return A new {@link JsonArrayNode} instance.
     */
    static JsonArrayNode jsonArrayNode()
    {
        return FACTORY.jsonArrayNode();
    }

    /**
     * Creates a new instance of {@link JsonArrayNode} from the supplied list of {@link JsonNode}.
     *
     * @param value The list of {@link JsonNode}.
     *
     * @return A new {@link JsonNode} instance.
     */
    static JsonArrayNode jsonArrayNode(List<? extends JsonNode> value)
    {
        return FACTORY.jsonArrayNode(value);
    }

    /**
     * Creates a new instance of {@link JsonArrayNode} from the supplied {@link JsonNode} instances.
     *
     * @param values The instances of {@link JsonNode}.
     *
     * @return A new {@link JsonNode} instance.
     */
    static JsonArrayNode jsonArrayNode(JsonNode... values)
    {
        return FACTORY.jsonArrayNode(values);
    }
}
