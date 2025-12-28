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
 * This interface is used to define a JSON null node.
 */
public interface JsonNullNode extends JsonNode
{
    @Override
    Object getValue();

    /**
     * Creates a new instance of {@link JsonNullNode}.
     *
     * @return A new {@link JsonNullNode} instance.
     */
    static JsonNullNode jsonNullNode()
    {
        return FACTORY.jsonNullNode();
    }
}
