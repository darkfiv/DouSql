/*
 * Copyright (c) 2022-2024. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities.json;

/**
 * <p>
 * This interface enables you to access convenient methods to read and manipulate JSON.
 * All the methods accept a JSON String and a location. Some methods accept an additional
 * JSON argument that you can use to modify the supplied JSON String.
 * </p>
 * <h2>Location syntax:</h2>
 * <ul style="list-style-type: none">
 *     <li style="display: table-row"><div style="display: table-cell; padding-right: 10px"><b>.</b></div><div>The location elements are delimited by a period character</div></li>
 *     <li style="display: table-row"><div style="display: table-cell; padding-right: 10px"><b>[n]</b></div><div>Specifies the nth item in a JSON array</div></li>
 *     <li style="display: table-row"><div style="display: table-cell; padding-right: 10px"><b>[]</b></div><div>Specifies the last element in a JSON array</div></li>
 *     <li style="display: table-row"><div style="display: table-cell; padding-right: 10px"><b>key</b></div><div>Identifies keyed entry in a JSON object</div></li>
 * </ul>
 * <p><em>Note: Indices are zero based.</em></p>
 * <p>For example, when applied to the JSON below:</p>
 * <p><em>account.[0].user.name</em> would select "Peter Wiener"</p>
 * <p><em>account.[].user.name</em> would select "Carlos Montoya"</p>
 * <p><em>account.[1].user.addresses.[]</em> would select "Address 6"</p>
 * <pre>
 *     {
 *         "account": [
 *              {
 *                  "user": {
 *                      "name": "Peter Wiener",
 *                      "addresses": [
 *                          "Address 1",
 *                          "Address 2",
 *                          "Address 3"
 *                      ]
 *                  }
 *              },
 *              {
 *                  "user": {
 *                      "name": "Carlos Montoya",
 *                      "addresses": [
 *                          "Address 4",
 *                          "Address 5",
 *                          "Address 6"
 *                      ]
 *                  }
 *              }
 *         ]
 *     }
 * </pre>
 * <h2>Remarks</h2>
 * <p>
 * Methods that take in JSON accept single quotes in place of double quotes.
 * </p>
 * <p>
 * If your use case is more complex than this interface allows, see {@link JsonNode} and its inheritors.
 * </p>
 */
public interface JsonUtils
{
    /**
     * Uses the location to create a new JSON string with the newJson added to the sourceJson.
     *
     * @param sourceJson The JSON to add the newJson to.
     * @param location Identifies where to add the newJson.
     * @param newJson The new JSON to add to the source.
     * @return A new string with the modified JSON.
     * @throws JsonException If the location is invalid.
     * @throws JsonParseException If either the sourceJson or newJson are not valid JSON.
     */
    String add(String sourceJson, String location, String newJson);

    /**
     * Uses the location to create a new JSON string where the sourceJson is updated with the newJson.
     *
     * @param sourceJson The JSON that will be updated by the newJson.
     * @param location Identifies where the update should occur on the sourceJson.
     * @param newJson The new JSON to use in the location.
     * @return A new string with the modified JSON.
     * @throws JsonException If the location is invalid.
     * @throws JsonParseException If either the sourceJson or newJson are not valid JSON.
     */
    String update(String sourceJson, String location, String newJson);

    /**
     * Creates a new JSON string where the data at the provided location is removed form the sourceJson.
     *
     * @param sourceJson The JSON that will have data removed.
     * @param location Identifies where to remove the JSON.
     * @return A new string with the data at the provided location removed from sourceJson.
     * @throws JsonException If the location is invalid.
     * @throws JsonParseException If the sourceJson is not valid JSON.
     */
    String remove(String sourceJson, String location);

    /**
     * Uses the location to work out where to read from the sourceJson.
     *
     * @param sourceJson The JSON to read some data from.
     * @param location Identifies where to read from the sourceJson.
     * @return The JSON read at the given location as a JSON string.
     * @throws JsonException If the location is invalid.
     * @throws JsonParseException If the sourceJson is not valid JSON.
     */
    String read(String sourceJson, String location);

    /**
     * Uses the location to work out where to read a {@link Boolean} value from the provided sourceJson.
     *
     * @param sourceJson The JSON to read from.
     * @param location Identifies where to read from the sourceJson.
     * @return The boolean value at the given location, or null if it is not a {@link Boolean}, or if it is not present.
     * @throws JsonException If the location is invalid.
     * @throws JsonParseException If the sourceJson is not valid JSON.
     */
    Boolean readBoolean(String sourceJson, String location);

    /**
     * <p>Uses the location to work out where to read a number as a {@link Double} value from the sourceJson.</p>
     *
     * <p><em>Note: A double value in Java represents a floating point number. </em></p>
     *
     * @param sourceJson The JSON to read from.
     * @param location Identifies where to read from the sourceJson
     * @return The number value as a {@link Double} at the given location, or null if it not a {@link Double}, or if it is not present.
     * @throws JsonException If the location is invalid.
     * @throws JsonParseException If the sourceJson is not valid JSON.
     */
    Double readDouble(String sourceJson, String location);

    /**
     * <p>Uses the location to work out where to read a number as a {@link Long} value from the sourceJson.</p>
     *
     * <p><em>Note: A long value in Java represents a mathematical integer - Reading a floating point number with this method will round it down.</em></p>
     *
     * @param sourceJson The JSON to read from.
     * @param location Identifies where to read from the sourceJson
     * @return The number value as a {@link Long} at the given location, or null if it not a {@link Long}, or if it is not present.
     * @throws JsonException If the location is invalid.
     * @throws JsonParseException If the sourceJson is not valid JSON.
     */
    Long readLong(String sourceJson, String location);

    /**
     * Uses the location to work out where to read a {@link String} value from the sourceJson.
     *
     * @param sourceJson The JSON to read from.
     * @param location Identifies where to read from the sourceJson
     * @return The string value at the given location, or null if it not a {@link String}, or if it is not present.
     * @throws JsonException If the location is invalid.
     * @throws JsonParseException If the sourceJson is not valid JSON.
     */
    String readString(String sourceJson, String location);

    /**
     * Checks if the supplied sourceJson can be parsed into one of the base JSON types - string, number, boolean, array, object or null.
     *
     * <p><em>Note: Passing in null will return false, whereas "null" will return true.</em></p>
     * <p><em>Note: To pass in a JSON string, surround it in single or double quotes ("'foo'" or "\"foo\"").</em></p>
     *
     * @param sourceJson The JSON string to check
     * @return True if this parser can parse the JSON string into one of the base JSON types. False otherwise or if sourceJson is null.
     */
    boolean isValidJson(String sourceJson);
}
