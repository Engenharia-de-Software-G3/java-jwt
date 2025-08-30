package com.auth0.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class SerializationTest {

    @Test
    public void testMapJsonNodeSerialization() throws Exception {
        ObjectMapper mapper = new ObjectMapper();

        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("claim", mapper.readTree("{\"value\":123}"));

        // Serialization
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(tree);
        }

        // Deserialization
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        Map<String, JsonNode> treeDeserialized;
        try (ObjectInputStream ois = new ObjectInputStream(bais)) {
            @SuppressWarnings("unchecked")
            Map<String, JsonNode> temp = (Map<String, JsonNode>) ois.readObject();
            treeDeserialized = temp;
        }

        // Verification
        assertEquals(tree.size(), treeDeserialized.size());
        assertEquals(tree.get("claim").toString(), treeDeserialized.get("claim").toString()); 
    }
}

