package org.fikua.keycloak.util;

import org.keycloak.common.util.Base64Url;

import java.nio.ByteBuffer;
import java.util.UUID;

public class ApplicationUtils {

    private ApplicationUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static String generateCustomNonce() {
        return Base64Url.encode(convertUUIDToBytes(UUID.randomUUID()));
    }

    private static byte[] convertUUIDToBytes(UUID uuid) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
        byteBuffer.putLong(uuid.getMostSignificantBits());
        byteBuffer.putLong(uuid.getLeastSignificantBits());
        return byteBuffer.array();
    }

}
