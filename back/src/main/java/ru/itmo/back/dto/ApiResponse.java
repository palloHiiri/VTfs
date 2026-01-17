package ru.itmo.back.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiResponse {
    private int statusCode;
    private String message;
    private byte[] data;

    public byte[] toByteArray() {
        ByteBuffer buffer = ByteBuffer.allocate(8 + (data != null ? data.length : 0));
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        buffer.putLong((long) statusCode);

        if (data != null && data.length > 0) {
            buffer.put(data);
        }

        return buffer.array();
    }
}