package ru.itmo.back.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiResponse {
    private int statusCode;
    private String message;
    private byte[] data;

    public byte[] toByteArray() {
        byte[] statusBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            statusBytes[i] = (byte) ((statusCode >>> (i * 8)) & 0xFF);
        }

        if (data == null || data.length == 0) {
            return statusBytes;
        }

        byte[] result = new byte[8 + data.length];
        System.arraycopy(statusBytes, 0, result, 0, 8);
        System.arraycopy(data, 0, result, 8, data.length);
        return result;
    }
}
