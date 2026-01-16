package ru.itmo.back.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.itmo.back.dto.ApiResponse;
import ru.itmo.back.model.VtfsFile;
import ru.itmo.back.service.VtfsService;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api")
@Slf4j
public class VtfsController {
    private final VtfsService vtfsService;

    public VtfsController(VtfsService vtfsService) {
        this.vtfsService = vtfsService;
    }

    private ResponseEntity<byte[]> createResponse(int statusCode, byte[] data) {
        ApiResponse response = ApiResponse.builder()
                .statusCode(statusCode)
                .data(data)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE)
                .body(response.toByteArray());
    }

    @GetMapping("/init")
    public ResponseEntity<byte[]> init(@RequestParam String token) {
        try {
            vtfsService.initializeRootIfNeeded(token);
            log.info("Initialized filesystem for token: {}", token);
            return createResponse(0, null);
        } catch (Exception e) {
            log.error("Init failed", e);
            return createResponse(-1, null);
        }
    }

    @GetMapping("/lookup")
    public ResponseEntity<byte[]> lookup(
            @RequestParam String token,
            @RequestParam String name,
            @RequestParam Long parent_ino) {
        try {
            Optional<VtfsFile> file = vtfsService.findFileInDir(name, parent_ino, token);
            if (file.isPresent()) {
                VtfsFile f = file.get();
                String response = String.format("%d,%d,%s,%d,%d,%d",
                        f.getIno(),
                        f.getParentIno(),
                        f.getIsDir() ? "d" : (f.getIsSymlink() ? "l" : "f"),
                        f.getContentSize(),
                        f.getIsSymlink() ? 1 : 0,
                        f.getIsDir() ? 1 : 0);
                return createResponse(0, response.getBytes());
            }
            return createResponse(-2, null);
        } catch (Exception e) {
            log.error("Lookup failed", e);
            return createResponse(-1, null);
        }
    }

    @PostMapping("/create")
    public ResponseEntity<byte[]> create(
            @RequestParam String token,
            @RequestParam String name,
            @RequestParam Long parent_ino) {
        try {
            Optional<VtfsFile> existing = vtfsService.findFileInDir(name, parent_ino, token);
            if (existing.isPresent()) {
                return createResponse(-17, null);
            }

            VtfsFile file = vtfsService.createFile(name, parent_ino, token);
            String response = String.valueOf(file.getIno());
            log.info("Created file: {} with ino: {}", name, file.getIno());
            return createResponse(0, response.getBytes());
        } catch (Exception e) {
            log.error("Create failed", e);
            return createResponse(-12, null);
        }
    }

    @PostMapping("/mkdir")
    public ResponseEntity<byte[]> mkdir(
            @RequestParam String token,
            @RequestParam String name,
            @RequestParam Long parent_ino) {
        try {
            Optional<VtfsFile> existing = vtfsService.findFileInDir(name, parent_ino, token);
            if (existing.isPresent()) {
                return createResponse(-17, null);
            }

            VtfsFile dir = vtfsService.createDirectory(name, parent_ino, token);
            String response = String.valueOf(dir.getIno());
            log.info("Created directory: {} with ino: {}", name, dir.getIno());
            return createResponse(0, response.getBytes());
        } catch (Exception e) {
            log.error("Mkdir failed", e);
            return createResponse(-12, null);
        }
    }

    @PostMapping("/symlink")
    public ResponseEntity<byte[]> symlink(
            @RequestParam String token,
            @RequestParam String name,
            @RequestParam Long parent_ino,
            @RequestParam String target) {
        try {
            Optional<VtfsFile> existing = vtfsService.findFileInDir(name, parent_ino, token);
            if (existing.isPresent()) {
                return createResponse(-17, null);
            }

            VtfsFile symlink = vtfsService.createSymlink(name, parent_ino, target, token);
            String response = String.valueOf(symlink.getIno());
            log.info("Created symlink: {} -> {} with ino: {}", name, target, symlink.getIno());
            return createResponse(0, response.getBytes());
        } catch (Exception e) {
            log.error("Symlink failed", e);
            return createResponse(-12, null);
        }
    }

    @GetMapping("/getlink")
    public ResponseEntity<byte[]> getlink(
            @RequestParam String token,
            @RequestParam Long ino) {
        try {
            Optional<VtfsFile> file = vtfsService.findFileByIno(ino, token);
            if (file.isPresent() && file.get().getIsSymlink()) {
                String target = file.get().getSymlinkTarget();
                log.info("Retrieved symlink target: {}", target);
                return createResponse(0, target.getBytes());
            }
            return createResponse(-2, null);
        } catch (Exception e) {
            log.error("Getlink failed", e);
            return createResponse(-1, null);
        }
    }

    @GetMapping("/read")
    public ResponseEntity<byte[]> read(
            @RequestParam String token,
            @RequestParam Long ino,
            @RequestParam Long offset,
            @RequestParam Long length) {
        try {
            Optional<VtfsFile> file = vtfsService.findFileByIno(ino, token);
            if (file.isEmpty() || file.get().getIsDir()) {
                return createResponse(-22, null);
            }

            byte[] content = file.get().getContent();
            if (content == null || offset >= content.length) {
                return createResponse(0, new byte[0]);
            }

            long readLength = Math.min(length, content.length - offset);
            byte[] result = new byte[(int) readLength];
            int offsetInt = Math.toIntExact(offset);
            int readLen = Math.toIntExact(readLength);
            System.arraycopy(content, offsetInt, result, 0, readLen);

            log.info("Read {} bytes from inode {} at offset {}", readLength, ino, offset);
            return createResponse(0, result);
        } catch (Exception e) {
            log.error("Read failed", e);
            return createResponse(-1, null);
        }
    }

    @PostMapping("/write")
    public ResponseEntity<byte[]> write(
            @RequestParam String token,
            @RequestParam Long ino,
            @RequestParam Long offset,
            @RequestBody byte[] data) {
        try {
            Optional<VtfsFile> file = vtfsService.findFileByIno(ino, token);
            if (file.isEmpty() || file.get().getIsDir()) {
                return createResponse(-22, null);
            }

            byte[] currentContent = file.get().getContent();
            byte[] newContent;

            if (currentContent == null) {
                newContent = new byte[(int) (offset + data.length)];
            } else {
                long maxSize = Math.max(currentContent.length, offset + data.length);
                int newSize = Math.toIntExact(maxSize);
                newContent = new byte[newSize];
                System.arraycopy(currentContent, 0, newContent, 0, currentContent.length);
            }

            int offsetInt = Math.toIntExact(offset);
            System.arraycopy(data, 0, newContent, offsetInt, data.length);
            vtfsService.updateFileContent(ino, newContent, token);

            String response = String.valueOf(data.length);
            log.info("Wrote {} bytes to inode {} at offset {}", data.length, ino, offset);
            return createResponse(0, response.getBytes());
        } catch (Exception e) {
            log.error("Write failed", e);
            return createResponse(-12, null);
        }
    }

    @DeleteMapping("/unlink")
    public ResponseEntity<byte[]> unlink(
            @RequestParam String token,
            @RequestParam String name,
            @RequestParam Long parent_ino) {
        try {
            Optional<VtfsFile> file = vtfsService.findFileInDir(name, parent_ino, token);
            if (file.isEmpty()) {
                return createResponse(-2, null);
            }
            if (file.get().getIsDir()) {
                return createResponse(-1, null);
            }

            vtfsService.deleteFile(file.get().getIno(), token);
            log.info("Unlinked file: {}", name);
            return createResponse(0, null);
        } catch (Exception e) {
            log.error("Unlink failed", e);
            return createResponse(-1, null);
        }
    }

    @DeleteMapping("/rmdir")
    public ResponseEntity<byte[]> rmdir(
            @RequestParam String token,
            @RequestParam String name,
            @RequestParam Long parent_ino) {
        try {
            Optional<VtfsFile> file = vtfsService.findFileInDir(name, parent_ino, token);
            if (file.isEmpty()) {
                return createResponse(-2, null);
            }
            if (!file.get().getIsDir()) {
                return createResponse(-20, null);
            }
            if (!vtfsService.isDirectoryEmpty(file.get().getIno(), token)) {
                return createResponse(-39, null);
            }

            vtfsService.deleteFile(file.get().getIno(), token);
            log.info("Removed directory: {}", name);
            return createResponse(0, null);
        } catch (Exception e) {
            log.error("Rmdir failed", e);
            return createResponse(-1, null);
        }
    }

    @GetMapping("/list")
    public ResponseEntity<byte[]> list(
            @RequestParam String token,
            @RequestParam Long parent_ino) {
        try {
            List<VtfsFile> files = vtfsService.listFilesInDir(parent_ino, token);
            StringBuilder result = new StringBuilder();

            for (VtfsFile f : files) {
                if (!result.isEmpty()) {
                    result.append("|");
                }
                result.append(f.getName())
                        .append(",").append(f.getIno())
                        .append(",").append(f.getIsDir() ? "d" : (f.getIsSymlink() ? "l" : "f"));
            }

            log.info("Listed {} files in directory {}", files.size(), parent_ino);
            return createResponse(0, result.toString().getBytes());
        } catch (Exception e) {
            log.error("List failed", e);
            return createResponse(-1, null);
        }
    }

    @GetMapping("/listall")
    public ResponseEntity<byte[]> listall(@RequestParam String token) {
        try {
            List<VtfsFile> files = vtfsService.getAllFiles(token);
            StringBuilder result = new StringBuilder();

            for (VtfsFile f : files) {
                if (!result.isEmpty()) {
                    result.append("\n");
                }
                result.append(f.getIno())
                        .append(",").append(f.getParentIno())
                        .append(",").append(f.getName())
                        .append(",").append(f.getIsDir() ? "d" : (f.getIsSymlink() ? "l" : "f"))
                        .append(",").append(f.getContentSize() != null ? f.getContentSize() : 0)
                        .append(",").append(f.getIsSymlink() && f.getSymlinkTarget() != null ? f.getSymlinkTarget() : "");
            }

            log.info("Listed all {} files for token {}", files.size(), token);
            return createResponse(0, result.toString().getBytes());
        } catch (Exception e) {
            log.error("Listall failed", e);
            return createResponse(-1, null);
        }
    }

    @PostMapping("/writehex")
    public ResponseEntity<byte[]> writehex(
            @RequestParam String token,
            @RequestParam Long ino,
            @RequestParam Long offset,
            @RequestParam String data) {
        try {
            Optional<VtfsFile> file = vtfsService.findFileByIno(ino, token);
            if (file.isEmpty() || file.get().getIsDir()) {
                return createResponse(-22, null);
            }

            byte[] decodedData = new byte[data.length() / 2];
            for (int i = 0; i < data.length(); i += 2) {
                decodedData[i / 2] = (byte) Integer.parseInt(data.substring(i, i + 2), 16);
            }

            byte[] currentContent = file.get().getContent();
            byte[] newContent;

            if (currentContent == null) {
                int newSize = Math.toIntExact(offset + decodedData.length);
                newContent = new byte[newSize];
            } else {
                long maxSize = Math.max(currentContent.length, offset + decodedData.length);
                int newSize = Math.toIntExact(maxSize);
                newContent = new byte[newSize];
                System.arraycopy(currentContent, 0, newContent, 0, currentContent.length);
            }

            int offsetInt = Math.toIntExact(offset);
            System.arraycopy(decodedData, 0, newContent, offsetInt, decodedData.length);
            vtfsService.updateFileContent(ino, newContent, token);

            String response = String.valueOf(decodedData.length);
            log.info("Wrote {} bytes (hex-decoded) to inode {} at offset {}", decodedData.length, ino, offset);
            return createResponse(0, response.getBytes());
        } catch (Exception e) {
            log.error("Write hex failed", e);
            return createResponse(-12, null);
        }
    }

    @GetMapping("/readhex")
    public ResponseEntity<byte[]> readhex(
            @RequestParam String token,
            @RequestParam Long ino,
            @RequestParam Long offset,
            @RequestParam Long length) {
        try {
            Optional<VtfsFile> file = vtfsService.findFileByIno(ino, token);
            if (file.isEmpty() || file.get().getIsDir()) {
                return createResponse(-22, null);
            }

            byte[] content = file.get().getContent();
            if (content == null || offset >= content.length) {
                return createResponse(0, "".getBytes());
            }

            long readLength = Math.min(length, content.length - offset);

            StringBuilder hexString = new StringBuilder();
            int offsetInt = Math.toIntExact(offset);
            int readLen = Math.toIntExact(readLength);
            for (int i = offsetInt; i < offsetInt + readLen; i++) {
                hexString.append(String.format("%02x", content[i]));
            }

            log.info("Read {} bytes (hex-encoded) from inode {} at offset {}", readLength, ino, offset);
            return createResponse(0, hexString.toString().getBytes());
        } catch (Exception e) {
            log.error("Read hex failed", e);
            return createResponse(-1, null);
        }
    }

}
