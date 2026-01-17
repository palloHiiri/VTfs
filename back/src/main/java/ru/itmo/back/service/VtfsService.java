package ru.itmo.back.service;

import ru.itmo.back.model.VtfsFile;
import ru.itmo.back.repository.VtfsFileRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
@Slf4j
public class VtfsService {
    private final VtfsFileRepository fileRepository;

    public VtfsService(VtfsFileRepository fileRepository) {
        this.fileRepository = fileRepository;
    }

    public long getNextIno(String token) {
        Long maxIno = fileRepository.getMaxInoByToken(token);
        return maxIno + 1;
    }

    public void initializeRootIfNeeded(String token) {
        Optional<VtfsFile> root = fileRepository.findByInoAndToken(1000L, token);
        if (root.isEmpty()) {
            VtfsFile rootDir = VtfsFile.builder()
                    .ino(1000L)
                    .parentIno(1000L)
                    .name(".")
                    .isDir(true)
                    .isSymlink(false)
                    .content(null)
                    .contentSize(0L)
                    .token(token)
                    .build();
            fileRepository.save(rootDir);
            log.info("Root directory initialized for token: {}", token);
        }
    }

    public Optional<VtfsFile> findFileByIno(Long ino, String token) {
        return fileRepository.findByInoAndToken(ino, token);
    }

    public Optional<VtfsFile> findFileInDir(String name, Long parentIno, String token) {
        return fileRepository.findByNameAndParentInoAndToken(name, parentIno, token);
    }

    public List<VtfsFile> listFilesInDir(Long parentIno, String token) {
        return fileRepository.findByParentInoAndToken(parentIno, token);
    }

    public VtfsFile createFile(String name, Long parentIno, String token) {
        long newIno = getNextIno(token);
        VtfsFile file = VtfsFile.builder()
                .ino(newIno)
                .parentIno(parentIno)
                .name(name)
                .isDir(false)
                .isSymlink(false)
                .content(null)
                .contentSize(0L)
                .token(token)
                .build();
        return fileRepository.save(file);
    }

    public VtfsFile createDirectory(String name, Long parentIno, String token) {
        long newIno = getNextIno(token);
        VtfsFile dir = VtfsFile.builder()
                .ino(newIno)
                .parentIno(parentIno)
                .name(name)
                .isDir(true)
                .isSymlink(false)
                .content(null)
                .contentSize(0L)
                .token(token)
                .build();
        return fileRepository.save(dir);
    }

    public VtfsFile createSymlink(String name, Long parentIno, String target, String token) {
        long newIno = getNextIno(token);
        VtfsFile symlink = VtfsFile.builder()
                .ino(newIno)
                .parentIno(parentIno)
                .name(name)
                .isDir(false)
                .isSymlink(true)
                .symlinkTarget(target)
                .content(null)
                .contentSize(0L)
                .token(token)
                .build();
        return fileRepository.save(symlink);
    }

    public void deleteFile(Long ino, String token) {
        Optional<VtfsFile> file = fileRepository.findByInoAndToken(ino, token);
        file.ifPresent(fileRepository::delete);
    }

    public void updateFileContent(Long ino, byte[] content, String token) {
        Optional<VtfsFile> file = fileRepository.findByInoAndToken(ino, token);
        file.ifPresent(f -> {
            f.setContent(content);
            f.setContentSize((long) content.length);
            fileRepository.save(f);
        });
    }

    public boolean isDirectoryEmpty(Long dirIno, String token) {
        List<VtfsFile> children = fileRepository.findByParentInoAndToken(dirIno, token);
        return children.stream().allMatch(f -> f.getName().equals(".") || f.getName().equals(".."));
    }

    public List<VtfsFile> getAllFiles(String token) {
        return fileRepository.findByToken(token);
    }

    public VtfsFile createHardlink(String name, Long parentIno, Long targetIno, String token) {
        Optional<VtfsFile> targetFile = fileRepository.findByInoAndToken(targetIno, token);
        if (targetFile.isEmpty()) {
            throw new RuntimeException("Target file not found");
        }

        VtfsFile original = targetFile.get();

        if (original.getIsDir()) {
            throw new RuntimeException("Cannot create hardlink to directory");
        }

        Optional<VtfsFile> existing = fileRepository.findByNameAndParentInoAndToken(name, parentIno, token);
        if (existing.isPresent()) {
            throw new RuntimeException("File with this name already exists");
        }

        VtfsFile hardlink = VtfsFile.builder()
                .ino(targetIno)
                .parentIno(parentIno)
                .name(name)
                .isDir(false)
                .isSymlink(false)
                .content(original.getContent())
                .contentSize(original.getContentSize())
                .token(token)
                .build();

        return fileRepository.save(hardlink);
    }

    public long getLinkCount(Long ino, String token) {
        return fileRepository.countLinksByInoAndToken(ino, token);
    }
}

