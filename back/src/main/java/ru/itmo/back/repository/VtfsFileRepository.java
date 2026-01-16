package ru.itmo.back.repository;

import ru.itmo.back.model.VtfsFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface VtfsFileRepository extends JpaRepository<VtfsFile, Long> {
    Optional<VtfsFile> findByInoAndToken(Long ino, String token);

    Optional<VtfsFile> findByNameAndParentInoAndToken(String name, Long parentIno, String token);

    List<VtfsFile> findByParentInoAndToken(Long parentIno, String token);

    @Query("SELECT COALESCE(MAX(f.ino), 1000) FROM VtfsFile f WHERE f.token = ?1")
    Long getMaxInoByToken(String token);

    List<VtfsFile> findByParentInoAndTokenAndIsDir(Long parentIno, String token, Boolean isDir);
    List<VtfsFile> findByToken(String token);
}

