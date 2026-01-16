package ru.itmo.back.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "vtfs_files")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VtfsFile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long ino;

    @Column(nullable = false)
    private Long parentIno;

    @Column(nullable = false, length = 256)
    private String name;

    @Column(nullable = false)
    private Boolean isDir;

    @Column(nullable = false)
    private Boolean isSymlink;

    @Column(length = 1024)
    private String symlinkTarget;

    @Column(columnDefinition = "BYTEA")
    private byte[] content;

    @Column(nullable = false)
    private Long contentSize;

    @Column(nullable = false)
    private String token;
}

