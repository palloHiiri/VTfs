#ifndef VTFS_H
#define VTFS_H

#include <linux/inet.h>

#define MODULE_NAME "vtfs"
#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)
#define VTFS_ROOT_INO 1000

struct vtfs_file_content {
    char *data;
    size_t size;
    size_t allocated;
};

struct vtfs_file_info {
    char name[256];
    ino_t ino;
    ino_t parent_ino;
    bool is_dir;
    struct list_head list;
    struct vtfs_file_content content;
    struct mutex lock;
};

extern struct list_head vtfs_files;
extern int next_ino;
extern struct mutex vtfs_files_lock;
extern int file_mask;

struct dentry* vtfs_mount(struct file_system_type* fs_type, int flags, const char* token, void* data);
void vtfs_kill_sb(struct super_block* sb);
int vtfs_fill_super(struct super_block *sb, void *data, int silent);
struct inode* vtfs_get_inode(struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino);
struct dentry* vtfs_lookup(struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag);
int vtfs_iterate(struct file* filp, struct dir_context* ctx);
int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool b);
int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset);

struct vtfs_file_info *find_file_info(ino_t ino);
struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino);

extern struct inode_operations vtfs_inode_ops;
extern struct file_operations vtfs_dir_ops;
extern struct file_operations vtfs_file_ops;
extern struct file_system_type vtfs_fs_type;

#endif // VTFS_H