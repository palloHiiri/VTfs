#ifndef VTFS_H
#define VTFS_H

#include <linux/inet.h>

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

static int file_mask = 0;

struct vtfs_file_info {
    char name[256];
    ino_t ino;
    bool exists;
    struct list_head list;
};

static LIST_HEAD(vtfs_files);
static DEFINE_MUTEX(vtfs_files_lock);
static int next_ino = 103;

struct dentry* vtfs_mount(struct file_system_type *fs_type,
                         int flags, const char *token,
                         void *data);
void vtfs_kill_sb(struct super_block *sb);
int vtfs_fill_super(struct super_block *sb, void *data, int silent);
struct inode* vtfs_get_inode(struct super_block *sb, const struct inode *inode,
              umode_t mode, int i_ino);
struct dentry* vtfs_lookup(struct inode* parent_inode, 
                          struct dentry* child_dentry, 
                          unsigned int flag);
int vtfs_iterate(struct file* filp, struct dir_context* ctx);
int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                struct dentry *child_dentry, umode_t mode, bool b);
int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
struct vtfs_file_info* find_file_info(const char* name, ino_t parent_ino);
struct vtfs_file_info* create_file_info(const char* name, ino_t ino);

#endif // VTFS_H