#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

#define MODULE_NAME "vtfs"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module");

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

struct dentry* vtfs_mount(struct file_system_type *fs_type,
                         int flags, const char *token,
                         void *data);
void vtfs_kill_sb(struct super_block *sb);
int vtfs_fill_super(struct super_block *sb, void *data, int silent);
struct inode* vtfs_get_inode(struct super_block *sb, const struct inode *inode,
                         umode_t mode, int i_ino);

struct file_system_type vtfs_fs_type = {
  .name = "vtfs",
  .mount = vtfs_mount,
  .kill_sb = vtfs_kill_sb,
};

struct dentry* vtfs_mount(struct file_system_type *fs_type,
                         int flags, const char *token,
                         void *data) {
  struct dentry *ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
  if(ret == NULL) {
    printk(KERN_ERR "Can't mount file system");
  } else {
    printk(KERN_INFO "Mounted successfuly");
  }
  return ret;
  
}

struct dentry* mount_nodev(
  struct file_system_type* fs_type,
  int flags, 
  void* data, 
  int (*fill_super)(struct super_block*, void*, int)
);

int vtfs_fill_super(struct super_block *sb, void *data, int silent) {
  struct inode* inode = vtfs_get_inode(sb, NULL, S_IFDIR, 1000);
  
  sb->s_root = d_make_root(inode);
  if (sb->s_root == NULL) {
    printk(KERN_ERR "Can't create root directory");
    return -ENOMEM;
  }
  printk(KERN_INFO "Root directory created successfully");
  return 0;
}

struct inode* vtfs_get_inode(
  struct super_block* sb, 
  const struct inode* dir, 
  umode_t mode, 
  int i_ino
) {
  struct inode *inode = new_inode(sb);
  if (inode != NULL) {
    inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
    inode->i_ino = i_ino;
    inode->__i_atime = inode->__i_mtime = inode->__i_ctime = current_time(inode);
  }

  return inode;
}

void vtfs_kill_sb(struct super_block* sb) {
  printk(KERN_INFO "vtfs super block is destroyed. Unmount successfully.\n");
}

static int __init vtfs_init(void) {
  register_filesystem(&vtfs_fs_type);
  LOG("VTFS joined the kernel\n");
  return 0;
}

static void __exit vtfs_exit(void) {
  unregister_filesystem(&vtfs_fs_type);
  LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);
