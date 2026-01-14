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
struct dentry* vtfs_lookup(struct inode* parent_inode, 
                          struct dentry* child_dentry, 
                          unsigned int flag);
int vtfs_iterate(struct file* filp, struct dir_context* ctx);

struct file_system_type vtfs_fs_type = {
  .name = "vtfs",
  .mount = vtfs_mount,
  .kill_sb = vtfs_kill_sb,
};

struct inode_operations vtfs_inode_ops = {
  .lookup = vtfs_lookup,
};

struct file_operations vtfs_dir_ops = {
  .iterate_shared = vtfs_iterate,
};
struct file_operations vtfs_file_ops = {
};

struct dentry* vtfs_lookup(struct inode* parent_inode, 
                          struct dentry* child_dentry, 
                          unsigned int flag){
  ino_t root = parent_inode->i_ino;
  const char* name = child_dentry->d_name.name;
  if(root == 1000 && !strcmp(name, "test.txt")) {
    struct inode* inode = vtfs_get_inode(
      parent_inode->i_sb, 
      parent_inode, 
      S_IFREG | 0777, 
      101
    );
    if(inode) {
      inode->i_fop = &vtfs_file_ops;
      d_add(child_dentry, inode);
      LOG("Created file inode for %s\n", name);
    }
  }else if (!strcmp(name, "dir"))
  {
    struct inode* inode = vtfs_get_inode(
      parent_inode->i_sb, 
      parent_inode, 
      S_IFDIR | 0777, 
      200
    );
    if(inode) {
      inode->i_op = &vtfs_inode_ops;
      inode->i_fop = &vtfs_dir_ops;
      d_add(child_dentry, inode);
      LOG("Created directory inode for %s\n", name);
    }
  }

  return NULL;
}

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

int vtfs_iterate(struct file* filp, struct dir_context* ctx) {
    struct dentry* dentry = filp->f_path.dentry;
    struct inode* inode   = dentry->d_inode;
    ino_t ino             = inode->i_ino;

    if (ino == 1000) {
        if (ctx->pos == 0) {
            if (!dir_emit(ctx, ".", 1, ino, DT_DIR))
                return 0;
            ctx->pos++;
        }
        
        if (ctx->pos == 1) {
            ino_t parent_ino = dentry->d_parent ? dentry->d_parent->d_inode->i_ino : ino;
            if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR))
                return 0;
            ctx->pos++;
        }
        
        if (ctx->pos == 2) {
            if (!dir_emit(ctx, "test.txt", 8, 101, DT_REG))
                return 0;
            ctx->pos++;
        }
    }
    
    return 0;
}



struct dentry* mount_nodev(
  struct file_system_type* fs_type,
  int flags, 
  void* data, 
  int (*fill_super)(struct super_block*, void*, int)
);

int vtfs_fill_super(struct super_block *sb, void *data, int silent) {
  struct inode* inode = vtfs_get_inode(sb, NULL, S_IFDIR|0777, 1000);

  if (inode == NULL) {
    printk(KERN_ERR "Can't create root inode");
    return -ENOMEM;
  }
  
  inode->i_op = &vtfs_inode_ops;
  inode->i_fop = &vtfs_dir_ops;

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

    if(S_ISDIR(mode)) {
      inode->i_fop = &vtfs_dir_ops;
      inode->i_op = &vtfs_inode_ops;
    }
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
