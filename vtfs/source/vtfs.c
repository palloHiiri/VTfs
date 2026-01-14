#include "vtfs.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

#define MODULE_NAME "vtfs"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module");


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

struct vtfs_file_info* find_file_info(const char* name, ino_t parent_ino) {
    struct vtfs_file_info *file_info;
    
    list_for_each_entry(file_info, &vtfs_files, list) {
        if (strcmp(file_info->name, name) == 0 && file_info->exists) {
            return file_info;
        }
    }
    return NULL;
}

struct vtfs_file_info* create_file_info(const char* name, ino_t ino) {
    struct vtfs_file_info *file_info = kmalloc(sizeof(*file_info), GFP_KERNEL);
    if (!file_info) {
        return NULL;
    }
    
    strncpy(file_info->name, name, sizeof(file_info->name) - 1);
    file_info->name[sizeof(file_info->name) - 1] = '\0';
    file_info->ino = ino;
    file_info->exists = true;
    
    INIT_LIST_HEAD(&file_info->list);
    list_add(&file_info->list, &vtfs_files);
    
    return file_info;
}

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

int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                struct dentry *child_dentry, umode_t mode, bool b) {
    ino_t parent_ino = parent_inode->i_ino;
    const char *name = child_dentry->d_name.name;
    
    LOG("create called for: '%s' in directory %lu, mode=%o\n", 
        name, parent_ino, mode);
    
    if (parent_ino == 1000) {
        mutex_lock(&vtfs_files_lock);
        
        if (find_file_info(name, parent_ino)) {
            mutex_unlock(&vtfs_files_lock);
            LOG("File '%s' already exists\n", name);
            return -EEXIST;
        }
        
        int new_ino = next_ino++;
        struct inode *inode = vtfs_get_inode(
            parent_inode->i_sb, 
            parent_inode, 
            mode | 0777, 
            new_ino
        );
        
        if (!inode) {
            mutex_unlock(&vtfs_files_lock);
            LOG("Failed to create inode for '%s'\n", name);
            return -ENOMEM;
        }
        
        inode->i_fop = &vtfs_file_ops;
        
        if (!create_file_info(name, new_ino)) {
            iput(inode);
            mutex_unlock(&vtfs_files_lock);
            LOG("Failed to save file info for '%s'\n", name);
            return -ENOMEM;
        }
        
        if (!strcmp(name, "test.txt")) {
            file_mask |= 1;
        } else if (!strcmp(name, "new_file.txt")) {
            file_mask |= 2;
        }
        
        d_add(child_dentry, inode);
        
        mutex_unlock(&vtfs_files_lock);
        
        LOG("Created file '%s' with ino=%d, mask=0x%x\n", 
            name, new_ino, file_mask);
        return 0;
    }
    
    LOG("Can only create files in root directory\n");
    return -EPERM;
}

int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry) {
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;
    
    LOG("unlink called for: '%s' in directory %lu\n", name, parent_ino);
    
    if (parent_ino == 1000) {
        mutex_lock(&vtfs_files_lock);
        
        struct vtfs_file_info *file_info = find_file_info(name, parent_ino);
        if (file_info) {
            file_info->exists = false;
            
            if (!strcmp(name, "test.txt")) {
                file_mask &= ~1;
            } else if (!strcmp(name, "new_file.txt")) {
                file_mask &= ~2;
            }
            
            LOG("Unlinked file '%s', mask=0x%x\n", name, file_mask);
            mutex_unlock(&vtfs_files_lock);
            return 0;
        }
        
        mutex_unlock(&vtfs_files_lock);
        LOG("File '%s' not found\n", name);
        return -ENOENT;
    }
    
    return -EPERM;
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
