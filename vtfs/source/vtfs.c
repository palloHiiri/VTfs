#include "vtfs.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module with RAM storage");

LIST_HEAD(vtfs_files);
int next_ino = 1001;
DEFINE_MUTEX(vtfs_files_lock);

struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
};

struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

struct file_operations vtfs_file_ops = {
    
};

struct file_system_type vtfs_fs_type = {
    .owner = THIS_MODULE,
    .name = "vtfs",
    .mount = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT,
};

static void init_root_directory(void) {
    struct vtfs_file_info* root_dir = kmalloc(sizeof(*root_dir), GFP_KERNEL);
    if(!root_dir) {
        LOG("Failed to allocate memory for root directory\n");
        return;
    }

    strcpy(root_dir->name, ".");
    root_dir->ino = VTFS_ROOT_INO;
    root_dir->parent_ino = VTFS_ROOT_INO;
    root_dir->is_dir = true;
    INIT_LIST_HEAD(&root_dir->list);
    list_add(&root_dir->list, &vtfs_files);
    LOG("Root directory initialized\n");
}

struct vtfs_file_info* find_file_info(ino_t ino) {
    struct vtfs_file_info *file_info;
    
    list_for_each_entry(file_info, &vtfs_files, list) {
        if(file_info->ino == ino) {
            return file_info;
        }
    }
    return NULL;
}

struct vtfs_file_info* find_file_in_dir(const char* name, ino_t parent_ino) {
    struct vtfs_file_info *file_info;
    
    list_for_each_entry(file_info, &vtfs_files, list) {
        if(file_info->parent_ino == parent_ino && 
           strcmp(file_info->name, name) == 0) {
            return file_info;
        }
    }
    return NULL;
}

struct dentry* vtfs_lookup(struct inode* parent_inode, 
                          struct dentry* child_dentry, 
                          unsigned int flag) {
    const char* name = child_dentry->d_name.name;
    struct vtfs_file_info* file_info;

    file_info = find_file_in_dir(name, parent_inode->i_ino);
    if(file_info) {
        struct inode* inode = vtfs_get_inode(
            parent_inode->i_sb,
            NULL,
            file_info->is_dir ? S_IFDIR | 0777 : S_IFREG | 0777,
            file_info->ino
        );
        if(inode) {
            inode->i_fop = file_info->is_dir ? &vtfs_dir_ops : &vtfs_file_ops;
            inode->i_op = &vtfs_inode_ops;
            d_add(child_dentry, inode);
            LOG("Lookup successful for '%s' in directory %lu\n", 
                name, parent_inode->i_ino);
        } else {
            LOG("Failed to create inode during lookup for '%s'\n", name);
        }
    } else {
        LOG("Lookup failed for '%s' in directory %lu\n", name, parent_inode->i_ino);
    }
    return NULL;
}

int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                struct dentry *child_dentry, umode_t mode, bool b) {
    const char *name = child_dentry->d_name.name;
    
    LOG("create called for: '%s' in directory %lu, mode=%o\n", 
        name, parent_inode->i_ino, mode);

    mutex_lock(&vtfs_files_lock);
    
    if(find_file_in_dir(name, parent_inode->i_ino)) {
        mutex_unlock(&vtfs_files_lock);
        LOG("File '%s' already exists\n", name);
        return -EEXIST;
    }

    struct vtfs_file_info *new_file_info = kmalloc(sizeof(*new_file_info), GFP_KERNEL);
    if (!new_file_info) {
        mutex_unlock(&vtfs_files_lock);
        LOG("Memory allocation failed for new file '%s'\n", name);
        return -ENOMEM;
    }

    strncpy(new_file_info->name, name, sizeof(new_file_info->name)-1);
    new_file_info->name[sizeof(new_file_info->name)-1] = '\0';
    new_file_info->ino = next_ino++;
    new_file_info->parent_ino = parent_inode->i_ino;
    new_file_info->is_dir = false;
    INIT_LIST_HEAD(&new_file_info->list);
    list_add(&new_file_info->list, &vtfs_files);

    struct inode* inode = vtfs_get_inode(
        parent_inode->i_sb,
        NULL,
        S_IFREG | 0777,
        new_file_info->ino
    );
    if (!inode) {
        list_del(&new_file_info->list);
        kfree(new_file_info);
        mutex_unlock(&vtfs_files_lock);
        LOG("Failed to create inode for new file '%s'\n", name);
        return -ENOMEM;
    }
    inode->i_fop = &vtfs_file_ops;
    inode->i_op = &vtfs_inode_ops;
    d_add(child_dentry, inode);
    LOG("Created file '%s' with inode %lu\n", name, new_file_info->ino);
    mutex_unlock(&vtfs_files_lock);
    return 0;
}

int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry) {
    const char *name = child_dentry->d_name.name;
    
    LOG("unlink called for: '%s' in directory %lu\n", 
        name, parent_inode->i_ino);
    
    mutex_lock(&vtfs_files_lock);
    struct vtfs_file_info *file_info = find_file_in_dir(name, parent_inode->i_ino);
    if (file_info) {
        list_del(&file_info->list);
        kfree(file_info);
        mutex_unlock(&vtfs_files_lock);
        LOG("Unlinked file '%s'\n", name);
        return 0;
    }
    mutex_unlock(&vtfs_files_lock);
    LOG("File '%s' not found for unlinking\n", name);
    return -ENOENT;
}

struct dentry* vtfs_mount(struct file_system_type *fs_type,
                         int flags, const char *token,
                         void *data) {
    struct dentry *ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
    if(ret == NULL) {
        LOG("Can't mount file system\n");
    } else {
        LOG("Mounted successfully with token: %s\n", token);
    }
    return ret;
}

int vtfs_iterate(struct file* filp, struct dir_context* ctx) {
    struct dentry* dentry = filp->f_path.dentry;
    struct inode* inode   = dentry->d_inode;
    ino_t ino             = inode->i_ino;

    if(ctx->pos < 0){
        return 0;
    }

    if(ctx->pos == 0) {
        if(!dir_emit(ctx, ".", 1, ino, DT_DIR)) {
            return 0;
        }
        ctx->pos++;
    }

    if(ctx->pos == 1) {
        struct vtfs_file_info* current_dir = find_file_info(ino);
        ino_t parent_ino = current_dir ? current_dir->parent_ino : VTFS_ROOT_INO;
        
        if(!dir_emit(ctx, "..", 2, parent_ino, DT_DIR)) {
            return 0;
        }
        ctx->pos++;
    }
    
    struct vtfs_file_info* file_info;
    int count = 2;

    list_for_each_entry(file_info, &vtfs_files, list) {
        if(file_info->parent_ino == ino) {
            if(count == ctx->pos) {
                unsigned char type = file_info->is_dir ? DT_DIR : DT_REG;
                if(!dir_emit(ctx, file_info->name, strlen(file_info->name), 
                           file_info->ino, type)) {
                    return 0;
                }
                ctx->pos++;
                return 0;
            }
            count++;
        }
    }
    return 0;
}

int vtfs_fill_super(struct super_block *sb, void *data, int silent) {
    struct inode* inode = vtfs_get_inode(sb, NULL, S_IFDIR|0777, VTFS_ROOT_INO);

    if (inode == NULL) {
        LOG("Can't create root inode\n");
        return -ENOMEM;
    }
    
    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_ops;

    sb->s_root = d_make_root(inode);
    if (sb->s_root == NULL) {
        iput(inode);
        LOG("Can't create root directory\n");
        return -ENOMEM;
    }
    LOG("Root directory created successfully\n");
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
        inode->i_mode = mode | 0777;
        i_uid_write(inode, 0);
        i_gid_write(inode, 0);
        inode->i_ino = i_ino;
        inode->__i_atime = inode->__i_mtime = inode->__i_ctime = current_time(inode);

        if(S_ISDIR(mode)) {
            inode->i_fop = &vtfs_dir_ops;
            inode->i_op = &vtfs_inode_ops;
        } else {
            inode->i_fop = &vtfs_file_ops;
            inode->i_op = &vtfs_inode_ops;
        }
    }

    return inode;
}

void vtfs_kill_sb(struct super_block* sb) {
    struct vtfs_file_info* file_info, *tmp;
    LOG("Unmounting VTFS filesystem\n");
    list_for_each_entry_safe(file_info, tmp, &vtfs_files, list) {
        list_del(&file_info->list);
        kfree(file_info);
    }
    kill_litter_super(sb);
    LOG("VTFS filesystem unmounted\n");
}

static int __init vtfs_init(void) {
    int ret = register_filesystem(&vtfs_fs_type);
    if (ret == 0) {
        LOG("VTFS registered successfully\n");
        init_root_directory();
    } else {
        LOG("Failed to register filesystem: %d\n", ret);
    }
    return ret;
}

static void __exit vtfs_exit(void) {
    int ret = unregister_filesystem(&vtfs_fs_type);
    if (ret == 0) {
        LOG("VTFS unregistered successfully\n");
    } else {
        LOG("Failed to unregister filesystem: %d\n", ret);
    }
}

module_init(vtfs_init);
module_exit(vtfs_exit);