#include "vtfs.h"
#include "http.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module with RAM storage");

LIST_HEAD(vtfs_files);
int next_ino = 1001;
DEFINE_MUTEX(vtfs_files_lock);
static char vtfs_token[256] = {0};

static int vtfs_http_lookup(const char *name, ino_t parent_ino) {
    char response_buffer[512];
    char parent_ino_str[32];
    char encoded_name[256];
    
    sprintf(parent_ino_str, "%lu", parent_ino);
    encode(name, encoded_name);
    
    int64_t result = vtfs_http_call(vtfs_token, "lookup", response_buffer, sizeof(response_buffer), 
                                    3, "name", encoded_name, "parent_ino", parent_ino_str);
    return (int)result;
}

static int vtfs_http_create(const char *name, ino_t parent_ino) {
    char response_buffer[128];
    char parent_ino_str[32];
    char encoded_name[256];
    
    sprintf(parent_ino_str, "%lu", parent_ino);
    encode(name, encoded_name);
    
    int64_t result = vtfs_http_call(vtfs_token, "create", response_buffer, sizeof(response_buffer),
                                    2, "name", encoded_name, "parent_ino", parent_ino_str);
    return (int)result;
}

static int vtfs_http_mkdir(const char *name, ino_t parent_ino) {
    char response_buffer[128];
    char parent_ino_str[32];
    char encoded_name[256];
    
    sprintf(parent_ino_str, "%lu", parent_ino);
    encode(name, encoded_name);
    
    int64_t result = vtfs_http_call(vtfs_token, "mkdir", response_buffer, sizeof(response_buffer),
                                    2, "name", encoded_name, "parent_ino", parent_ino_str);
    return (int)result;
}

static int vtfs_http_unlink(const char *name, ino_t parent_ino) {
    char response_buffer[64];
    char parent_ino_str[32];
    char encoded_name[256];
    
    sprintf(parent_ino_str, "%lu", parent_ino);
    encode(name, encoded_name);
    
    int64_t result = vtfs_http_call(vtfs_token, "unlink", response_buffer, sizeof(response_buffer),
                                    2, "name", encoded_name, "parent_ino", parent_ino_str);
    return (int)result;
}

static int vtfs_http_rmdir(const char *name, ino_t parent_ino) {
    char response_buffer[64];
    char parent_ino_str[32];
    char encoded_name[256];
    
    sprintf(parent_ino_str, "%lu", parent_ino);
    encode(name, encoded_name);
    
    int64_t result = vtfs_http_call(vtfs_token, "rmdir", response_buffer, sizeof(response_buffer),
                                    2, "name", encoded_name, "parent_ino", parent_ino_str);
    return (int)result;
}

static int vtfs_load_files_from_db(void) {
    char *response_buffer = kmalloc(32768, GFP_KERNEL); // 32KB buffer
    if (!response_buffer) {
        return -ENOMEM;
    }
    
    int64_t result = vtfs_http_call(vtfs_token, "listall", response_buffer, 32768, 0);
    if (result != 0) {
        LOG("Failed to load files from database: %lld\n", result);
        kfree(response_buffer);
        return (int)result;
    }
    
    // Parse response: each line is "ino,parent_ino,name,type,size,symlink_target"
    char *line = response_buffer;
    char *next_line;
    int loaded_count = 0;
    int max_ino = 1000;
    
    while (line && *line) {
        next_line = strchr(line, '\n');
        if (next_line) {
            *next_line = '\0';
            next_line++;
        }
        
        if (strlen(line) == 0) {
            line = next_line;
            continue;
        }
        
        // Parse fields using strsep (kernel-compatible)
        char *ptr = line;
        char *ino_str = strsep(&ptr, ",");
        char *parent_ino_str = strsep(&ptr, ",");
        char *name = strsep(&ptr, ",");
        char *type_str = strsep(&ptr, ",");
        char *size_str = strsep(&ptr, ",");
        char *symlink_target = strsep(&ptr, ",");
        
        if (!ino_str || !parent_ino_str || !name || !type_str) {
            line = next_line;
            continue;
        }
        
        ino_t ino, parent_ino;
        if (kstrtoul(ino_str, 10, &ino) != 0 || kstrtoul(parent_ino_str, 10, &parent_ino) != 0) {
            line = next_line;
            continue;
        }
        
        // Skip root directory (already created)
        if (ino == VTFS_ROOT_INO) {
            line = next_line;
            continue;
        }
        
        // Create file info structure
        struct vtfs_file_info *file_info = kzalloc(sizeof(*file_info), GFP_KERNEL);
        if (!file_info) {
            LOG("Failed to allocate memory for file %s\n", name);
            line = next_line;
            continue;
        }
        
        strncpy(file_info->name, name, sizeof(file_info->name) - 1);
        file_info->name[sizeof(file_info->name) - 1] = '\0';
        file_info->ino = ino;
        file_info->parent_ino = parent_ino;
        file_info->is_dir = (type_str[0] == 'd');
        file_info->is_symlink = (type_str[0] == 'l');
        
        // Load file content from server for regular files
        if (!file_info->is_dir && !file_info->is_symlink && size_str && strlen(size_str) > 0) {
            unsigned long content_size;
            if (kstrtoul(size_str, 10, &content_size) == 0 && content_size > 0 && content_size < 4096) {
                char read_buffer[8192]; // 4KB data = 8KB hex
                char ino_str_read[32];
                char size_str_read[32];
                sprintf(ino_str_read, "%lu", ino);
                sprintf(size_str_read, "%lu", content_size);
                
                int64_t read_result = vtfs_http_call(vtfs_token, "readhex", read_buffer, sizeof(read_buffer),
                                                      3, "ino", ino_str_read, "offset", "0", "length", size_str_read);
                if (read_result == 0 && strlen(read_buffer) > 0) {
                    // Decode hex to binary
                    size_t hex_len = strlen(read_buffer);
                    size_t data_len = hex_len / 2;
                    
                    if (data_len > 0 && data_len <= content_size) {
                        file_info->content.data = kmalloc(data_len, GFP_KERNEL);
                        if (file_info->content.data) {
                            // Decode hex string
                            for (size_t i = 0; i < data_len; i++) {
                                char hex_byte[3] = {read_buffer[i*2], read_buffer[i*2+1], '\0'};
                                unsigned int byte_val;
                                if (kstrtouint(hex_byte, 16, &byte_val) == 0) {
                                    file_info->content.data[i] = (char)byte_val;
                                }
                            }
                            file_info->content.size = data_len;
                            file_info->content.allocated = data_len;
                            LOG("Loaded %zu bytes of content for file %s (hex-decoded)\n", data_len, name);
                        }
                    } else {
                        file_info->content.data = NULL;
                        file_info->content.size = 0;
                        file_info->content.allocated = 0;
                    }
                } else {
                    file_info->content.data = NULL;
                    file_info->content.size = 0;
                    file_info->content.allocated = 0;
                }
            } else {
                file_info->content.data = NULL;
                file_info->content.size = 0;
                file_info->content.allocated = 0;
            }
        } else {
            file_info->content.data = NULL;
            file_info->content.size = 0;
            file_info->content.allocated = 0;
        }
        
        if (file_info->is_symlink && symlink_target && strlen(symlink_target) > 0) {
            file_info->symlink_target = kstrdup(symlink_target, GFP_KERNEL);
        } else {
            file_info->symlink_target = NULL;
        }
        
        mutex_init(&file_info->lock);
        INIT_LIST_HEAD(&file_info->list);
        list_add_tail(&file_info->list, &vtfs_files);
        
        if ((int)ino > max_ino) {
            max_ino = (int)ino;
        }
        
        loaded_count++;
        line = next_line;
    }
    
    // Update next_ino to avoid conflicts
    if (max_ino >= next_ino) {
        next_ino = max_ino + 1;
    }
    
    LOG("Loaded %d files from database, next_ino=%d\n", loaded_count, next_ino);
    kfree(response_buffer);
    return 0;
}

struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
    .mkdir = vtfs_mkdir,
    .rmdir = vtfs_rmdir,
    .link = vtfs_link,
    .symlink = vtfs_symlink,
};

struct inode_operations vtfs_symlink_inode_ops = {
    .get_link = vtfs_get_link,
};

struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

struct file_operations vtfs_file_ops = {
    .read = vtfs_read,
    .write = vtfs_write, 
    .open = vtfs_open,   
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
    root_dir->is_symlink = false;
    root_dir->symlink_target = NULL;
    root_dir->content.data = NULL;
    root_dir->content.size = 0;
    root_dir->content.allocated = 0;
    mutex_init(&root_dir->lock);
    INIT_LIST_HEAD(&root_dir->list);
    list_add(&root_dir->list, &vtfs_files);
    LOG("Root directory initialized\n");
}
int vtfs_open(struct inode *inode, struct file *filp)
{
    struct vtfs_file_info *file_info = find_file_info(inode->i_ino);

    if (!file_info || file_info->is_dir)
        return -EINVAL;

    if (filp->f_flags & O_TRUNC) {
        mutex_lock(&file_info->lock);
        if (file_info->content.data) {
            kfree(file_info->content.data);
            file_info->content.data = NULL;
        }
        file_info->content.size = 0;
        file_info->content.allocated = 0;
        inode->i_size = 0;
        mutex_unlock(&file_info->lock);
        LOG("Truncated file inode %lu\n", inode->i_ino);
    }

    return 0;
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

static bool is_directory_empty(ino_t dir_ino) {
    struct vtfs_file_info* file_info;
    
    list_for_each_entry(file_info, &vtfs_files, list) {
        if(file_info->parent_ino == dir_ino) {
            if(strcmp(file_info->name, ".") != 0 && 
               strcmp(file_info->name, "..") != 0) {
                return false;
            }
        }
    }
    return true;
}

struct dentry* vtfs_lookup(struct inode* parent_inode, 
                          struct dentry* child_dentry, 
                          unsigned int flag) {
    const char* name = child_dentry->d_name.name;
    struct vtfs_file_info* file_info;

    file_info = find_file_in_dir(name, parent_inode->i_ino);
    if(file_info) {
        umode_t mode;
        if(file_info->is_symlink) {
            mode = S_IFLNK | 0777;
        } else if(file_info->is_dir) {
            mode = S_IFDIR | 0777;
        } else {
            mode = S_IFREG | 0777;
        }
        
        struct inode* inode = vtfs_get_inode(
            parent_inode->i_sb,
            NULL,
            mode,
            file_info->ino
        );
        if(inode) {
            if(file_info->is_symlink) {
                inode->i_op = &vtfs_symlink_inode_ops;
                inode->i_link = file_info->symlink_target;
            } else if(file_info->is_dir) {
                inode->i_fop = &vtfs_dir_ops;
                inode->i_op = &vtfs_inode_ops;
            } else {
                inode->i_fop = &vtfs_file_ops;
                inode->i_op = &vtfs_inode_ops;
            }
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
    new_file_info->is_symlink = false;
    new_file_info->symlink_target = NULL;
    new_file_info->content.data = NULL;
    new_file_info->content.size = 0;
    new_file_info->content.allocated = 0;
    mutex_init(&new_file_info->lock);
    INIT_LIST_HEAD(&new_file_info->list);
    list_add(&new_file_info->list, &vtfs_files);
    
    // Sync with backend server
    int http_result = vtfs_http_create(name, parent_inode->i_ino);
    if (http_result != 0) {
        LOG("Warning: Failed to sync file creation to server: %d\n", http_result);
    }

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
        if(file_info->is_dir) {
            mutex_unlock(&vtfs_files_lock);
            LOG("Cannot unlink directory '%s' with unlink\n", name);
            return -EPERM;
        }

        int link_count = 0;
        struct vtfs_file_info *temp_info;
        list_for_each_entry(temp_info, &vtfs_files, list) {
            if(temp_info->ino == file_info->ino) {
                link_count++;
            }
        }
        LOG("Link count for inode %lu is %d\n", file_info->ino, link_count);

        list_del(&file_info->list);

        if(link_count == 1) {
            // Sync deletion with backend server
            int http_result = vtfs_http_unlink(name, parent_inode->i_ino);
            if (http_result != 0) {
                LOG("Warning: Failed to sync file deletion to server: %d\n", http_result);
            }
            
            if(file_info->symlink_target) {
                kfree(file_info->symlink_target);
            }
            if(file_info->content.data) {
                kfree(file_info->content.data);
            }
            mutex_destroy(&file_info->lock);
            kfree(file_info);
            mutex_unlock(&vtfs_files_lock);
            LOG("Unlinked and deleted file '%s'\n", name);
            return 0;
        } else {
            mutex_unlock(&vtfs_files_lock);
            LOG("Unlinked file '%s', but not deleted due to existing links\n", name);
            return 0;
        }
    }
    mutex_unlock(&vtfs_files_lock);
    LOG("File '%s' not found for unlinking\n", name);
    return -ENOENT;
}

struct dentry* vtfs_mount(struct file_system_type *fs_type,
                         int flags, const char *token,
                         void *data) {
    strncpy(vtfs_token, token, sizeof(vtfs_token) - 1);
    vtfs_token[sizeof(vtfs_token) - 1] = '\0';
    
    char response_buffer[64];
    int64_t result = vtfs_http_call(token, "init", response_buffer, sizeof(response_buffer), 0);
    
    if (result != 0) {
        LOG("Failed to initialize filesystem on server: %lld\n", result);
    }
    
    // Load existing files from database
    int load_result = vtfs_load_files_from_db();
    if (load_result != 0) {
        LOG("Warning: Failed to load files from database: %d\n", load_result);
    }
    
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
            if(strcmp(file_info->name, ".") == 0 || 
               strcmp(file_info->name, "..") == 0) {
                continue;
            }
            
            if(count == ctx->pos) {
                unsigned char type;
                if(file_info->is_symlink) {
                    type = DT_LNK;
                } else if(file_info->is_dir) {
                    type = DT_DIR;
                } else {
                    type = DT_REG;
                }
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
        } else if(S_ISLNK(mode)) {
            inode->i_op = &vtfs_symlink_inode_ops;
        } else {
            inode->i_fop = &vtfs_file_ops;
            inode->i_op = &vtfs_inode_ops;
        }
    }

    return inode;
}

int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode,
                 struct dentry *child_dentry, umode_t mode) {
    const char *name = child_dentry->d_name.name;
    
    LOG("mkdir called for: '%s' in directory %lu, mode=%o\n", 
        name, parent_inode->i_ino, mode);

    mutex_lock(&vtfs_files_lock);
    
    if(find_file_in_dir(name, parent_inode->i_ino)) {
        mutex_unlock(&vtfs_files_lock);
        LOG("Directory '%s' already exists\n", name);
        return -EEXIST;
    }

    struct vtfs_file_info *new_dir_info = kmalloc(sizeof(*new_dir_info), GFP_KERNEL);
    if (!new_dir_info) {
        mutex_unlock(&vtfs_files_lock);
        LOG("Memory allocation failed for new directory '%s'\n", name);
        return -ENOMEM;
    }

    strncpy(new_dir_info->name, name, sizeof(new_dir_info->name)-1);
    new_dir_info->name[sizeof(new_dir_info->name)-1] = '\0';
    new_dir_info->ino = next_ino++;
    new_dir_info->parent_ino = parent_inode->i_ino;
    new_dir_info->is_dir = true;
    new_dir_info->is_symlink = false;
    new_dir_info->symlink_target = NULL;
    INIT_LIST_HEAD(&new_dir_info->list);
    list_add(&new_dir_info->list, &vtfs_files);
    
    // Sync with backend server
    int http_result = vtfs_http_mkdir(name, parent_inode->i_ino);
    if (http_result != 0) {
        LOG("Warning: Failed to sync directory creation to server: %d\n", http_result);
    }

    struct inode* inode = vtfs_get_inode(
        parent_inode->i_sb,
        NULL,
        S_IFDIR | 0777,
        new_dir_info->ino
    );
    if (!inode) {
        list_del(&new_dir_info->list);
        kfree(new_dir_info);
        mutex_unlock(&vtfs_files_lock);
        LOG("Failed to create inode for new directory '%s'\n", name);
        return -ENOMEM;
    }
    inode->i_fop = &vtfs_dir_ops;
    inode->i_op = &vtfs_inode_ops;
    d_add(child_dentry, inode);
    LOG("Created directory '%s' with inode %lu\n", name, new_dir_info->ino);
    mutex_unlock(&vtfs_files_lock);
    return 0;
}

int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry) {
    const char *name = child_dentry->d_name.name;
    
    LOG("rmdir called for: '%s' in directory %lu\n", 
        name, parent_inode->i_ino);
    
    mutex_lock(&vtfs_files_lock);
    struct vtfs_file_info *dir_info = find_file_in_dir(name, parent_inode->i_ino);
    if (dir_info) {
        if(!dir_info->is_dir) {
            mutex_unlock(&vtfs_files_lock);
            LOG("'%s' is not a directory\n", name);
            return -ENOTDIR;
        }

        if(!is_directory_empty(dir_info->ino)) {
            mutex_unlock(&vtfs_files_lock);
            LOG("Directory '%s' is not empty\n", name);
            return -ENOTEMPTY;
        }

        // Sync deletion with backend server
        int http_result = vtfs_http_rmdir(name, parent_inode->i_ino);
        if (http_result != 0) {
            LOG("Warning: Failed to sync directory deletion to server: %d\n", http_result);
        }

        if(dir_info->content.data) {
            kfree(dir_info->content.data);
        }
        mutex_destroy(&dir_info->lock);

        list_del(&dir_info->list);
        kfree(dir_info);
        mutex_unlock(&vtfs_files_lock);
        LOG("Removed directory '%s'\n", name);
        return 0;
    }
    mutex_unlock(&vtfs_files_lock);
    LOG("Directory '%s' not found for removal\n", name);
    return -ENOENT;
}

void vtfs_kill_sb(struct super_block* sb) {
  printk(KERN_INFO "vtfs super block is destroyed. Unmount successfully.\n");
}


ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset) {
    struct inode* inode = filp->f_inode;
    struct vtfs_file_info* file_info = find_file_info(inode->i_ino);
    ssize_t ret = -ENOENT;

    if(!file_info) {
        LOG("Read failed: file info not found for inode %lu\n", inode->i_ino);
        return ret;
    }
    mutex_lock(&file_info->lock);

    if(*offset >= file_info->content.size) {
        mutex_unlock(&file_info->lock);
        return 0; 
    }
    if (length > file_info->content.size - *offset)
      length = file_info->content.size - *offset;

    if(length > 0 && file_info->content.data){
      if(copy_to_user(buffer, file_info->content.data + *offset, length)) {
        mutex_unlock(&file_info->lock);
        LOG("Read failed: copy_to_user error for inode %lu\n", inode->i_ino);
        return -EFAULT;
    }
    *offset += length;
    ret = length;
    LOG("read %zu bytes from inode %lu at offset %lld\n", length, inode->i_ino, *offset - length);
    } else {
        ret = 0;
    }
    mutex_unlock(&file_info->lock);
    return ret;
}

ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset) {
    struct inode* inode = filp->f_inode;
    struct vtfs_file_info* file_info = find_file_info(inode->i_ino);
    ssize_t ret = -ENOENT;

    if(!file_info) {
        LOG("Write failed: file info not found for inode %lu\n", inode->i_ino);
        return ret;
    }
    mutex_lock(&file_info->lock);

    if(*offset + length > file_info->content.allocated){
      size_t required = *offset + length;
      size_t new_size = max_t(size_t, file_info->content.allocated * 2, required);

      if(new_size == 0) {
          new_size = PAGE_SIZE;
      }
      char* new_data = krealloc(file_info->content.data, new_size, GFP_KERNEL);
      if(!new_data) {
          mutex_unlock(&file_info->lock);
          LOG("Write failed: memory allocation error for inode %lu\n", inode->i_ino);
          return -ENOMEM;
    }

    if(new_size > file_info->content.allocated) {
        memset(new_data + file_info->content.allocated, 0, new_size - file_info->content.allocated);
    }

      file_info->content.data = new_data;
      file_info->content.allocated = new_size;
      LOG("Reallocated data buffer to %zu bytes for inode %lu\n", new_size, inode->i_ino);
    }

    char *tmp_buffer = kmalloc(length, GFP_KERNEL);
    if(!tmp_buffer) {
        mutex_unlock(&file_info->lock);
        LOG("Write failed: temporary buffer allocation error for inode %lu\n", inode->i_ino);
        return -ENOMEM;
    }
    if(copy_from_user(tmp_buffer, buffer, length)) {
        kfree(tmp_buffer);
        mutex_unlock(&file_info->lock);
        LOG("Write failed: copy_from_user error for inode %lu\n", inode->i_ino);
        return -EFAULT;
    }
    for(size_t i = 0; i < length; i++) {
        if((unsigned char)tmp_buffer[i]>127){
            kfree(tmp_buffer);
            mutex_unlock(&file_info->lock);
            LOG("Write failed: non-ASCII character detected for inode %lu\n", inode->i_ino);
            return -EINVAL;
        }
    }
    memcpy(file_info->content.data + *offset, tmp_buffer, length);
    kfree(tmp_buffer);

    if(*offset + length > file_info->content.size) {
        file_info->content.size = *offset + length;
    }
    *offset += length;
    ret = length;
    LOG("Wrote %zu bytes to inode %lu at offset %lld\n", length, inode->i_ino, *offset - length);
    
    // Sync content to server using hex encoding (for files < 500 bytes)
    if (file_info->content.size > 0 && file_info->content.size < 500) {
        char *hex_data = kmalloc(file_info->content.size * 2 + 1, GFP_KERNEL);
        if (hex_data) {
            for (size_t i = 0; i < file_info->content.size; i++) {
                sprintf(hex_data + i * 2, "%02x", (unsigned char)file_info->content.data[i]);
            }
            hex_data[file_info->content.size * 2] = '\0';
            
            char response_buffer[64];
            char ino_str[32];
            char offset_str[32];
            
            sprintf(ino_str, "%lu", inode->i_ino);
            sprintf(offset_str, "0");
            
            int64_t sync_result = vtfs_http_call(vtfs_token, "writehex", response_buffer, 
                                                  sizeof(response_buffer), 
                                                  3, "ino", ino_str, "offset", offset_str, "data", hex_data);
            if (sync_result != 0) {
                LOG("Warning: Failed to sync file content to server: %lld\n", sync_result);
            } else {
                LOG("Synced %zu bytes to server for inode %lu\n", file_info->content.size, inode->i_ino);
            }
            kfree(hex_data);
        }
    }
    
    mutex_unlock(&file_info->lock);
    return ret;
}

int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *dentry) {
   const char *new_name = dentry->d_name.name;
   struct inode *old_inode = old_dentry->d_inode;
   struct vtfs_file_info *old_file_info, *new_file_info;

    LOG("link called for: '%s' to '%s' in directory %lu\n", 
        old_dentry->d_name.name, new_name, parent_dir->i_ino);

    if(!S_ISREG(old_inode->i_mode)) {
        LOG("Link failed: only regular files can be linked\n");
        return -EPERM;
    }

    mutex_lock(&vtfs_files_lock);

    old_file_info = find_file_info(old_inode->i_ino);
    if(!old_file_info) {
        mutex_unlock(&vtfs_files_lock);
        LOG("Link failed: original file info not found for inode %lu\n", old_inode->i_ino);
        return -ENOENT;
    }
    if(find_file_in_dir(new_name, parent_dir->i_ino)) {
        mutex_unlock(&vtfs_files_lock);
        LOG("Link failed: target name '%s' already exists in directory %lu\n", 
            new_name, parent_dir->i_ino);
        return -EEXIST;
    }

    new_file_info = kzalloc(sizeof(*new_file_info), GFP_KERNEL);
    if(!new_file_info) {
        mutex_unlock(&vtfs_files_lock);
        LOG("Link failed: memory allocation error for new link '%s'\n", new_name);
        return -ENOMEM;
    }
    strncpy(new_file_info->name, new_name, sizeof(new_file_info->name)-1);
    new_file_info->name[sizeof(new_file_info->name)-1] = '\0';
    new_file_info->ino = old_file_info->ino;
    new_file_info->parent_ino = parent_dir->i_ino;
    new_file_info->is_dir = false;
    new_file_info->content = old_file_info->content;
    mutex_init(&new_file_info->lock);
    INIT_LIST_HEAD(&new_file_info->list);
    list_add(&new_file_info->list, &vtfs_files);

    ihold(old_inode);
    mutex_unlock(&vtfs_files_lock);

    struct inode* new_inode = vtfs_get_inode(
        parent_dir->i_sb,
        NULL,
        old_inode->i_mode,
        new_file_info->ino
    );
    if(!new_inode) {
        mutex_lock(&vtfs_files_lock);
        list_del(&new_file_info->list);
        kfree(new_file_info);
        mutex_unlock(&vtfs_files_lock);
        LOG("Link failed: inode creation error for new link '%s'\n", new_name);
        return -ENOMEM;
    }
    new_inode->i_fop = &vtfs_file_ops;
    new_inode->i_op = &vtfs_inode_ops;
    d_instantiate(dentry, new_inode);
    LOG("Created hard link '%s' to inode %lu in directory %lu\n",
        new_name, new_file_info->ino, parent_dir->i_ino);
    return 0;

}

int vtfs_symlink(struct mnt_idmap *idmap, struct inode *dir, 
                 struct dentry *dentry, const char *symname) {
    const char *name = dentry->d_name.name;
    
    LOG("symlink called: '%s' -> '%s' in directory %lu\n", 
        name, symname, dir->i_ino);

    mutex_lock(&vtfs_files_lock);
    
    if(find_file_in_dir(name, dir->i_ino)) {
        mutex_unlock(&vtfs_files_lock);
        LOG("Symlink failed: '%s' already exists\n", name);
        return -EEXIST;
    }

    struct vtfs_file_info *new_symlink = kmalloc(sizeof(*new_symlink), GFP_KERNEL);
    if (!new_symlink) {
        mutex_unlock(&vtfs_files_lock);
        LOG("Symlink failed: memory allocation error for '%s'\n", name);
        return -ENOMEM;
    }

    size_t target_len = strlen(symname) + 1;
    new_symlink->symlink_target = kmalloc(target_len, GFP_KERNEL);
    if (!new_symlink->symlink_target) {
        kfree(new_symlink);
        mutex_unlock(&vtfs_files_lock);
        LOG("Symlink failed: memory allocation error for target '%s'\n", symname);
        return -ENOMEM;
    }
    strcpy(new_symlink->symlink_target, symname);

    strncpy(new_symlink->name, name, sizeof(new_symlink->name)-1);
    new_symlink->name[sizeof(new_symlink->name)-1] = '\0';
    new_symlink->ino = next_ino++;
    new_symlink->parent_ino = dir->i_ino;
    new_symlink->is_dir = false;
    new_symlink->is_symlink = true;
    new_symlink->content.data = NULL;
    new_symlink->content.size = 0;
    new_symlink->content.allocated = 0;
    mutex_init(&new_symlink->lock);
    INIT_LIST_HEAD(&new_symlink->list);
    list_add(&new_symlink->list, &vtfs_files);

    struct inode* inode = vtfs_get_inode(
        dir->i_sb,
        NULL,
        S_IFLNK | 0777,
        new_symlink->ino
    );
    if (!inode) {
        list_del(&new_symlink->list);
        kfree(new_symlink->symlink_target);
        kfree(new_symlink);
        mutex_unlock(&vtfs_files_lock);
        LOG("Symlink failed: inode creation error for '%s'\n", name);
        return -ENOMEM;
    }
    
    inode->i_op = &vtfs_symlink_inode_ops;
    inode->i_link = new_symlink->symlink_target;
    inode->i_size = strlen(symname);
    
    d_add(dentry, inode);
    mutex_unlock(&vtfs_files_lock);
    
    LOG("Created symlink '%s' -> '%s' with inode %lu\n", 
        name, symname, new_symlink->ino);
    return 0;
}

const char *vtfs_get_link(struct dentry *dentry, struct inode *inode, 
                          struct delayed_call *done) {
    if (!inode) {
        return ERR_PTR(-ECHILD);
    }
    
    LOG("get_link called for inode %lu\n", inode->i_ino);
    
    if (inode->i_link) {
        LOG("Returning link target: %s\n", inode->i_link);
        return inode->i_link;
    }
    
    struct vtfs_file_info *file_info = find_file_info(inode->i_ino);
    if (file_info && file_info->is_symlink && file_info->symlink_target) {
        LOG("Found symlink target from file_info: %s\n", file_info->symlink_target);
        return file_info->symlink_target;
    }
    
    LOG("get_link failed: no target found for inode %lu\n", inode->i_ino);
    return ERR_PTR(-ENOENT);
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