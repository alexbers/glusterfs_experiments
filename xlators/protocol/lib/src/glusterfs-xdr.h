/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _GLUSTERFS3_H_RPCGEN
#define _GLUSTERFS3_H_RPCGEN

#include <rpc/rpc.h>
#include "xdr-common.h"
#include "iatt.h"

#ifdef __cplusplus
extern "C" {
#endif


#define GF_O_ACCMODE           003
#define GF_O_RDONLY             00
#define GF_O_WRONLY             01
#define GF_O_RDWR               02
#define GF_O_CREAT            0100
#define GF_O_EXCL             0200
#define GF_O_NOCTTY           0400
#define GF_O_TRUNC           01000
#define GF_O_APPEND          02000
#define GF_O_NONBLOCK        04000
#define GF_O_SYNC           010000
#define GF_O_ASYNC          020000

#define GF_O_DIRECT         040000
#define GF_O_DIRECTORY     0200000
#define GF_O_NOFOLLOW      0400000
#define GF_O_NOATIME      01000000
#define GF_O_CLOEXEC      02000000

#define GF_O_LARGEFILE     0100000

#define XLATE_BIT(from, to, bit)    do {                \
                if (from & bit)                         \
                        to = to | GF_##bit;             \
        } while (0)

#define UNXLATE_BIT(from, to, bit)  do {                \
                if (from & GF_##bit)                    \
                        to = to | bit;                  \
        } while (0)

#define XLATE_ACCESSMODE(from, to) do {                 \
                switch (from & O_ACCMODE) {             \
                case O_RDONLY: to |= GF_O_RDONLY;       \
                        break;                          \
                case O_WRONLY: to |= GF_O_WRONLY;       \
                        break;                          \
                case O_RDWR: to |= GF_O_RDWR;           \
                        break;                          \
                }                                       \
        } while (0)

#define UNXLATE_ACCESSMODE(from, to) do {               \
                switch (from & GF_O_ACCMODE) {          \
                case GF_O_RDONLY: to |= O_RDONLY;       \
                        break;                          \
                case GF_O_WRONLY: to |= O_WRONLY;       \
                        break;                          \
                case GF_O_RDWR: to |= O_RDWR;           \
                        break;                          \
                }                                       \
        } while (0)

static inline uint32_t
gf_flags_from_flags (uint32_t flags)
{
        uint32_t gf_flags = 0;

        XLATE_ACCESSMODE (flags, gf_flags);

        XLATE_BIT (flags, gf_flags, O_CREAT);
        XLATE_BIT (flags, gf_flags, O_EXCL);
        XLATE_BIT (flags, gf_flags, O_NOCTTY);
        XLATE_BIT (flags, gf_flags, O_TRUNC);
        XLATE_BIT (flags, gf_flags, O_APPEND);
        XLATE_BIT (flags, gf_flags, O_NONBLOCK);
        XLATE_BIT (flags, gf_flags, O_SYNC);
        XLATE_BIT (flags, gf_flags, O_ASYNC);

        XLATE_BIT (flags, gf_flags, O_DIRECT);
        XLATE_BIT (flags, gf_flags, O_DIRECTORY);
        XLATE_BIT (flags, gf_flags, O_NOFOLLOW);
#ifdef O_NOATIME
        XLATE_BIT (flags, gf_flags, O_NOATIME);
#endif
#ifdef O_CLOEXEC
        XLATE_BIT (flags, gf_flags, O_CLOEXEC);
#endif
        XLATE_BIT (flags, gf_flags, O_LARGEFILE);

        return gf_flags;
}

static inline uint32_t
gf_flags_to_flags (uint32_t gf_flags)
{
        uint32_t flags = 0;

        UNXLATE_ACCESSMODE (gf_flags, flags);

        UNXLATE_BIT (gf_flags, flags, O_CREAT);
        UNXLATE_BIT (gf_flags, flags, O_EXCL);
        UNXLATE_BIT (gf_flags, flags, O_NOCTTY);
        UNXLATE_BIT (gf_flags, flags, O_TRUNC);
        UNXLATE_BIT (gf_flags, flags, O_APPEND);
        UNXLATE_BIT (gf_flags, flags, O_NONBLOCK);
        UNXLATE_BIT (gf_flags, flags, O_SYNC);
        UNXLATE_BIT (gf_flags, flags, O_ASYNC);

        UNXLATE_BIT (gf_flags, flags, O_DIRECT);
        UNXLATE_BIT (gf_flags, flags, O_DIRECTORY);
        UNXLATE_BIT (gf_flags, flags, O_NOFOLLOW);
#ifdef O_NOATIME
        UNXLATE_BIT (gf_flags, flags, O_NOATIME);
#endif
#ifdef O_CLOEXEC
        UNXLATE_BIT (gf_flags, flags, O_CLOEXEC);
#endif
        UNXLATE_BIT (gf_flags, flags, O_LARGEFILE);

        return flags;
}


struct gf_statfs {
	u_quad_t bsize;
	u_quad_t frsize;
	u_quad_t blocks;
	u_quad_t bfree;
	u_quad_t bavail;
	u_quad_t files;
	u_quad_t ffree;
	u_quad_t favail;
	u_quad_t fsid;
	u_quad_t flag;
	u_quad_t namemax;
};
typedef struct gf_statfs gf_statfs;

static inline void
gf_statfs_to_statfs (struct gf_statfs *gf_stat, struct statvfs *stat)
{
        if (!stat || !gf_stat)
                return;

	stat->f_bsize   =  (gf_stat->bsize);
	stat->f_frsize  =  (gf_stat->frsize);
	stat->f_blocks  =  (gf_stat->blocks);
	stat->f_bfree   =  (gf_stat->bfree);
	stat->f_bavail  =  (gf_stat->bavail);
	stat->f_files   =  (gf_stat->files);
	stat->f_ffree   =  (gf_stat->ffree);
	stat->f_favail  =  (gf_stat->favail);
	stat->f_fsid    =  (gf_stat->fsid);
	stat->f_flag    =  (gf_stat->flag);
	stat->f_namemax =  (gf_stat->namemax);
}


static inline void
gf_statfs_from_statfs (struct gf_statfs *gf_stat, struct statvfs *stat)
{
        if (!stat || !gf_stat)
                return;

	gf_stat->bsize   = stat->f_bsize;
	gf_stat->frsize  = stat->f_frsize;
	gf_stat->blocks  = stat->f_blocks;
	gf_stat->bfree   = stat->f_bfree;
	gf_stat->bavail  = stat->f_bavail;
	gf_stat->files   = stat->f_files;
	gf_stat->ffree   = stat->f_ffree;
	gf_stat->favail  = stat->f_favail;
	gf_stat->fsid    = stat->f_fsid;
	gf_stat->flag    = stat->f_flag;
	gf_stat->namemax = stat->f_namemax;
}

struct gf_flock {
	u_int type;
	u_int whence;
	u_quad_t start;
	u_quad_t len;
	u_int pid;
};
typedef struct gf_flock gf_flock;


static inline void
gf_flock_to_flock (struct gf_flock *gf_flock, struct flock *flock)
{
        if (!flock || !gf_flock)
                return;

	flock->l_type   = gf_flock->type;
	flock->l_whence = gf_flock->whence;
	flock->l_start  = gf_flock->start;
	flock->l_len    = gf_flock->len;
	flock->l_pid    = gf_flock->pid;
}


static inline void
gf_flock_from_flock (struct gf_flock *gf_flock, struct flock *flock)
{
        if (!flock || !gf_flock)
                return;

	gf_flock->type   =  (flock->l_type);
	gf_flock->whence =  (flock->l_whence);
	gf_flock->start  =  (flock->l_start);
	gf_flock->len    =  (flock->l_len);
	gf_flock->pid    =  (flock->l_pid);
}

struct gf_iatt {
	u_quad_t ia_ino;
	u_quad_t ia_gen;
	u_quad_t ia_dev;
	u_int mode;
	u_int ia_nlink;
	u_int ia_uid;
	u_int ia_gid;
	u_quad_t ia_rdev;
	u_quad_t ia_size;
	u_int ia_blksize;
	u_quad_t ia_blocks;
	u_int ia_atime;
	u_int ia_atime_nsec;
	u_int ia_mtime;
	u_int ia_mtime_nsec;
	u_int ia_ctime;
	u_int ia_ctime_nsec;
} __attribute__((packed));
typedef struct gf_iatt gf_iatt;


static inline void
gf_stat_to_iatt (struct gf_iatt *gf_stat, struct iatt *iatt)
{
        if (!iatt || !gf_stat)
                return;

	iatt->ia_ino = gf_stat->ia_ino ;
	iatt->ia_gen = gf_stat->ia_gen ;
	iatt->ia_dev = gf_stat->ia_dev ;
	iatt->ia_type = ia_type_from_st_mode (gf_stat->mode) ;
	iatt->ia_prot = ia_prot_from_st_mode (gf_stat->mode) ;
	iatt->ia_nlink = gf_stat->ia_nlink ;
	iatt->ia_uid = gf_stat->ia_uid ;
	iatt->ia_gid = gf_stat->ia_gid ;
	iatt->ia_rdev = gf_stat->ia_rdev ;
	iatt->ia_size = gf_stat->ia_size ;
	iatt->ia_blksize = gf_stat->ia_blksize ;
	iatt->ia_blocks = gf_stat->ia_blocks ;
	iatt->ia_atime = gf_stat->ia_atime ;
	iatt->ia_atime_nsec = gf_stat->ia_atime_nsec ;
	iatt->ia_mtime = gf_stat->ia_mtime ;
	iatt->ia_mtime_nsec = gf_stat->ia_mtime_nsec ;
	iatt->ia_ctime = gf_stat->ia_ctime ;
	iatt->ia_ctime_nsec = gf_stat->ia_ctime_nsec ;
}


static inline void
gf_stat_from_iatt (struct gf_iatt *gf_stat, struct iatt *iatt)
{
        if (!iatt || !gf_stat)
                return;

	gf_stat->ia_ino = iatt->ia_ino ;
	gf_stat->ia_gen = iatt->ia_gen ;
	gf_stat->ia_dev = iatt->ia_dev ;
	gf_stat->mode   = st_mode_from_ia (iatt->ia_prot, iatt->ia_type);
	gf_stat->ia_nlink = iatt->ia_nlink ;
	gf_stat->ia_uid = iatt->ia_uid ;
	gf_stat->ia_gid = iatt->ia_gid ;
	gf_stat->ia_rdev = iatt->ia_rdev ;
	gf_stat->ia_size = iatt->ia_size ;
	gf_stat->ia_blksize = iatt->ia_blksize ;
	gf_stat->ia_blocks = iatt->ia_blocks ;
	gf_stat->ia_atime = iatt->ia_atime ;
	gf_stat->ia_atime_nsec = iatt->ia_atime_nsec ;
	gf_stat->ia_mtime = iatt->ia_mtime ;
	gf_stat->ia_mtime_nsec = iatt->ia_mtime_nsec ;
	gf_stat->ia_ctime = iatt->ia_ctime ;
	gf_stat->ia_ctime_nsec = iatt->ia_ctime_nsec ;
}


/* Gluster FS Payload structures */

struct gfs3_stat_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	char *path;
};
typedef struct gfs3_stat_req gfs3_stat_req;

struct gfs3_stat_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
};
typedef struct gfs3_stat_rsp gfs3_stat_rsp;

struct gfs3_readlink_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int size;
	char *path;
};
typedef struct gfs3_readlink_req gfs3_readlink_req;

struct gfs3_readlink_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt buf;
	char *path;
};
typedef struct gfs3_readlink_rsp gfs3_readlink_rsp;

struct gfs3_mknod_req {
	u_quad_t gfs_id;
	u_quad_t par;
	u_quad_t gen;
	u_quad_t dev;
	u_int mode;
	char *path;
	char *bname;
};
typedef struct gfs3_mknod_req gfs3_mknod_req;

struct gfs3_mknod_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
	struct gf_iatt preparent;
	struct gf_iatt postparent;
};
typedef struct gfs3_mknod_rsp gfs3_mknod_rsp;

struct gfs3_mkdir_req {
	u_quad_t gfs_id;
	u_quad_t par;
	u_quad_t gen;
	u_int mode;
	char *path;
	char *bname;
};
typedef struct gfs3_mkdir_req gfs3_mkdir_req;

struct gfs3_mkdir_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
	struct gf_iatt preparent;
	struct gf_iatt postparent;
};
typedef struct gfs3_mkdir_rsp gfs3_mkdir_rsp;

struct gfs3_unlink_req {
	u_quad_t gfs_id;
	u_quad_t par;
	u_quad_t gen;
	char *path;
	char *bname;
};
typedef struct gfs3_unlink_req gfs3_unlink_req;

struct gfs3_unlink_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt preparent;
	struct gf_iatt postparent;
};
typedef struct gfs3_unlink_rsp gfs3_unlink_rsp;

struct gfs3_rmdir_req {
	u_quad_t gfs_id;
	u_quad_t par;
	u_quad_t gen;
	char *path;
	char *bname;
};
typedef struct gfs3_rmdir_req gfs3_rmdir_req;

struct gfs3_rmdir_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt preparent;
	struct gf_iatt postparent;
};
typedef struct gfs3_rmdir_rsp gfs3_rmdir_rsp;

struct gfs3_symlink_req {
	u_quad_t gfs_id;
	u_quad_t par;
	u_quad_t gen;
	char *path;
	char *bname;
	char *linkname;
};
typedef struct gfs3_symlink_req gfs3_symlink_req;

struct gfs3_symlink_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
	struct gf_iatt preparent;
	struct gf_iatt postparent;
};
typedef struct gfs3_symlink_rsp gfs3_symlink_rsp;

struct gfs3_rename_req {
	u_quad_t gfs_id;
	u_quad_t oldpar;
	u_quad_t oldgen;
	u_quad_t newpar;
	u_quad_t newgen;
	char *oldpath;
	char *oldbname;
	char *newpath;
	char *newbname;
};
typedef struct gfs3_rename_req gfs3_rename_req;

struct gfs3_rename_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
	struct gf_iatt preoldparent;
	struct gf_iatt postoldparent;
	struct gf_iatt prenewparent;
	struct gf_iatt postnewparent;
};
typedef struct gfs3_rename_rsp gfs3_rename_rsp;

struct gfs3_link_req {
	u_quad_t gfs_id;
	u_quad_t oldino;
	u_quad_t oldgen;
	u_quad_t newpar;
	u_quad_t newgen;
	char *oldpath;
	char *newpath;
	char *newbname;
};
typedef struct gfs3_link_req gfs3_link_req;

struct gfs3_link_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
	struct gf_iatt preparent;
	struct gf_iatt postparent;
};
typedef struct gfs3_link_rsp gfs3_link_rsp;

struct gfs3_truncate_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_quad_t offset;
	char *path;
};
typedef struct gfs3_truncate_req gfs3_truncate_req;

struct gfs3_truncate_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt prestat;
	struct gf_iatt poststat;
};
typedef struct gfs3_truncate_rsp gfs3_truncate_rsp;

struct gfs3_open_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int flags;
	u_int wbflags;
	char *path;
};
typedef struct gfs3_open_req gfs3_open_req;

struct gfs3_open_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	quad_t fd;
};
typedef struct gfs3_open_rsp gfs3_open_rsp;

struct gfs3_read_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_quad_t offset;
	u_int size;
};
typedef struct gfs3_read_req gfs3_read_req;

struct gfs3_read_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
        u_int size;
} __attribute__((packed));
typedef struct gfs3_read_rsp gfs3_read_rsp;

struct gfs3_lookup_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t par;
	u_quad_t gen;
	u_int flags;
	char *path;
	char *bname;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gfs3_lookup_req gfs3_lookup_req;

struct gfs3_lookup_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
	struct gf_iatt postparent;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gfs3_lookup_rsp gfs3_lookup_rsp;

struct gfs3_write_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_quad_t offset;
	u_int size;
} __attribute__((packed));
typedef struct gfs3_write_req gfs3_write_req;

struct gfs3_write_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt prestat;
	struct gf_iatt poststat;
};
typedef struct gfs3_write_rsp gfs3_write_rsp;

struct gfs3_statfs_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	char *path;
};
typedef struct gfs3_statfs_req gfs3_statfs_req;

struct gfs3_statfs_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_statfs statfs;
};
typedef struct gfs3_statfs_rsp gfs3_statfs_rsp;

struct gfs3_lk_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_int cmd;
	u_int type;
	struct gf_flock flock;
};
typedef struct gfs3_lk_req gfs3_lk_req;

struct gfs3_lk_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_flock flock;
};
typedef struct gfs3_lk_rsp gfs3_lk_rsp;

struct gfs3_inodelk_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int cmd;
	u_int type;
	struct gf_flock flock;
	char *path;
	char *volume;
};
typedef struct gfs3_inodelk_req gfs3_inodelk_req;

struct gfs3_finodelk_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_int cmd;
	u_int type;
	struct gf_flock flock;
	char *volume;
};
typedef struct gfs3_finodelk_req gfs3_finodelk_req;

struct gfs3_flush_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
};
typedef struct gfs3_flush_req gfs3_flush_req;

struct gfs3_fsync_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_int data;
};
typedef struct gfs3_fsync_req gfs3_fsync_req;

struct gfs3_fsync_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt prestat;
	struct gf_iatt poststat;
};
typedef struct gfs3_fsync_rsp gfs3_fsync_rsp;

struct gfs3_setxattr_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int flags;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
	char *path;
};
typedef struct gfs3_setxattr_req gfs3_setxattr_req;

struct gfs3_fsetxattr_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_int flags;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gfs3_fsetxattr_req gfs3_fsetxattr_req;

struct gfs3_xattrop_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int flags;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
	char *path;
};
typedef struct gfs3_xattrop_req gfs3_xattrop_req;

struct gfs3_xattrop_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gfs3_xattrop_rsp gfs3_xattrop_rsp;

struct gfs3_fxattrop_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_int flags;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gfs3_fxattrop_req gfs3_fxattrop_req;

struct gfs3_fxattrop_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gfs3_fxattrop_rsp gfs3_fxattrop_rsp;

struct gfs3_getxattr_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int namelen;
	char *path;
	char *name;
};
typedef struct gfs3_getxattr_req gfs3_getxattr_req;

struct gfs3_getxattr_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gfs3_getxattr_rsp gfs3_getxattr_rsp;

struct gfs3_fgetxattr_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_int namelen;
	char *name;
};
typedef struct gfs3_fgetxattr_req gfs3_fgetxattr_req;

struct gfs3_fgetxattr_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gfs3_fgetxattr_rsp gfs3_fgetxattr_rsp;

struct gfs3_removexattr_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	char *path;
	char *name;
};
typedef struct gfs3_removexattr_req gfs3_removexattr_req;

struct gfs3_opendir_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	char *path;
};
typedef struct gfs3_opendir_req gfs3_opendir_req;

struct gfs3_opendir_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	quad_t fd;
};
typedef struct gfs3_opendir_rsp gfs3_opendir_rsp;

struct gfs3_fsyncdir_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	int data;
};
typedef struct gfs3_fsyncdir_req gfs3_fsyncdir_req;

struct gfs3_readdir_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_quad_t offset;
	u_int size;
};
typedef struct gfs3_readdir_req gfs3_readdir_req;

struct gfs3_readdirp_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_quad_t offset;
	u_int size;
};
typedef struct gfs3_readdirp_req gfs3_readdirp_req;

struct gf_setvolume_req {
	u_quad_t gfs_id;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gf_setvolume_req gf_setvolume_req;

struct gf_setvolume_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct {
		u_int dict_len;
		char *dict_val;
	} dict;
};
typedef struct gf_setvolume_rsp gf_setvolume_rsp;

struct gfs3_access_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int mask;
	char *path;
};
typedef struct gfs3_access_req gfs3_access_req;

struct gfs3_create_req {
	u_quad_t gfs_id;
	u_quad_t par;
	u_quad_t gen;
	u_int flags;
	u_int mode;
	char *path;
	char *bname;
};
typedef struct gfs3_create_req gfs3_create_req;

struct gfs3_create_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
	u_quad_t fd;
	struct gf_iatt preparent;
	struct gf_iatt postparent;
};
typedef struct gfs3_create_rsp gfs3_create_rsp;

struct gfs3_ftruncate_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_quad_t offset;
};
typedef struct gfs3_ftruncate_req gfs3_ftruncate_req;

struct gfs3_ftruncate_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt prestat;
	struct gf_iatt poststat;
};
typedef struct gfs3_ftruncate_rsp gfs3_ftruncate_rsp;

struct gfs3_fstat_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
};
typedef struct gfs3_fstat_req gfs3_fstat_req;

struct gfs3_fstat_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt stat;
};
typedef struct gfs3_fstat_rsp gfs3_fstat_rsp;

struct gfs3_entrylk_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int cmd;
	u_int type;
	u_quad_t namelen;
	char *path;
	char *name;
	char *volume;
};
typedef struct gfs3_entrylk_req gfs3_entrylk_req;

struct gfs3_fentrylk_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
	u_int cmd;
	u_int type;
	u_quad_t namelen;
	char *name;
	char *volume;
};
typedef struct gfs3_fentrylk_req gfs3_fentrylk_req;

struct gfs3_checksum_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	u_int flag;
	char *path;
};
typedef struct gfs3_checksum_req gfs3_checksum_req;

struct gfs3_checksum_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct {
		u_int fchecksum_len;
		char *fchecksum_val;
	} fchecksum;
	struct {
		u_int dchecksum_len;
		char *dchecksum_val;
	} dchecksum;
};
typedef struct gfs3_checksum_rsp gfs3_checksum_rsp;

struct gfs3_setattr_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	struct gf_iatt stbuf;
	int valid;
	char *path;
};
typedef struct gfs3_setattr_req gfs3_setattr_req;

struct gfs3_setattr_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt statpre;
	struct gf_iatt statpost;
};
typedef struct gfs3_setattr_rsp gfs3_setattr_rsp;

struct gfs3_fsetattr_req {
	u_quad_t gfs_id;
	quad_t fd;
	struct gf_iatt stbuf;
	int valid;
};
typedef struct gfs3_fsetattr_req gfs3_fsetattr_req;

struct gfs3_fsetattr_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gf_iatt statpre;
	struct gf_iatt statpost;
};
typedef struct gfs3_fsetattr_rsp gfs3_fsetattr_rsp;

struct gfs3_rchecksum_req {
	u_quad_t gfs_id;
	quad_t fd;
	u_quad_t offset;
	u_int len;
};
typedef struct gfs3_rchecksum_req gfs3_rchecksum_req;

struct gfs3_rchecksum_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	u_int weak_checksum;
	struct {
		u_int strong_checksum_len;
		char *strong_checksum_val;
	} strong_checksum;
};
typedef struct gfs3_rchecksum_rsp gfs3_rchecksum_rsp;

struct gf_getspec_req {
	u_quad_t gfs_id;
	u_int flags;
	char *key;
};
typedef struct gf_getspec_req gf_getspec_req;

struct gf_getspec_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	char *spec;
};
typedef struct gf_getspec_rsp gf_getspec_rsp;

struct gf_log_req {
	u_quad_t gfs_id;
	struct {
		u_int msg_len;
		char *msg_val;
	} msg;
};
typedef struct gf_log_req gf_log_req;

struct gf_notify_req {
	u_quad_t gfs_id;
	u_int flags;
	char *buf;
};
typedef struct gf_notify_req gf_notify_req;

struct gf_notify_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	u_int flags;
	char *buf;
};
typedef struct gf_notify_rsp gf_notify_rsp;

struct gfs3_releasedir_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
};
typedef struct gfs3_releasedir_req gfs3_releasedir_req;

struct gfs3_release_req {
	u_quad_t gfs_id;
	u_quad_t ino;
	u_quad_t gen;
	quad_t fd;
};
typedef struct gfs3_release_req gfs3_release_req;

struct gf_common_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
};
typedef struct gf_common_rsp gf_common_rsp;

struct gf_dump_version_req {
	u_quad_t gfs_id;
        u_int  flags;
        char *key;
};
typedef struct gf_dump_version_req gf_dump_version_req;

struct gf_dump_version_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
        u_int flags;
	struct {
		u_int msg_len;
		char *msg_val;
	} msg;
};
typedef struct gf_dump_version_rsp gf_dump_version_rsp;

struct gfs3_dirlist {
	u_quad_t d_ino;
	u_quad_t d_off;
	u_int d_len;
	u_int d_type;
	char *name;
	struct gfs3_dirlist *nextentry;
};
typedef struct gfs3_dirlist gfs3_dirlist;

struct gfs3_readdir_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gfs3_dirlist *reply;
};
typedef struct gfs3_readdir_rsp gfs3_readdir_rsp;

struct gfs3_dirplist {
	u_quad_t d_ino;
	u_quad_t d_off;
	u_int d_len;
	u_int d_type;
	char *name;
	struct gf_iatt stat;
	struct gfs3_dirplist *nextentry;
};
typedef struct gfs3_dirplist gfs3_dirplist;

struct gfs3_readdirp_rsp {
	u_quad_t gfs_id;
	int op_ret;
	int op_errno;
	struct gfs3_dirplist *reply;
};
typedef struct gfs3_readdirp_rsp gfs3_readdirp_rsp;


/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_gf_statfs (XDR *, gf_statfs*);
extern  bool_t xdr_gf_flock (XDR *, gf_flock*);
extern  bool_t xdr_gf_iatt (XDR *, gf_iatt*);
extern  bool_t xdr_gfs3_stat_req (XDR *, gfs3_stat_req*);
extern  bool_t xdr_gfs3_stat_rsp (XDR *, gfs3_stat_rsp*);
extern  bool_t xdr_gfs3_readlink_req (XDR *, gfs3_readlink_req*);
extern  bool_t xdr_gfs3_readlink_rsp (XDR *, gfs3_readlink_rsp*);
extern  bool_t xdr_gfs3_mknod_req (XDR *, gfs3_mknod_req*);
extern  bool_t xdr_gfs3_mknod_rsp (XDR *, gfs3_mknod_rsp*);
extern  bool_t xdr_gfs3_mkdir_req (XDR *, gfs3_mkdir_req*);
extern  bool_t xdr_gfs3_mkdir_rsp (XDR *, gfs3_mkdir_rsp*);
extern  bool_t xdr_gfs3_unlink_req (XDR *, gfs3_unlink_req*);
extern  bool_t xdr_gfs3_unlink_rsp (XDR *, gfs3_unlink_rsp*);
extern  bool_t xdr_gfs3_rmdir_req (XDR *, gfs3_rmdir_req*);
extern  bool_t xdr_gfs3_rmdir_rsp (XDR *, gfs3_rmdir_rsp*);
extern  bool_t xdr_gfs3_symlink_req (XDR *, gfs3_symlink_req*);
extern  bool_t xdr_gfs3_symlink_rsp (XDR *, gfs3_symlink_rsp*);
extern  bool_t xdr_gfs3_rename_req (XDR *, gfs3_rename_req*);
extern  bool_t xdr_gfs3_rename_rsp (XDR *, gfs3_rename_rsp*);
extern  bool_t xdr_gfs3_link_req (XDR *, gfs3_link_req*);
extern  bool_t xdr_gfs3_link_rsp (XDR *, gfs3_link_rsp*);
extern  bool_t xdr_gfs3_truncate_req (XDR *, gfs3_truncate_req*);
extern  bool_t xdr_gfs3_truncate_rsp (XDR *, gfs3_truncate_rsp*);
extern  bool_t xdr_gfs3_open_req (XDR *, gfs3_open_req*);
extern  bool_t xdr_gfs3_open_rsp (XDR *, gfs3_open_rsp*);
extern  bool_t xdr_gfs3_read_req (XDR *, gfs3_read_req*);
extern  bool_t xdr_gfs3_read_rsp (XDR *, gfs3_read_rsp*);
extern  bool_t xdr_gfs3_lookup_req (XDR *, gfs3_lookup_req*);
extern  bool_t xdr_gfs3_lookup_rsp (XDR *, gfs3_lookup_rsp*);
extern  bool_t xdr_gfs3_write_req (XDR *, gfs3_write_req*);
extern  bool_t xdr_gfs3_write_rsp (XDR *, gfs3_write_rsp*);
extern  bool_t xdr_gfs3_statfs_req (XDR *, gfs3_statfs_req*);
extern  bool_t xdr_gfs3_statfs_rsp (XDR *, gfs3_statfs_rsp*);
extern  bool_t xdr_gfs3_lk_req (XDR *, gfs3_lk_req*);
extern  bool_t xdr_gfs3_lk_rsp (XDR *, gfs3_lk_rsp*);
extern  bool_t xdr_gfs3_inodelk_req (XDR *, gfs3_inodelk_req*);
extern  bool_t xdr_gfs3_finodelk_req (XDR *, gfs3_finodelk_req*);
extern  bool_t xdr_gfs3_flush_req (XDR *, gfs3_flush_req*);
extern  bool_t xdr_gfs3_fsync_req (XDR *, gfs3_fsync_req*);
extern  bool_t xdr_gfs3_fsync_rsp (XDR *, gfs3_fsync_rsp*);
extern  bool_t xdr_gfs3_setxattr_req (XDR *, gfs3_setxattr_req*);
extern  bool_t xdr_gfs3_fsetxattr_req (XDR *, gfs3_fsetxattr_req*);
extern  bool_t xdr_gfs3_xattrop_req (XDR *, gfs3_xattrop_req*);
extern  bool_t xdr_gfs3_xattrop_rsp (XDR *, gfs3_xattrop_rsp*);
extern  bool_t xdr_gfs3_fxattrop_req (XDR *, gfs3_fxattrop_req*);
extern  bool_t xdr_gfs3_fxattrop_rsp (XDR *, gfs3_fxattrop_rsp*);
extern  bool_t xdr_gfs3_getxattr_req (XDR *, gfs3_getxattr_req*);
extern  bool_t xdr_gfs3_getxattr_rsp (XDR *, gfs3_getxattr_rsp*);
extern  bool_t xdr_gfs3_fgetxattr_req (XDR *, gfs3_fgetxattr_req*);
extern  bool_t xdr_gfs3_fgetxattr_rsp (XDR *, gfs3_fgetxattr_rsp*);
extern  bool_t xdr_gfs3_removexattr_req (XDR *, gfs3_removexattr_req*);
extern  bool_t xdr_gfs3_opendir_req (XDR *, gfs3_opendir_req*);
extern  bool_t xdr_gfs3_opendir_rsp (XDR *, gfs3_opendir_rsp*);
extern  bool_t xdr_gfs3_fsyncdir_req (XDR *, gfs3_fsyncdir_req*);
extern  bool_t xdr_gfs3_readdir_req (XDR *, gfs3_readdir_req*);
extern  bool_t xdr_gfs3_dirlist (XDR *, gfs3_dirlist*);
extern  bool_t xdr_gfs3_readdir_rsp (XDR *, gfs3_readdir_rsp*);
extern  bool_t xdr_gfs3_dirplist (XDR *, gfs3_dirplist*);
extern  bool_t xdr_gfs3_readdirp_rsp (XDR *, gfs3_readdirp_rsp*);
extern  bool_t xdr_gfs3_readdirp_req (XDR *, gfs3_readdirp_req*);
extern  bool_t xdr_gf_setvolume_req (XDR *, gf_setvolume_req*);
extern  bool_t xdr_gf_setvolume_rsp (XDR *, gf_setvolume_rsp*);
extern  bool_t xdr_gfs3_access_req (XDR *, gfs3_access_req*);
extern  bool_t xdr_gfs3_create_req (XDR *, gfs3_create_req*);
extern  bool_t xdr_gfs3_create_rsp (XDR *, gfs3_create_rsp*);
extern  bool_t xdr_gfs3_ftruncate_req (XDR *, gfs3_ftruncate_req*);
extern  bool_t xdr_gfs3_ftruncate_rsp (XDR *, gfs3_ftruncate_rsp*);
extern  bool_t xdr_gfs3_fstat_req (XDR *, gfs3_fstat_req*);
extern  bool_t xdr_gfs3_fstat_rsp (XDR *, gfs3_fstat_rsp*);
extern  bool_t xdr_gfs3_entrylk_req (XDR *, gfs3_entrylk_req*);
extern  bool_t xdr_gfs3_fentrylk_req (XDR *, gfs3_fentrylk_req*);
extern  bool_t xdr_gfs3_checksum_req (XDR *, gfs3_checksum_req*);
extern  bool_t xdr_gfs3_checksum_rsp (XDR *, gfs3_checksum_rsp*);
extern  bool_t xdr_gfs3_setattr_req (XDR *, gfs3_setattr_req*);
extern  bool_t xdr_gfs3_setattr_rsp (XDR *, gfs3_setattr_rsp*);
extern  bool_t xdr_gfs3_fsetattr_req (XDR *, gfs3_fsetattr_req*);
extern  bool_t xdr_gfs3_fsetattr_rsp (XDR *, gfs3_fsetattr_rsp*);
extern  bool_t xdr_gfs3_rchecksum_req (XDR *, gfs3_rchecksum_req*);
extern  bool_t xdr_gfs3_rchecksum_rsp (XDR *, gfs3_rchecksum_rsp*);
extern  bool_t xdr_gf_getspec_req (XDR *, gf_getspec_req*);
extern  bool_t xdr_gf_getspec_rsp (XDR *, gf_getspec_rsp*);
extern  bool_t xdr_gf_log_req (XDR *, gf_log_req*);
extern  bool_t xdr_gf_notify_req (XDR *, gf_notify_req*);
extern  bool_t xdr_gf_notify_rsp (XDR *, gf_notify_rsp*);
extern  bool_t xdr_gfs3_releasedir_req (XDR *, gfs3_releasedir_req*);
extern  bool_t xdr_gfs3_release_req (XDR *, gfs3_release_req*);
extern  bool_t xdr_gf_common_rsp (XDR *, gf_common_rsp*);
extern  bool_t xdr_gf_dump_version_req (XDR *, gf_dump_version_req *);
extern  bool_t xdr_gf_dump_version_rsp (XDR *, gf_dump_version_rsp *);

#else /* K&R C */
extern bool_t xdr_gf_statfs ();
extern bool_t xdr_gf_flock ();
extern bool_t xdr_gf_iatt ();
extern bool_t xdr_gfs3_stat_req ();
extern bool_t xdr_gfs3_stat_rsp ();
extern bool_t xdr_gfs3_readlink_req ();
extern bool_t xdr_gfs3_readlink_rsp ();
extern bool_t xdr_gfs3_mknod_req ();
extern bool_t xdr_gfs3_mknod_rsp ();
extern bool_t xdr_gfs3_mkdir_req ();
extern bool_t xdr_gfs3_mkdir_rsp ();
extern bool_t xdr_gfs3_unlink_req ();
extern bool_t xdr_gfs3_unlink_rsp ();
extern bool_t xdr_gfs3_rmdir_req ();
extern bool_t xdr_gfs3_rmdir_rsp ();
extern bool_t xdr_gfs3_symlink_req ();
extern bool_t xdr_gfs3_symlink_rsp ();
extern bool_t xdr_gfs3_rename_req ();
extern bool_t xdr_gfs3_rename_rsp ();
extern bool_t xdr_gfs3_link_req ();
extern bool_t xdr_gfs3_link_rsp ();
extern bool_t xdr_gfs3_truncate_req ();
extern bool_t xdr_gfs3_truncate_rsp ();
extern bool_t xdr_gfs3_open_req ();
extern bool_t xdr_gfs3_open_rsp ();
extern bool_t xdr_gfs3_read_req ();
extern bool_t xdr_gfs3_read_rsp ();
extern bool_t xdr_gfs3_lookup_req ();
extern bool_t xdr_gfs3_lookup_rsp ();
extern bool_t xdr_gfs3_write_req ();
extern bool_t xdr_gfs3_write_rsp ();
extern bool_t xdr_gfs3_statfs_req ();
extern bool_t xdr_gfs3_statfs_rsp ();
extern bool_t xdr_gfs3_lk_req ();
extern bool_t xdr_gfs3_lk_rsp ();
extern bool_t xdr_gfs3_inodelk_req ();
extern bool_t xdr_gfs3_finodelk_req ();
extern bool_t xdr_gfs3_flush_req ();
extern bool_t xdr_gfs3_fsync_req ();
extern bool_t xdr_gfs3_fsync_rsp ();
extern bool_t xdr_gfs3_setxattr_req ();
extern bool_t xdr_gfs3_fsetxattr_req ();
extern bool_t xdr_gfs3_xattrop_req ();
extern bool_t xdr_gfs3_xattrop_rsp ();
extern bool_t xdr_gfs3_fxattrop_req ();
extern bool_t xdr_gfs3_fxattrop_rsp ();
extern bool_t xdr_gfs3_getxattr_req ();
extern bool_t xdr_gfs3_getxattr_rsp ();
extern bool_t xdr_gfs3_fgetxattr_req ();
extern bool_t xdr_gfs3_fgetxattr_rsp ();
extern bool_t xdr_gfs3_removexattr_req ();
extern bool_t xdr_gfs3_opendir_req ();
extern bool_t xdr_gfs3_opendir_rsp ();
extern bool_t xdr_gfs3_fsyncdir_req ();
extern bool_t xdr_gfs3_readdir_req ();
extern bool_t xdr_gfs3_dirlist ();
extern bool_t xdr_gfs3_readdir_rsp ();
extern bool_t xdr_gfs3_dirplist ();
extern bool_t xdr_gfs3_readdirp_rsp ();
extern bool_t xdr_gfs3_readdirp_req ();
extern bool_t xdr_gf_setvolume_req ();
extern bool_t xdr_gf_setvolume_rsp ();
extern bool_t xdr_gfs3_access_req ();
extern bool_t xdr_gfs3_create_req ();
extern bool_t xdr_gfs3_create_rsp ();
extern bool_t xdr_gfs3_ftruncate_req ();
extern bool_t xdr_gfs3_ftruncate_rsp ();
extern bool_t xdr_gfs3_fstat_req ();
extern bool_t xdr_gfs3_fstat_rsp ();
extern bool_t xdr_gfs3_entrylk_req ();
extern bool_t xdr_gfs3_fentrylk_req ();
extern bool_t xdr_gfs3_checksum_req ();
extern bool_t xdr_gfs3_checksum_rsp ();
extern bool_t xdr_gfs3_setattr_req ();
extern bool_t xdr_gfs3_setattr_rsp ();
extern bool_t xdr_gfs3_fsetattr_req ();
extern bool_t xdr_gfs3_fsetattr_rsp ();
extern bool_t xdr_gfs3_rchecksum_req ();
extern bool_t xdr_gfs3_rchecksum_rsp ();
extern bool_t xdr_gfs3_releasedir_req ();
extern bool_t xdr_gfs3_release_req ();
extern bool_t xdr_gf_getspec_req ();
extern bool_t xdr_gf_getspec_rsp ();
extern bool_t xdr_gf_log_req ();
extern bool_t xdr_gf_notify_req ();
extern bool_t xdr_gf_notify_rsp ();
extern bool_t xdr_gf_common_rsp ();
extern bool_t xdr_gf_dump_version_req ();
extern bool_t xdr_gf_dump_version_rsp ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_GLUSTERFS3_H_RPCGEN */