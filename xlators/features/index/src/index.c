/*
  Copyright (c) 2012-2012 Gluster, Inc. <http://www.gluster.com>
  This file is part of GlusterFS.

  GlusterFS is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  GlusterFS is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "index.h"
#include "options.h"
#include "glusterfs3-xdr.h"

#define XATTROP_SUBDIR "xattrop"

call_stub_t *
__index_dequeue (struct list_head *callstubs)
{
        call_stub_t *stub = NULL;

        if (!list_empty (callstubs)) {
                stub = list_entry (callstubs->next, call_stub_t, list);
                list_del_init (&stub->list);
        }

        return stub;
}

inline static void
__index_enqueue (struct list_head *callstubs, call_stub_t *stub)
{
        list_add_tail (&stub->list, callstubs);
}

static void
worker_enqueue (xlator_t *this, call_stub_t *stub)
{
        index_priv_t    *priv = NULL;

        priv = this->private;
        pthread_mutex_lock (&priv->mutex);
        {
                __index_enqueue (&priv->callstubs, stub);
                pthread_cond_signal (&priv->cond);
        }
        pthread_mutex_unlock (&priv->mutex);
}

void *
index_worker (void *data)
{
        index_priv_t     *priv = NULL;
        xlator_t         *this = NULL;
        call_stub_t      *stub = NULL;
        int               ret = 0;

        THIS = data;
        this = data;
        priv = this->private;

        for (;;) {
                pthread_mutex_lock (&priv->mutex);
                {
                        while (list_empty (&priv->callstubs)) {
                                ret = pthread_cond_wait (&priv->cond,
                                                         &priv->mutex);
                        }

                        stub = __index_dequeue (&priv->callstubs);
                }
                pthread_mutex_unlock (&priv->mutex);

                if (stub) /* guard against spurious wakeups */
                        call_resume (stub);
        }

        return NULL;
}
int
__index_inode_ctx_get (inode_t *inode, xlator_t *this, index_inode_ctx_t **ctx)
{
        int               ret = 0;
        index_inode_ctx_t *ictx = NULL;
        uint64_t          tmpctx = 0;

        ret = __inode_ctx_get (inode, this, &tmpctx);
        if (!ret) {
                ictx = (index_inode_ctx_t*) (long) tmpctx;
                goto out;
        }
        ictx = GF_CALLOC (1, sizeof (*ictx), gf_index_inode_ctx_t);
        if (!ictx) {
                ret = -1;
                goto out;
        }

        INIT_LIST_HEAD (&ictx->callstubs);
        ret = __inode_ctx_put (inode, this, (uint64_t)ictx);
        if (ret) {
                GF_FREE (ictx);
                ictx = NULL;
                goto out;
        }
out:
        if (ictx)
                *ctx = ictx;
        return ret;
}

int
index_inode_ctx_get (inode_t *inode, xlator_t *this, index_inode_ctx_t **ctx)
{
        int               ret = 0;

        LOCK (&inode->lock);
        {
                ret = __index_inode_ctx_get (inode, this, ctx);
        }
        UNLOCK (&inode->lock);

        return ret;
}

static void
make_index_dir_path (char *base, const char *subdir,
                     char *index_dir, size_t len)
{
        snprintf (index_dir, len, "%s/%s", base, subdir);
}

int
index_dir_create (xlator_t *this, const char *subdir)
{
        int          ret = 0;
        struct       stat st = {0};
        char         fullpath[PATH_MAX] = {0};
        char         path[PATH_MAX] = {0};
        char         *dir = NULL;
        index_priv_t *priv = NULL;
        size_t       len = 0;
        size_t       pathlen = 0;

        priv = this->private;
        make_index_dir_path (priv->index_basepath, subdir, fullpath,
                             sizeof (fullpath));
        ret = stat (fullpath, &st);
        if (!ret) {
                if (!S_ISDIR (st.st_mode))
                        ret = -2;
                goto out;
        }

        pathlen = strlen (fullpath);
        if ((pathlen > 1) && fullpath[pathlen - 1] == '/')
                fullpath[pathlen - 1] = '\0';
        dir = strchr (fullpath, '/');
        while (dir) {
                dir = strchr (dir + 1, '/');
                if (dir)
                        len = pathlen - strlen (dir);
                else
                        len = pathlen;
                strncpy (path, fullpath, len);
                path[len] = '\0';
                ret = mkdir (path, 0600);
                if (ret && (errno != EEXIST))
                        goto out;
        }
        ret = 0;
out:
        if (ret == -1) {
                gf_log (this->name, GF_LOG_ERROR, "%s/%s: Failed to "
                        "create (%s)", priv->index_basepath, subdir,
                        strerror (errno));
        } else if (ret == -2) {
                gf_log (this->name, GF_LOG_ERROR, "%s/%s: Failed to create, "
                        "path exists, not a directory ", priv->index_basepath,
                        subdir);
        }
        return ret;
}

void
index_get_index (index_priv_t *priv, uuid_t index)
{
        LOCK (&priv->lock);
        {
                uuid_copy (index, priv->index);
        }
        UNLOCK (&priv->lock);
}

void
index_generate_index (index_priv_t *priv, uuid_t index)
{
        LOCK (&priv->lock);
        {
                //To prevent duplicate generates.
                //This method fails if number of contending threads is greater
                //than MAX_LINK count of the fs
                if (!uuid_compare (priv->index, index))
                        uuid_generate (priv->index);
                uuid_copy (index, priv->index);
        }
        UNLOCK (&priv->lock);
}

static void
make_index_path (char *base, const char *subdir, uuid_t index,
                 char *index_path, size_t len)
{
        make_index_dir_path (base, subdir, index_path, len);
        snprintf (index_path + strlen (index_path), len - strlen (index_path),
                  "/%s-%s", subdir, uuid_utoa (index));
}

static void
make_gfid_path (char *base, const char *subdir, uuid_t gfid,
                char *gfid_path, size_t len)
{
        make_index_dir_path (base, subdir, gfid_path, len);
        snprintf (gfid_path + strlen (gfid_path), len - strlen (gfid_path),
                  "/%s", uuid_utoa (gfid));
}

static void
make_file_path (char *base, const char *subdir, const char *filename,
                char *file_path, size_t len)
{
        make_index_dir_path (base, subdir, file_path, len);
        snprintf (file_path + strlen (file_path), len - strlen (file_path),
                  "/%s", filename);
}

static void
check_delete_stale_index_file (xlator_t *this, char *filename)
{
        int             ret = 0;
        struct stat     st = {0};
        char            filepath[PATH_MAX] = {0};
        index_priv_t    *priv = NULL;

        priv = this->private;
        make_file_path (priv->index_basepath, XATTROP_SUBDIR,
                        filename, filepath, sizeof (filepath));
        ret = stat (filepath, &st);
        if (!ret && st.st_nlink == 1)
                unlink (filepath);
}

static int
index_fill_readdir (fd_t *fd, DIR *dir, off_t off,
                    size_t size, gf_dirent_t *entries)
{
        off_t     in_case = -1;
        size_t    filled = 0;
        int       count = 0;
        char      entrybuf[sizeof(struct dirent) + 256 + 8];
        struct dirent  *entry          = NULL;
        int32_t              this_size      = -1;
        gf_dirent_t          *this_entry     = NULL;
        xlator_t             *this = NULL;

        this = THIS;
        if (!off) {
                rewinddir (dir);
        } else {
                seekdir (dir, off);
        }

        while (filled <= size) {
                in_case = telldir (dir);

                if (in_case == -1) {
                        gf_log (THIS->name, GF_LOG_ERROR,
                                "telldir failed on dir=%p: %s",
                                dir, strerror (errno));
                        goto out;
                }

                errno = 0;
                entry = NULL;
                readdir_r (dir, (struct dirent *)entrybuf, &entry);

                if (!entry) {
                        if (errno == EBADF) {
                                gf_log (THIS->name, GF_LOG_WARNING,
                                        "readdir failed on dir=%p: %s",
                                        dir, strerror (errno));
                                goto out;
                        }
                        break;
                }

                if (!strncmp (entry->d_name, XATTROP_SUBDIR"-",
                              strlen (XATTROP_SUBDIR"-"))) {
                        check_delete_stale_index_file (this, entry->d_name);
                        continue;
                }

                this_size = max (sizeof (gf_dirent_t),
                                 sizeof (gfs3_dirplist))
                        + strlen (entry->d_name) + 1;

                if (this_size + filled > size) {
                        seekdir (dir, in_case);
                        break;
                }

                this_entry = gf_dirent_for_name (entry->d_name);

                if (!this_entry) {
                        gf_log (THIS->name, GF_LOG_ERROR,
                                "could not create gf_dirent for entry %s: (%s)",
                                entry->d_name, strerror (errno));
                        goto out;
                }
                this_entry->d_off = telldir (dir);
                this_entry->d_ino = entry->d_ino;

                list_add_tail (&this_entry->list, &entries->list);

                filled += this_size;
                count ++;
        }

        if ((!readdir (dir) && (errno == 0)))
                /* Indicate EOF */
                errno = ENOENT;
out:
        return count;
}

int
index_add (xlator_t *this, uuid_t gfid, const char *subdir)
{
        int32_t           op_errno = 0;
        char              gfid_path[PATH_MAX] = {0};
        char              index_path[PATH_MAX] = {0};
        int               ret = 0;
        uuid_t            index = {0};
        index_priv_t      *priv = NULL;
        struct stat       st = {0};
        int               fd = 0;

        priv = this->private;
        GF_ASSERT_AND_GOTO_WITH_ERROR (this->name, !uuid_is_null (gfid),
                                       out, op_errno, EINVAL);

        make_gfid_path (priv->index_basepath, subdir, gfid,
                        gfid_path, sizeof (gfid_path));

        ret = stat (gfid_path, &st);
        if (!ret)
                goto out;
        index_get_index (priv, index);
        make_index_path (priv->index_basepath, subdir,
                         index, index_path, sizeof (index_path));
        ret = link (index_path, gfid_path);
        if (!ret || (errno == EEXIST))  {
                ret = 0;
                goto out;
        }

        op_errno = errno;
        if (op_errno == ENOENT) {
                ret = index_dir_create (this, subdir);
                if (ret)
                        goto out;
        } else if (op_errno == EMLINK) {
                index_generate_index (priv, index);
                make_index_path (priv->index_basepath, subdir,
                                 index, index_path, sizeof (index_path));
        } else {
                goto out;
        }

        fd = creat (index_path, 0);
        if ((fd < 0) && (errno != EEXIST)) {
                ret = -1;
                gf_log (this->name, GF_LOG_ERROR, "%s: Not able to "
                        "create index (%s)", uuid_utoa (gfid),
                        strerror (errno));
                goto out;
        }

        if (fd >= 0)
                close (fd);

        ret = link (index_path, gfid_path);
        if (ret && (errno != EEXIST)) {
                gf_log (this->name, GF_LOG_ERROR, "%s: Not able to "
                        "add to index (%s)", uuid_utoa (gfid),
                        strerror (errno));
                goto out;
        }

        ret = 0;
out:
        return ret;
}

int
index_del (xlator_t *this, uuid_t gfid, const char *subdir)
{
        int32_t      op_errno __attribute__((unused)) = 0;
        index_priv_t *priv = NULL;
        int          ret = 0;
        char         gfid_path[PATH_MAX] = {0};

        priv = this->private;
        GF_ASSERT_AND_GOTO_WITH_ERROR (this->name, !uuid_is_null (gfid),
                                       out, op_errno, EINVAL);
        make_gfid_path (priv->index_basepath, subdir, gfid,
                        gfid_path, sizeof (gfid_path));
        ret = unlink (gfid_path);
        if (ret && (errno != ENOENT)) {
                gf_log (this->name, GF_LOG_ERROR,
                        "%s: failed to delete from index (%s)",
                        gfid_path, strerror (errno));
                ret = -errno;
                goto out;
        }
        ret = 0;
out:
        return ret;
}

void
_xattrop_index_action (xlator_t *this, inode_t *inode,  dict_t *xattr)
{
        data_pair_t       *trav = NULL;
        gf_boolean_t      zero_xattr = _gf_true;
        index_inode_ctx_t *ctx = NULL;
        int               ret = 0;

        trav = xattr->members_list;
        while (trav && inode) {
                if (mem_0filled ((const char*)trav->value->data,
                                 trav->value->len)) {
                        zero_xattr = _gf_false;
                        break;
                }
                trav = trav->next;
        }
        ret = index_inode_ctx_get (inode, this, &ctx);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Not able to %s %s -> index",
                        zero_xattr?"add":"del", uuid_utoa (inode->gfid));
                goto out;
        }
        if (zero_xattr) {
                if (ctx->state == NOTIN)
                        goto out;
                ret = index_del (this, inode->gfid, XATTROP_SUBDIR);
                if (!ret)
                        ctx->state = NOTIN;
        } else {
                if (ctx->state == IN)
                        goto out;
                ret = index_add (this, inode->gfid, XATTROP_SUBDIR);
                if (!ret)
                        ctx->state = IN;
        }
out:
        return;
}

void
fop_xattrop_index_action (xlator_t *this, inode_t *inode, dict_t *xattr)
{
        _xattrop_index_action (this, inode, xattr);
}

void
fop_fxattrop_index_action (xlator_t *this, inode_t *inode, dict_t *xattr)
{
        _xattrop_index_action (this, inode, xattr);
}

inline gf_boolean_t
index_xattrop_track (loc_t *loc, gf_xattrop_flags_t flags, dict_t *dict)
{
        return (flags == GF_XATTROP_ADD_ARRAY);
}

inline gf_boolean_t
index_fxattrop_track (fd_t *fd, gf_xattrop_flags_t flags, dict_t *dict)
{
        return (flags == GF_XATTROP_ADD_ARRAY);
}

int
__index_fd_ctx_get (fd_t *fd, xlator_t *this, index_fd_ctx_t **ctx)
{
        int               ret = 0;
        index_fd_ctx_t    *fctx = NULL;
        uint64_t          tmpctx = 0;
        char              index_dir[PATH_MAX] = {0};
        index_priv_t      *priv = NULL;

        priv = this->private;
        if (uuid_compare (fd->inode->gfid, priv->xattrop_vgfid)) {
                ret = -EINVAL;
                goto out;
        }

        ret = __fd_ctx_get (fd, this, &tmpctx);
        if (!ret) {
                fctx = (index_fd_ctx_t*) (long) tmpctx;
                goto out;
        }

        fctx = GF_CALLOC (1, sizeof (*fctx), gf_index_fd_ctx_t);
        if (!fctx) {
                ret = -ENOMEM;
                goto out;
        }

        make_index_dir_path (priv->index_basepath, XATTROP_SUBDIR,
                             index_dir, sizeof (index_dir));
        fctx->dir = opendir (index_dir);
        if (!fctx->dir) {
                ret = -errno;
                GF_FREE (fctx);
                fctx = NULL;
                goto out;
        }

        ret = __fd_ctx_set (fd, this, (uint64_t)(long)fctx);
        if (ret) {
                GF_FREE (fctx);
                fctx = NULL;
                ret = -EINVAL;
                goto out;
        }
out:
        if (fctx)
                *ctx = fctx;
        return ret;
}

int
index_fd_ctx_get (fd_t *fd, xlator_t *this, index_fd_ctx_t **ctx)
{
        int     ret = 0;
        LOCK (&fd->lock);
        {
                ret = __index_fd_ctx_get (fd, this, ctx);
        }
        UNLOCK (&fd->lock);
        return ret;
}

//new - Not NULL means start a fop
//new - NULL means done processing the fop
void
index_queue_process (xlator_t *this, inode_t *inode, call_stub_t *new)
{
        call_stub_t       *stub = NULL;
        index_inode_ctx_t *ctx = NULL;
        int               ret = 0;
        call_frame_t      *frame = NULL;

        LOCK (&inode->lock);
        {
                ret = __index_inode_ctx_get (inode, this, &ctx);
                if (ret)
                        goto unlock;

                if (new) {
                        __index_enqueue (&ctx->callstubs, new);
                        new = NULL;
                } else {
                        ctx->processing = _gf_false;
                }

                if (!ctx->processing) {
                        stub = __index_dequeue (&ctx->callstubs);
                        if (stub)
                                ctx->processing = _gf_true;
                        else
                                ctx->processing = _gf_false;
                }
        }
unlock:
        UNLOCK (&inode->lock);

        if (ret && new) {
                frame = new->frame;
                if (new->fop == GF_FOP_XATTROP) {
                        INDEX_STACK_UNWIND (xattrop, frame, -1, ENOMEM,
                                            NULL, NULL);
                } else if (new->fop == GF_FOP_FXATTROP) {
                        INDEX_STACK_UNWIND (fxattrop, frame, -1, ENOMEM,
                                            NULL, NULL);
                }
                call_stub_destroy (new);
        } else if (stub) {
                call_resume (stub);
        }
        return;
}

int32_t
index_xattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, dict_t *xattr, dict_t *xdata)
{
        inode_t *inode = NULL;

        inode = inode_ref (frame->local);
        if (op_ret < 0)
                goto out;
        fop_xattrop_index_action (this, frame->local, xattr);
out:
        INDEX_STACK_UNWIND (xattrop, frame, op_ret, op_errno, xattr, xdata);
        index_queue_process (this, inode, NULL);
        inode_unref (inode);

        return 0;
}

int32_t
index_fxattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, dict_t *xattr,
                    dict_t *xdata)
{
        inode_t *inode = NULL;

        inode = inode_ref (frame->local);
        if (op_ret < 0)
                goto out;

        fop_fxattrop_index_action (this, frame->local, xattr);
out:
        INDEX_STACK_UNWIND (fxattrop, frame, op_ret, op_errno, xattr, xdata);
        index_queue_process (this, inode, NULL);
        inode_unref (inode);

        return 0;
}

int
index_xattrop_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                       gf_xattrop_flags_t optype, dict_t *xattr, dict_t *xdata)
{
        STACK_WIND (frame, index_xattrop_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->xattrop, loc, optype, xattr,
                    xdata);
        return 0;
}

int
index_fxattrop_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                        gf_xattrop_flags_t optype, dict_t *xattr, dict_t *xdata)
{
        STACK_WIND (frame, index_fxattrop_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->fxattrop, fd, optype, xattr,
                    xdata);
        return 0;
}

int32_t
index_xattrop (call_frame_t *frame, xlator_t *this, loc_t *loc,
	       gf_xattrop_flags_t flags, dict_t *dict, dict_t *xdata)
{
        call_stub_t     *stub = NULL;

        if (!index_xattrop_track (loc, flags, dict))
                goto out;

        frame->local = inode_ref (loc->inode);
        stub = fop_xattrop_stub (frame, index_xattrop_wrapper,
                                 loc, flags, dict, xdata);
        if (!stub) {
                INDEX_STACK_UNWIND (xattrop, frame, -1, ENOMEM, NULL, NULL);
                return 0;
        }

        index_queue_process (this, loc->inode, stub);
        return 0;
out:
        STACK_WIND (frame, default_xattrop_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->xattrop, loc, flags, dict, xdata);
        return 0;
}

int32_t
index_fxattrop (call_frame_t *frame, xlator_t *this, fd_t *fd,
		gf_xattrop_flags_t flags, dict_t *dict, dict_t *xdata)
{
        call_stub_t    *stub = NULL;

        if (!index_fxattrop_track (fd, flags, dict))
                goto out;

        frame->local = inode_ref (fd->inode);
        stub = fop_fxattrop_stub (frame, index_fxattrop_wrapper,
                                  fd, flags, dict, xdata);
        if (!stub) {
                INDEX_STACK_UNWIND (fxattrop, frame, -1, ENOMEM, NULL, xdata);
                return 0;
        }

        index_queue_process (this, fd->inode, stub);
        return 0;
out:
        STACK_WIND (frame, default_fxattrop_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fxattrop, fd, flags, dict, xdata);
        return 0;
}

int32_t
index_getxattr_wrapper (call_frame_t *frame, xlator_t *this,
                        loc_t *loc, const char *name, dict_t *xdata)
{
        index_priv_t    *priv = NULL;
        dict_t          *xattr = NULL;
        int             ret = 0;

        priv = this->private;

        xattr = dict_new ();
        if (!xattr) {
                ret = -ENOMEM;
                goto done;
        }

        ret = dict_set_static_bin (xattr, (char*)name, priv->xattrop_vgfid,
                                   sizeof (priv->xattrop_vgfid));
        if (ret) {
                ret = -ENOMEM;
                gf_log (THIS->name, GF_LOG_ERROR, "xattrop index "
                        "gfid set failed");
                goto done;
        }
done:
        if (ret)
                STACK_UNWIND_STRICT (getxattr, frame, -1, -ret, xattr, xdata);
        else
                STACK_UNWIND_STRICT (getxattr, frame, 0, 0, xattr, xdata);

        if (xattr)
                dict_unref (xattr);

        return 0;
}

int32_t
index_lookup_wrapper (call_frame_t *frame, xlator_t *this,
                      loc_t *loc, dict_t *xattr_req)
{
        index_priv_t    *priv = NULL;
        struct stat     lstatbuf = {0};
        int             ret = 0;
        int32_t         op_errno = EINVAL;
        int32_t         op_ret = -1;
        char            path[PATH_MAX] = {0};
        struct iatt     stbuf        = {0, };
        struct iatt     postparent = {0,};
        dict_t          *xattr = NULL;
        gf_boolean_t    is_dir = _gf_false;

        priv = this->private;

        VALIDATE_OR_GOTO (loc, done);
        if (!uuid_compare (loc->gfid, priv->xattrop_vgfid)) {
                make_index_dir_path (priv->index_basepath, XATTROP_SUBDIR,
                                     path, sizeof (path));
                is_dir = _gf_true;
        } else if (!uuid_compare (loc->pargfid, priv->xattrop_vgfid)) {
                make_file_path (priv->index_basepath, XATTROP_SUBDIR,
                                loc->name, path, sizeof (path));
        }

        ret = lstat (path, &lstatbuf);
        if (ret) {
                gf_log (this->name, GF_LOG_DEBUG, "Stat failed on index dir "
                        "(%s)", strerror (errno));
                op_errno = errno;
                goto done;
        } else if (!S_ISDIR (lstatbuf.st_mode) && is_dir) {
                gf_log (this->name, GF_LOG_DEBUG, "Stat failed on index dir, "
                        "not a directory");
                op_errno = ENOENT;
                goto done;
        }
        xattr = dict_new ();
        if (!xattr) {
                op_errno = ENOMEM;
                goto done;
        }

        iatt_from_stat (&stbuf, &lstatbuf);
        if (is_dir)
                uuid_copy (stbuf.ia_gfid, priv->xattrop_vgfid);
        else
                uuid_generate (stbuf.ia_gfid);
        stbuf.ia_ino = -1;
        op_ret = 0;
done:
        STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno,
                             loc->inode, &stbuf, xattr, &postparent);
        if (xattr)
                dict_unref (xattr);
        return 0;
}

int32_t
index_readdir_wrapper (call_frame_t *frame, xlator_t *this,
                       fd_t *fd, size_t size, off_t off, dict_t *xdata)
{
        index_fd_ctx_t       *fctx           = NULL;
        DIR                  *dir            = NULL;
        int                   ret            = -1;
        int32_t               op_ret         = -1;
        int32_t               op_errno       = 0;
        int                   count          = 0;
        gf_dirent_t           entries;

        INIT_LIST_HEAD (&entries.list);

        ret = index_fd_ctx_get (fd, this, &fctx);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -ret;
                goto done;
        }

        dir = fctx->dir;

        if (!dir) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dir is NULL for fd=%p", fd);
                op_errno = EINVAL;
                goto done;
        }

        count = index_fill_readdir (fd, dir, off, size, &entries);

        /* pick ENOENT to indicate EOF */
        op_errno = errno;
        op_ret = count;
done:
        STACK_UNWIND_STRICT (readdir, frame, op_ret, op_errno, &entries, xdata);
        gf_dirent_free (&entries);
        return 0;
}

int
index_unlink_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc, int flag,
                      dict_t *xdata)
{
        index_priv_t    *priv = NULL;
        int32_t         op_ret = 0;
        int32_t         op_errno = 0;
        int             ret = 0;
        struct  iatt    preparent = {0};
        struct  iatt    postparent = {0};
        char            index_dir[PATH_MAX] = {0};
        struct  stat    lstatbuf = {0};
        uuid_t          gfid = {0};

        priv = this->private;
        make_index_dir_path (priv->index_basepath, XATTROP_SUBDIR,
                             index_dir, sizeof (index_dir));
        ret = lstat (index_dir, &lstatbuf);
        if (ret < 0) {
                op_ret = -1;
                op_errno = errno;
                goto done;
        }

        iatt_from_stat (&preparent, &lstatbuf);
        uuid_copy (preparent.ia_gfid, priv->xattrop_vgfid);
        preparent.ia_ino = -1;
        uuid_parse (loc->name, gfid);
        ret = index_del (this, gfid, XATTROP_SUBDIR);
        if (ret < 0) {
                op_ret = -1;
                op_errno = -ret;
                goto done;
        }
        memset (&lstatbuf, 0, sizeof (lstatbuf));
        ret = lstat (index_dir, &lstatbuf);
        if (ret < 0) {
                op_ret = -1;
                op_errno = errno;
                goto done;
        }
        iatt_from_stat (&postparent, &lstatbuf);
        uuid_copy (postparent.ia_gfid, priv->xattrop_vgfid);
        postparent.ia_ino = -1;
done:
        INDEX_STACK_UNWIND (unlink, frame, op_ret, op_errno, &preparent,
                            &postparent, xdata);
        return 0;
}

int32_t
index_getxattr (call_frame_t *frame, xlator_t *this,
                loc_t *loc, const char *name, dict_t *xdata)
{
        call_stub_t     *stub = NULL;

        if (!name || strcmp (GF_XATTROP_INDEX_GFID, name))
                goto out;

        stub = fop_getxattr_stub (frame, index_getxattr_wrapper, loc, name,
                                  xdata);
        if (!stub) {
                STACK_UNWIND_STRICT (getxattr, frame, -1, ENOMEM, NULL, NULL);
                return 0;
        }
        worker_enqueue (this, stub);
        return 0;
out:
        STACK_WIND (frame, default_getxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->getxattr, loc, name, xdata);
        return 0;
}

int32_t
index_lookup (call_frame_t *frame, xlator_t *this,
              loc_t *loc, dict_t *xattr_req)
{
        call_stub_t     *stub = NULL;
        index_priv_t    *priv = NULL;

        priv = this->private;

        if (uuid_compare (loc->gfid, priv->xattrop_vgfid) &&
            uuid_compare (loc->pargfid, priv->xattrop_vgfid))
                goto normal;

        stub = fop_lookup_stub (frame, index_lookup_wrapper, loc, xattr_req);
        if (!stub) {
                STACK_UNWIND_STRICT (lookup, frame, -1, ENOMEM, loc->inode,
                                     NULL, NULL, NULL);
                return 0;
        }
        worker_enqueue (this, stub);
        return 0;
normal:
        STACK_WIND (frame, default_lookup_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->lookup, loc, xattr_req);

        return 0;
}

int32_t
index_readdir (call_frame_t *frame, xlator_t *this,
               fd_t *fd, size_t size, off_t off, dict_t *xdata)
{
        call_stub_t     *stub = NULL;
        index_priv_t    *priv = NULL;

        priv = this->private;
        if (uuid_compare (fd->inode->gfid, priv->xattrop_vgfid))
                goto out;
        stub = fop_readdir_stub (frame, index_readdir_wrapper, fd, size, off,
                                 xdata);
        if (!stub) {
                STACK_UNWIND_STRICT (readdir, frame, -1, ENOMEM, NULL, NULL);
                return 0;
        }
        worker_enqueue (this, stub);
        return 0;
out:
        STACK_WIND (frame, default_readdir_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->readdir, fd, size, off, xdata);
        return 0;
}

int
index_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc, int xflag,
              dict_t *xdata)
{
        call_stub_t     *stub = NULL;
        index_priv_t    *priv = NULL;

        priv = this->private;
        if (uuid_compare (loc->pargfid, priv->xattrop_vgfid))
                goto out;

        stub = fop_unlink_stub (frame, index_unlink_wrapper, loc, xflag, xdata);
        if (!stub) {
                STACK_UNWIND_STRICT (unlink, frame, -1, ENOMEM, NULL, NULL,
                                     NULL);
                return 0;
        }
        worker_enqueue (this, stub);
        return 0;
out:
        STACK_WIND (frame, default_unlink_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->unlink, loc, xflag, xdata);
        return 0;
}

int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        ret = xlator_mem_acct_init (this, gf_index_mt_end + 1);

        return ret;
}

int
init (xlator_t *this)
{
        int ret = -1;
        index_priv_t *priv = NULL;
        pthread_t thread;

	if (!this->children || this->children->next) {
		gf_log (this->name, GF_LOG_ERROR,
			"'index' not configured with exactly one child");
                goto out;
	}

	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
			"dangling volume. check volfile ");
	}

        priv = GF_CALLOC (1, sizeof (*priv), gf_index_mt_priv_t);
        if (!priv)
                goto out;

        LOCK_INIT (&priv->lock);
        if ((ret = pthread_cond_init(&priv->cond, NULL)) != 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "pthread_cond_init failed (%d)", ret);
                goto out;
        }

        if ((ret = pthread_mutex_init(&priv->mutex, NULL)) != 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "pthread_mutex_init failed (%d)", ret);
                goto out;
        }

        pthread_attr_init (&priv->w_attr);
        ret = pthread_attr_setstacksize (&priv->w_attr,
                                         INDEX_THREAD_STACK_SIZE);
        if (ret == EINVAL) {
                gf_log (this->name, GF_LOG_WARNING,
                        "Using default thread stack size");
        }
        GF_OPTION_INIT ("index-base", priv->index_basepath, path, out);
        uuid_generate (priv->index);
        uuid_generate (priv->xattrop_vgfid);
        INIT_LIST_HEAD (&priv->callstubs);

        this->private = priv;
        ret = pthread_create (&thread, &priv->w_attr, index_worker, this);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING, "Failed to create "
                        "worker thread, aborting");
                goto out;
        }
        ret = 0;
out:
        if (!this->private && priv)
                GF_FREE (priv);

        return ret;
}

void
fini (xlator_t *this)
{
        index_priv_t *priv = NULL;

        priv = this->private;
        if (!priv)
                goto out;
        this->private = NULL;
        LOCK_DESTROY (&priv->lock);
        GF_FREE (priv);
out:
        return;
}

int
index_forget (xlator_t *this, inode_t *inode)
{
        uint64_t tmp_cache = 0;
        if (!inode_ctx_del (inode, this, &tmp_cache))
                GF_FREE ((index_inode_ctx_t*) (long)tmp_cache);

        return 0;
}

int32_t
index_releasedir (xlator_t *this, fd_t *fd)
{
        index_fd_ctx_t *fctx = NULL;
        uint64_t        ctx = 0;
        int             ret = 0;

        ret = fd_ctx_del (fd, this, &ctx);
        if (ret < 0)
                goto out;

        fctx = (index_fd_ctx_t*) (long) ctx;
        if (fctx->dir)
                closedir (fctx->dir);

        GF_FREE (fctx);
out:
        return 0;
}

int32_t
index_release (xlator_t *this, fd_t *fd)
{
        index_fd_ctx_t *fctx = NULL;
        uint64_t        ctx = 0;
        int             ret = 0;

        ret = fd_ctx_del (fd, this, &ctx);
        if (ret < 0)
                goto out;

        fctx = (index_fd_ctx_t*) (long) ctx;
        GF_FREE (fctx);
out:
        return 0;
}

int
notify (xlator_t *this, int event, void *data, ...)
{
        int     ret = 0;
        ret = default_notify (this, event, data);
        return ret;
}

struct xlator_fops fops = {
	.xattrop     = index_xattrop,
	.fxattrop    = index_fxattrop,

        //interface functions follow
        .getxattr    = index_getxattr,
        .lookup      = index_lookup,
        .readdir     = index_readdir,
        .unlink      = index_unlink
};

struct xlator_dumpops dumpops = {
};

struct xlator_cbks cbks = {
        .forget         = index_forget,
        .release        = index_release,
        .releasedir     = index_releasedir
};

struct volume_options options[] = {
        { .key  = {"index-base" },
          .type = GF_OPTION_TYPE_PATH,
          .description = "path where the index files need to be stored",
        },
        { .key  = {NULL} },
};
