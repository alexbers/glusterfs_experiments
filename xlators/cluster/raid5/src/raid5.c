/*
  Copyright (c) 2007-2011 Gluster, Inc. <http://www.gluster.com>
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

/**
 * xlators/cluster/stripe:
 *    Stripe translator, stripes the data across its child nodes,
 *    as per the options given in the volfile. The striping works
 *    fairly simple. It writes files at different offset as per
 *    calculation. So, 'ls -l' output at the real posix level will
 *    show file size bigger than the actual size. But when one does
 *    'df' or 'du <file>', real size of the file on the server is shown.
 *
 * WARNING:
 *  Stripe translator can't regenerate data if a child node gets disconnected.
 *  So, no 'self-heal' for stripe. Hence the advice, use stripe only when its
 *  very much necessary, or else, use it in combination with AFR, to have a
 *  backup copy.
 */
//#include <attr/attributes.h>
#include <fnmatch.h>

#include "raid5.h"
#include "libxlator.h"
#include "byte-order.h"
#include "statedump.h"

#define ATTR_ROOT       0x0002

struct volume_options options[];

/*
 *  Raid5 helpers
 */

/*
 *  Gets checksum block num by blocknum
 */
int32_t get_checksum_block_num(int32_t blocknum, int32_t totalblocks) {
 int32_t linenum = blocknum/totalblocks;
 int32_t offset_from_left=(totalblocks-linenum%totalblocks) - 1;

 return linenum * totalblocks + offset_from_left;
}
 
/*
 * Get physical block num by logical one
 */

int32_t get_phys_block_num(int32_t blocknum, int32_t totalblocks) {
 int32_t ret = 0;

 int32_t linenum = blocknum/(totalblocks-1);
 int32_t check_offset_from_left=(totalblocks-linenum%totalblocks) - 1;

 ret = blocknum;
 ret += blocknum / (totalblocks - 1) ;

 if (check_offset_from_left <= blocknum % (totalblocks -1 ))
  ret +=1;

 return ret;
}

int32_t is_checksum_block(int32_t blocknum, int32_t totalblocks) {
        return blocknum==get_checksum_block_num(blocknum,totalblocks);
}

/*
 * xors two arrays and put the result into third array
 */
void xor_data(char *dest, char *src_1, char *src_2, size_t size) {
        size_t off = 0;
        for(off=0; off<size; off++)
                dest[off]=src_1[off] ^ src_2[off];
}

/*
 * xors three arrays and put the result into third array
 */
void xor_data_with(char *dest, char *src_1, char *src_2, size_t size) {
        size_t off = 0;
        for(off=0; off<size; off++)
                dest[off]^=src_1[off] ^ src_2[off];
}

//void
//bay_debug_dict (dict_t *this, char *key, data_t *value, void *data) {
//        gf_log ("stripe", GF_LOG_WARNING, "debugdict %s", key);
//        return;
//}


 
void
stripe_local_wipe (stripe_local_t *local)
{
        if (!local)
                goto out;

        loc_wipe (&local->loc);
        loc_wipe (&local->loc2);

        if (local->fd)
                fd_unref (local->fd);

        if (local->inode)
                inode_unref (local->inode);

        if (local->xattr)
                dict_unref (local->xattr);

        if (local->xdata)
                dict_unref (local->xdata);

out:
        return;
}

/**
 * stripe_get_matching_bs - Get the matching block size for the given path.
 */
int32_t
stripe_get_matching_bs (const char *path, struct stripe_options *opts,
                        uint64_t default_bs)
{
        struct stripe_options *trav       = NULL;
        char                  *pathname   = NULL;
        uint64_t               block_size = 0;

        block_size = default_bs;

        if (!path || !opts)
                goto out;

        /* FIXME: is a strdup really necessary? */
        pathname = gf_strdup (path);
        if (!pathname)
                goto out;

        trav = opts;
        while (trav) {
                if (!fnmatch (trav->path_pattern, pathname, FNM_NOESCAPE)) {
                        block_size = trav->block_size;
                        break;
                }
                trav = trav->next;
        }

        GF_FREE (pathname);

out:
        return block_size;
}

int32_t
stripe_ctx_handle (xlator_t *this, call_frame_t *prev, stripe_local_t *local,
                   dict_t *dict)
{
        char            key[256]       = {0,};
        data_t         *data            = NULL;
        int32_t         index           = 0;
        stripe_private_t *priv          = NULL;
        int32_t         ret             = -1;

        priv = this->private;


        if (!local->fctx) {
                local->fctx =  GF_CALLOC (1, sizeof (stripe_fd_ctx_t),
                                         gf_stripe_mt_stripe_fd_ctx_t);
                if (!local->fctx) {
                        local->op_errno = ENOMEM;
                        local->op_ret = -1;
                        goto out;
                }

                local->fctx->static_array = 0;
        }
        /* Stripe block size */
        sprintf (key, "trusted.%s.stripe-size", this->name);
        data = dict_get (dict, key);
        if (!data) {
                local->xattr_self_heal_needed = 1;
                gf_log (this->name, GF_LOG_ERROR,
                        "Failed to get stripe-size");
                goto out;
        } else {
                if (!local->fctx->stripe_size) {
                        local->fctx->stripe_size =
                                     data_to_int64 (data);
                }

                if (local->fctx->stripe_size != data_to_int64 (data)) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "stripe-size mismatch in blocks");
                        local->xattr_self_heal_needed = 1;
                }
        }

        /* Stripe count */
        sprintf (key, "trusted.%s.stripe-count", this->name);
        data = dict_get (dict, key);

        if (!data) {
                local->xattr_self_heal_needed = 1;
                gf_log (this->name, GF_LOG_ERROR,
                        "Failed to get stripe-count");
                goto out;
        }
        if (!local->fctx->xl_array) {
                local->fctx->stripe_count = data_to_int32 (data);
                if (!local->fctx->stripe_count) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "error with stripe-count xattr");
                        local->op_ret   = -1;
                        local->op_errno = EIO;
                        goto out;
                }

                local->fctx->xl_array = GF_CALLOC (local->fctx->stripe_count,
                                                   sizeof (xlator_t *),
                                                   gf_stripe_mt_xlator_t);

                if (!local->fctx->xl_array) {
                        local->op_errno = ENOMEM;
                        local->op_ret   = -1;
                        goto out;
                }
        }
        if (local->fctx->stripe_count != data_to_int32 (data)) {
                gf_log (this->name, GF_LOG_ERROR,
                        "error with stripe-count xattr (%d != %d)",
                        local->fctx->stripe_count, data_to_int32 (data));
                local->op_ret   = -1;
                local->op_errno = EIO;
                goto out;
        }

        /* index */
        sprintf (key, "trusted.%s.stripe-index", this->name);
        data = dict_get (dict, key);
        if (!data) {
                local->xattr_self_heal_needed = 1;
                gf_log (this->name, GF_LOG_ERROR,
                        "Failed to get stripe-index");
                goto out;
        }
        index = data_to_int32 (data);
        if (index > priv->child_count) {
                gf_log (this->name, GF_LOG_ERROR,
                        "error with stripe-index xattr (%d)", index);
                local->op_ret   = -1;
                local->op_errno = EIO;
                goto out;
        }
        if (local->fctx->xl_array) {
                if (!local->fctx->xl_array[index])
                        local->fctx->xl_array[index] = prev->this;
        }
        ret = 0;
out:
        return ret;
}

int32_t
stripe_sh_chown_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno,
                     struct iatt *preop, struct iatt *postop, dict_t *xdata)
{
        int             callcnt = -1;
        stripe_local_t *local   = NULL;

        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                STRIPE_STACK_DESTROY (frame);
        }
out:
        return 0;
}

int32_t
stripe_sh_make_entry_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                          int32_t op_ret, int32_t op_errno, inode_t *inode,
                          struct iatt *buf, struct iatt *preparent,
                          struct iatt *postparent, dict_t *xdata)
{
        stripe_local_t *local = NULL;
        call_frame_t    *prev = NULL;

        if (!frame || !frame->local || !cookie || !this) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        STACK_WIND (frame, stripe_sh_chown_cbk, prev->this,
                    prev->this->fops->setattr, &local->loc,
                    &local->stbuf, (GF_SET_ATTR_UID | GF_SET_ATTR_GID), NULL);

out:
        return 0;
}

int32_t
stripe_entry_self_heal (call_frame_t *frame, xlator_t *this,
                        stripe_local_t *local)
{
        xlator_list_t    *trav   = NULL;
        call_frame_t     *rframe = NULL;
        stripe_local_t   *rlocal = NULL;
        stripe_private_t *priv   = NULL;
        dict_t           *xdata   = NULL;
        int               ret    = 0;

        if (!local || !this || !frame) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        if (!(IA_ISREG (local->stbuf.ia_type) ||
              IA_ISDIR (local->stbuf.ia_type)))
                return 0;

        priv = this->private;
        trav = this->children;
        rframe = copy_frame (frame);
        if (!rframe) {
                goto out;
        }
        rlocal = GF_CALLOC (1, sizeof (stripe_local_t),
                            gf_stripe_mt_stripe_local_t);
        if (!rlocal) {
                goto out;
        }
        rframe->local = rlocal;
        rlocal->call_count = priv->child_count;
        loc_copy (&rlocal->loc, &local->loc);
        memcpy (&rlocal->stbuf, &local->stbuf, sizeof (struct iatt));

        xdata = dict_new ();
        if (!xdata)
                goto out;

        ret = dict_set_static_bin (xdata, "gfid-req", local->stbuf.ia_gfid, 16);
        if (ret)
                gf_log (this->name, GF_LOG_WARNING,
                        "%s: failed to set gfid-req", local->loc.path);

        while (trav) {
                if (IA_ISREG (local->stbuf.ia_type)) {
                        STACK_WIND (rframe, stripe_sh_make_entry_cbk,
                                    trav->xlator, trav->xlator->fops->mknod,
                                    &local->loc,
                                    st_mode_from_ia (local->stbuf.ia_prot,
                                                     local->stbuf.ia_type), 
                                    0,0,xdata);
                }
                if (IA_ISDIR (local->stbuf.ia_type)) {
                        STACK_WIND (rframe, stripe_sh_make_entry_cbk,
                                    trav->xlator, trav->xlator->fops->mkdir,
                                    &local->loc, st_mode_from_ia (local->stbuf.ia_prot,
                                                                  local->stbuf.ia_type),
                                    0,xdata);
                }
                trav = trav->next;
        }

        if (xdata)
                dict_unref (xdata);
        return 0;

out:
        if (rframe)
                STRIPE_STACK_DESTROY (rframe);
        if (xdata)
                dict_unref (xdata);

        return 0;
}


void
stripe_aggregate (dict_t *this, char *key, data_t *value, void *data)
{
        dict_t  *dst  = NULL;
        int64_t *ptr  = 0, *size = NULL;
        int32_t  ret  = -1;

        dst = data;

        if (strcmp (key, GF_XATTR_QUOTA_SIZE_KEY) == 0) {
                ret = dict_get_bin (dst, key, (void **)&size);
                if (ret < 0) {
                        size = GF_CALLOC (1, sizeof (int64_t),
                                          gf_common_mt_char);
                        if (size == NULL) {
                                gf_log ("stripe", GF_LOG_WARNING,
                                        "memory allocation failed");
                                goto out;
                        }
                        ret = dict_set_bin (dst, key, size, sizeof (int64_t));
                        if (ret < 0) {
                                gf_log ("stripe", GF_LOG_WARNING,
                                        "stripe aggregate dict set failed");
                                GF_FREE (size);
                                goto out;
                        }
                }

                ptr = data_to_bin (value);
                if (ptr == NULL) {
                        gf_log ("stripe", GF_LOG_WARNING, "data to bin failed");
                        goto out;
                }

                *size = hton64 (ntoh64 (*size) + ntoh64 (*ptr));
        } else if (strcmp (key, GF_CONTENT_KEY)) {
                /* No need to aggregate 'CONTENT' data */
                ret = dict_set (dst, key, value);
                if (ret)
                        gf_log ("stripe", GF_LOG_WARNING, "xattr dict set failed");
        }

out:
        return;
}


void
stripe_aggregate_xattr (dict_t *dst, dict_t *src)
{
        if ((dst == NULL) || (src == NULL)) {
                goto out;
        }

        dict_foreach (src, stripe_aggregate, dst);
out:
        return;
}


int32_t
stripe_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, inode_t *inode,
                   struct iatt *buf, dict_t *xdata, struct iatt *postparent)
{
        int32_t         callcnt     = 0;
        stripe_local_t *local       = NULL;
        call_frame_t   *prev        = NULL;
        uint64_t        stripe_size = 0;
        uint64_t        real_size = 0;
        char size_xattr[256]        = {0,};
        char real_size_xattr[256]        = {0,};
        int             ret         = 0;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }
        
        prev = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        if (op_errno != ENOENT)
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "%s returned error %s",
                                        prev->this->name,
                                        strerror (op_errno));
                        if (local->op_errno != ESTALE)
                                local->op_errno = op_errno;
                        if (((op_errno != ENOENT) && (op_errno != ENOTCONN)) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                        if (op_errno == ENOENT)
                                local->entry_self_heal_needed = 1;
                }

                if (op_ret >= 0) {
                        local->op_ret = 0;

                        if (FIRST_CHILD(this) == prev->this) {
                                local->stbuf      = *buf;
                                local->postparent = *postparent;
                                local->inode = inode_ref (inode);
                                local->xdata = dict_ref (xdata);
                                if (local->xattr) {
                                        stripe_aggregate_xattr (local->xdata,
                                                                local->xattr);
                                        dict_unref (local->xattr);
                                        local->xattr = NULL;
                                }

                                (void) snprintf (size_xattr, 256,
                                                 "trusted.%s.stripe-size",
                                                 this->name);
                                ret = dict_get_uint64 (xdata, size_xattr,
                                                       &stripe_size);
                                gf_log (this->name, GF_LOG_WARNING, "BAY: AAA ret=%d stripe-size=%d",(int)ret,(int)stripe_size );

                                if (!ret) {
                                        ret = inode_ctx_put (inode, this,
                                                             stripe_size);
                                        if (ret)
                                                gf_log (this->name, GF_LOG_ERROR,
                                                        "Error setting ctx");
                                }
                        }
                        if (!local->xdata && !local->xattr) {
                                local->xattr = dict_ref (xdata);
                        } else if (local->xdata) {
                                stripe_aggregate_xattr (local->xdata, xdata);
                        } else if (local->xattr) {
                                stripe_aggregate_xattr (local->xattr, xdata);
                        }

                        local->stbuf_blocks      += buf->ia_blocks;
                        local->postparent_blocks += postparent->ia_blocks;

                        if (local->stbuf_size < buf->ia_size)
                                local->stbuf_size = buf->ia_size;
                        if (local->postparent_size < postparent->ia_size)
                                local->postparent_size = postparent->ia_size;

                        if (uuid_is_null (local->ia_gfid))
                                uuid_copy (local->ia_gfid, buf->ia_gfid);

                        /* Make sure the gfid on all the nodes are same */
                        if (uuid_compare (local->ia_gfid, buf->ia_gfid)) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "%s: gfid different on subvolume %s",
                                        local->loc.path, prev->this->name);
                        }
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->op_ret == 0 && local->entry_self_heal_needed &&
                    !uuid_is_null (local->loc.inode->gfid))
                        stripe_entry_self_heal (frame, this, local);

                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret != -1) {
                        //real_size_xattr
                        local->stbuf.ia_size=-1;
                        //if (local->xattr) {
                                (void) snprintf (real_size_xattr, 256,
                                                 "trusted.%s.real-size",
                                                 this->name);
                                //ret = dict_set_uint64 (local->dict, real_size_xattr,
                                //                       12345);
                                ret = dict_get_uint64 (xdata, real_size_xattr,
                                                       &real_size);
                                
                                
                                gf_log (this->name, GF_LOG_WARNING, "BAY: ret=%d stripe-size=%d",
                                        (int)ret,(int)real_size);

                                if(!ret) {
                                      local->stbuf.ia_size = real_size;
                                }
                        //}
                        
                        local->stbuf.ia_blocks      = local->stbuf_blocks;
                        //local->stbuf.ia_size        = //local->stbuf_size;
                        local->postparent.ia_blocks = local->postparent_blocks;
                        local->postparent.ia_size   = local->postparent_size;
                }

                STRIPE_STACK_UNWIND (lookup, frame, local->op_ret,
                                     local->op_errno, local->inode,
                                     &local->stbuf, local->xdata,
                                     &local->postparent);
        }
out:
        return 0;
}

int32_t
stripe_lookup (call_frame_t *frame, xlator_t *this, loc_t *loc,
               dict_t *xdata)
{
        stripe_local_t   *local    = NULL;
        xlator_list_t    *trav     = NULL;
        stripe_private_t *priv     = NULL;
        int32_t           op_errno = EINVAL;
        int64_t           filesize = 0;
        int               ret      = 0;
        char xtra_xattr[256]       = {0,};

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;


        gf_log (this->name, GF_LOG_WARNING, "BAY: stripe_lookup path=%s name=%s",
                loc->path, loc->name
        );

        
        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        loc_copy (&local->loc, loc);

        if (xdata && dict_get (xdata, GF_CONTENT_KEY)) {
                ret = dict_get_int64 (xdata, GF_CONTENT_KEY, &filesize);
                if (!ret && (filesize > priv->block_size))
                        dict_del (xdata, GF_CONTENT_KEY);
        }

        /* get stripe-size xattr on lookup for pathinfo string */
        if (!xdata) {
                xdata=dict_new();
                if(!xdata) {
                        op_errno = ENOMEM;
                        goto err;
                }
                        
        }
        (void) snprintf (xtra_xattr, 256, "trusted.%s.stripe-size",
                                this->name);
        ret = dict_set_uint64 (xdata, xtra_xattr, (uint64_t) 0);
        if (ret)
                gf_log (this->name, GF_LOG_ERROR, "Cannot set stripe-"
                        "size key in xattr request dict");

        (void) snprintf (xtra_xattr, 256, "trusted.%s.real-size",
                                this->name);
        ret = dict_set_uint64 (xdata, xtra_xattr, (uint64_t) 0);
        if (ret)
                gf_log (this->name, GF_LOG_ERROR, "Cannot set real-"
                        "size key in xattr request dict");

        /* Everytime in stripe lookup, all child nodes
           should be looked up */
        local->call_count = priv->child_count;
        while (trav) {
                STACK_WIND (frame, stripe_lookup_cbk, trav->xlator,
                            trav->xlator->fops->lookup, loc, xdata);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (lookup, frame, -1, op_errno, NULL, NULL, NULL, NULL);
        return 0;
}




int32_t
stripe_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, struct iatt *buf, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }
        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }

                if (op_ret == 0) {
                        local->op_ret = 0;

                        if (FIRST_CHILD(this) == prev->this) {
                                local->stbuf = *buf;
                        }

                        local->stbuf_blocks += buf->ia_blocks;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret != -1) {
                        local->stbuf.ia_size   = local->size;
                        local->stbuf.ia_blocks = local->stbuf_blocks;
                }

                STRIPE_STACK_UNWIND (stat, frame, local->op_ret,
                                     local->op_errno, &local->stbuf, NULL);
        }
out:
        return 0;
}

int32_t
stripe_stat_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t lookup_op_errno, inode_t *inode,
                   struct iatt *buf, dict_t *xdata, struct iatt *postparent)
{
        xlator_list_t    *trav = NULL;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        int32_t           stat_op_errno = EINVAL;

        size_t            lookuped_size = 0; ;
        loc_t *           loc = cookie;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (buf, err);

        lookuped_size = buf->ia_size;
        
        priv = this->private;
        trav = this->children;
        
        if (priv->first_child_down) {
                stat_op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                stat_op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;
        local->size = lookuped_size;
        
        while (trav) {
                STACK_WIND (frame, stripe_stat_cbk, trav->xlator,
                            trav->xlator->fops->stat, loc, NULL);
                trav = trav->next;
        }

        return 0;

err:
        STRIPE_STACK_UNWIND (stat, frame, -1, stat_op_errno, NULL, NULL);
        return 0;
}


int32_t
stripe_stat (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
        int32_t           op_errno = EINVAL;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        gf_log (this->name, GF_LOG_WARNING, "BAY: stat" );
        
        STACK_WIND_COOKIE (frame, stripe_stat_lookup_cbk,loc,this,
                        this->fops->lookup, loc, NULL);   
        return 0;

err:
        STRIPE_STACK_UNWIND (stat, frame, -1, op_errno, NULL, NULL);
        return 0;
}


int32_t
stripe_statfs_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct statvfs *stbuf, dict_t *xdata)
{
        stripe_local_t *local = NULL;
        int32_t         callcnt = 0;

        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }
        local = frame->local;

        LOCK(&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret && (op_errno != ENOTCONN)) {
                        local->op_errno = op_errno;
                }
                if (op_ret == 0) {
                        struct statvfs *dict_buf = &local->statvfs_buf;
                        dict_buf->f_bsize   = stbuf->f_bsize;
                        dict_buf->f_frsize  = stbuf->f_frsize;
                        dict_buf->f_blocks += stbuf->f_blocks;
                        dict_buf->f_bfree  += stbuf->f_bfree;
                        dict_buf->f_bavail += stbuf->f_bavail;
                        dict_buf->f_files  += stbuf->f_files;
                        dict_buf->f_ffree  += stbuf->f_ffree;
                        dict_buf->f_favail += stbuf->f_favail;
                        dict_buf->f_fsid    = stbuf->f_fsid;
                        dict_buf->f_flag    = stbuf->f_flag;
                        dict_buf->f_namemax = stbuf->f_namemax;
                        local->op_ret = 0;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                STRIPE_STACK_UNWIND (statfs, frame, local->op_ret,
                                     local->op_errno, &local->statvfs_buf, NULL);
        }
out:
        return 0;
}

int32_t
stripe_statfs (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        xlator_list_t    *trav = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);

        trav = this->children;
        priv = this->private;

        gf_log (this->name, GF_LOG_WARNING, "BAY: statfs" );
        
        
        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        local->op_errno = ENOTCONN;
        frame->local = local;

        local->call_count = priv->child_count;
        while (trav) {
                STACK_WIND (frame, stripe_statfs_cbk, trav->xlator,
                            trav->xlator->fops->statfs, loc, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (statfs, frame, -1, op_errno, NULL, NULL);
        return 0;
}



int32_t
stripe_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                     struct iatt *postbuf, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }

                if (op_ret == 0) {
                        local->op_ret = 0;
                        if (FIRST_CHILD(this) == prev->this) {
                                local->pre_buf  = *prebuf;
                                local->post_buf = *postbuf;
                        }

                        local->prebuf_blocks  += prebuf->ia_blocks;
                        local->postbuf_blocks += postbuf->ia_blocks;

                        if (local->prebuf_size < prebuf->ia_size)
                                local->prebuf_size = prebuf->ia_size;

                        if (local->postbuf_size < postbuf->ia_size)
                                local->postbuf_size = postbuf->ia_size;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret != -1) {
                        local->pre_buf.ia_blocks  = local->prebuf_blocks;
                        local->pre_buf.ia_size    = local->prebuf_size;
                        local->post_buf.ia_blocks = local->postbuf_blocks;
                        local->post_buf.ia_size   = local->postbuf_size;
                }

                STRIPE_STACK_UNWIND (truncate, frame, local->op_ret,
                                     local->op_errno, &local->pre_buf,
                                     &local->post_buf, NULL);
        }
out:
        return 0;
}

int32_t
stripe_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc, off_t offset, dict_t *xdata)
{
        xlator_list_t    *trav = NULL;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_truncate_cbk, trav->xlator,
                            trav->xlator->fops->truncate, loc, offset, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (truncate, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}


int32_t
stripe_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno,
                    struct iatt *preop, struct iatt *postop, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }

                if (op_ret == 0) {
                        local->op_ret = 0;

                        if (FIRST_CHILD(this) == prev->this) {
                                local->pre_buf  = *preop;
                                local->post_buf = *postop;
                        }

                        local->prebuf_blocks  += preop->ia_blocks;
                        local->postbuf_blocks += postop->ia_blocks;

                        if (local->prebuf_size < preop->ia_size)
                                local->prebuf_size = preop->ia_size;
                        if (local->postbuf_size < postop->ia_size)
                                local->postbuf_size = postop->ia_size;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret != -1) {
                        local->pre_buf.ia_blocks  = local->prebuf_blocks;
                        local->pre_buf.ia_size    = local->prebuf_size;
                        local->post_buf.ia_blocks = local->postbuf_blocks;
                        local->post_buf.ia_size   = local->postbuf_size;
                }

                STRIPE_STACK_UNWIND (setattr, frame, local->op_ret,
                                     local->op_errno, &local->pre_buf,
                                     &local->post_buf, NULL);
        }
out:
        return 0;
}


int32_t
stripe_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        xlator_list_t    *trav = NULL;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        if (!IA_ISDIR (loc->inode->ia_type) &&
            !IA_ISREG (loc->inode->ia_type)) {
                local->call_count = 1;
                STACK_WIND (frame, stripe_setattr_cbk, FIRST_CHILD (this),
                            FIRST_CHILD (this)->fops->setattr,
                            loc, stbuf, valid, NULL);
                return 0;
        }

        local->call_count = priv->child_count;
        while (trav) {
                STACK_WIND (frame, stripe_setattr_cbk,
                            trav->xlator, trav->xlator->fops->setattr,
                            loc, stbuf, valid, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (setattr, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}


int32_t
stripe_fsetattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                 struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;
        trav = this->children;

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_setattr_cbk, trav->xlator,
                            trav->xlator->fops->fsetattr, fd, stbuf, valid, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (fsetattr, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}

int32_t
stripe_stack_rename_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                         int32_t op_ret, int32_t op_errno, struct iatt *buf,
                         struct iatt *preoldparent, struct iatt *postoldparent,
                         struct iatt *prenewparent, struct iatt *postnewparent,
                         dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }

                if (op_ret == 0) {
                        local->op_ret = 0;

                        local->stbuf.ia_blocks      += buf->ia_blocks;
                        local->preparent.ia_blocks  += preoldparent->ia_blocks;
                        local->postparent.ia_blocks += postoldparent->ia_blocks;
                        local->pre_buf.ia_blocks    += prenewparent->ia_blocks;
                        local->post_buf.ia_blocks   += postnewparent->ia_blocks;

                        if (local->stbuf.ia_size < buf->ia_size)
                                local->stbuf.ia_size =  buf->ia_size;

                        if (local->preparent.ia_size < preoldparent->ia_size)
                                local->preparent.ia_size = preoldparent->ia_size;

                        if (local->postparent.ia_size < postoldparent->ia_size)
                                local->postparent.ia_size = postoldparent->ia_size;

                        if (local->pre_buf.ia_size < prenewparent->ia_size)
                                local->pre_buf.ia_size = prenewparent->ia_size;

                        if (local->post_buf.ia_size < postnewparent->ia_size)
                                local->post_buf.ia_size = postnewparent->ia_size;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                STRIPE_STACK_UNWIND (rename, frame, local->op_ret, local->op_errno,
                                     &local->stbuf, &local->preparent,
                                     &local->postparent,  &local->pre_buf,
                                     &local->post_buf, NULL);
        }
out:
        return 0;
}

int32_t
stripe_first_rename_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                         int32_t op_ret, int32_t op_errno, struct iatt *buf,
                         struct iatt *preoldparent, struct iatt *postoldparent,
                         struct iatt *prenewparent, struct iatt *postnewparent,
                         dict_t *xdata)
{
        stripe_local_t *local = NULL;
        xlator_list_t  *trav = NULL;

        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                op_errno = EINVAL;
                goto unwind;
        }

        if (op_ret == -1) {
                goto unwind;
        }

        local = frame->local;
        trav = this->children;

        local->stbuf      = *buf;
        local->preparent  = *preoldparent;
        local->postparent = *postoldparent;
        local->pre_buf    = *prenewparent;
        local->post_buf   = *postnewparent;

        local->op_ret = 0;
        local->call_count--;

        trav = trav->next; /* Skip first child */
        while (trav) {
                STACK_WIND (frame, stripe_stack_rename_cbk,
                            trav->xlator, trav->xlator->fops->rename,
                            &local->loc, &local->loc2, NULL);
                trav = trav->next;
        }
        return 0;

unwind:
        STRIPE_STACK_UNWIND (rename, frame, -1, op_errno, buf, preoldparent,
                             postoldparent, prenewparent, postnewparent, NULL);
        return 0;
}

int32_t
stripe_rename (call_frame_t *frame, xlator_t *this, loc_t *oldloc,
               loc_t *newloc, dict_t *xdata)
{
        stripe_private_t *priv = NULL;
        stripe_local_t   *local = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (oldloc, err);
        VALIDATE_OR_GOTO (oldloc->path, err);
        VALIDATE_OR_GOTO (oldloc->inode, err);
        VALIDATE_OR_GOTO (newloc, err);

        priv = this->private;
        trav = this->children;

        /* If any one node is down, don't allow rename */
        if (priv->nodes_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        loc_copy (&local->loc, oldloc);
        loc_copy (&local->loc2, newloc);

        local->call_count = priv->child_count;

        frame->local = local;

        STACK_WIND (frame, stripe_first_rename_cbk, trav->xlator,
                    trav->xlator->fops->rename, oldloc, newloc, NULL);

        return 0;
err:
        STRIPE_STACK_UNWIND (rename, frame, -1, op_errno, NULL, NULL, NULL,
                             NULL, NULL, NULL);
        return 0;
}
int32_t
stripe_first_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
        stripe_local_t *local   = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        if (op_ret == -1) {
                gf_log (this->name, GF_LOG_DEBUG, "%s returned %s",
                        prev->this->name, strerror (op_errno));
                goto out;
        }
        local->op_ret = 0;
        local->preparent  = *preparent;
        local->postparent = *postparent;
        local->preparent_blocks  += preparent->ia_blocks;
        local->postparent_blocks += postparent->ia_blocks;

        STRIPE_STACK_UNWIND(unlink, frame, local->op_ret, local->op_errno,
                            &local->preparent, &local->postparent, NULL);
        return 0;
out:
        STRIPE_STACK_UNWIND (unlink, frame, -1, op_errno, NULL, NULL, NULL);

        return 0;
}




int32_t
stripe_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local   = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG, "%s returned %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if (op_errno != ENOENT) {
                                local->failed = 1;
                                local->op_ret = op_ret;
                        }
                }
        }
        UNLOCK (&frame->lock);

        if (callcnt == 1) {
                if (local->failed) {
                        op_errno = local->op_errno;
                        goto out;
                }
                STACK_WIND(frame, stripe_first_unlink_cbk, FIRST_CHILD (this),
                           FIRST_CHILD (this)->fops->unlink, &local->loc, 
                           local->xflag, local->xdata);
        }
        return 0;
out:
        STRIPE_STACK_UNWIND (unlink, frame, -1, op_errno, NULL, NULL, NULL);

        return 0;
}

int32_t
stripe_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc, 
               int xflag, dict_t *xdata)
{
        xlator_list_t    *trav = NULL;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Don't unlink a file if a node is down */
        if (priv->nodes_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        loc_copy (&local->loc, loc);
        local->xflag = xflag;
        local->xdata = dict_ref (xdata);
        
        frame->local = local;
        local->call_count = priv->child_count;
        trav = trav->next; /* Skip the first child */

        while (trav) {
                STACK_WIND (frame, stripe_unlink_cbk,
                            trav->xlator, trav->xlator->fops->unlink,
                            loc, xflag, xdata);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (unlink, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}


int32_t
stripe_first_rmdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno,struct iatt *preparent,
                        struct iatt *postparent, dict_t *xdata)

{
        stripe_local_t *local = NULL;

        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                op_errno = EINVAL;
                goto err;
        }

        if (op_ret == -1) {
                goto err;
        }

        local = frame->local;
        local->op_ret = 0;

        local->call_count--; /* First child successful */

        local->preparent  = *preparent;
        local->postparent = *postparent;
        local->preparent_size  = preparent->ia_size;
        local->postparent_size = postparent->ia_size;
        local->preparent_blocks  += preparent->ia_blocks;
        local->postparent_blocks += postparent->ia_blocks;

        STRIPE_STACK_UNWIND (rmdir, frame, local->op_ret, local->op_errno,
                             &local->preparent, &local->postparent, xdata);
        return 0;
err:
        STRIPE_STACK_UNWIND (rmdir, frame, op_ret, op_errno, NULL, NULL, NULL);
        return 0;

}

int32_t
stripe_rmdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local   = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG, "%s returned %s",
                                prev->this->name, strerror (op_errno));
                        if (op_errno != ENOENT)
                                local->failed = 1;
                }
        }
        UNLOCK (&frame->lock);

        if (callcnt == 1) {
                if (local->failed)
                        goto out;
                STACK_WIND (frame, stripe_first_rmdir_cbk, FIRST_CHILD (this),
                            FIRST_CHILD (this)->fops->rmdir, &local->loc,
                            local->flags, NULL);
        }
        return 0;
out:
        STRIPE_STACK_UNWIND (rmdir, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}

int32_t
stripe_rmdir (call_frame_t *frame, xlator_t *this, loc_t *loc, int flags, dict_t *xdata)
{
        xlator_list_t    *trav = NULL;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        /* don't delete a directory if any of the subvolume is down */
        if (priv->nodes_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        loc_copy (&local->loc, loc);
        local->flags = flags;
        local->call_count = priv->child_count;
        trav = trav->next; /* skip the first child */

        while (trav) {
                STACK_WIND (frame, stripe_rmdir_cbk,  trav->xlator,
                            trav->xlator->fops->rmdir, loc, flags, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (rmdir, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}


int32_t
stripe_mknod_ifreg_fail_unlink_cbk (call_frame_t *frame, void *cookie,
                                    xlator_t *this, int32_t op_ret,
                                    int32_t op_errno, struct iatt *preparent,
                                    struct iatt *postparent, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;

        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                STRIPE_STACK_UNWIND (mknod, frame, local->op_ret, local->op_errno,
                                     local->inode, &local->stbuf,
                                     &local->preparent, &local->postparent, NULL);
        }
out:
        return 0;
}


/**
 */
int32_t
stripe_mknod_ifreg_setxattr_cbk (call_frame_t *frame, void *cookie,
                                 xlator_t *this, int32_t op_ret,
                                 int32_t op_errno, dict_t *xdata)
{
        int32_t           callcnt = 0;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        call_frame_t     *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        priv  = this->private;
        local = frame->local;

	LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_ret = -1;
                        local->op_errno = op_errno;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->op_ret == -1) {
                        local->call_count = priv->child_count;
                        while (trav) {
                                STACK_WIND (frame,
                                            stripe_mknod_ifreg_fail_unlink_cbk,
                                            trav->xlator,
                                            trav->xlator->fops->unlink,
                                            &local->loc, 0, NULL);
                                trav = trav->next;
                        }
                        return 0;
                }

                STRIPE_STACK_UNWIND (mknod, frame, local->op_ret, local->op_errno,
                                     local->inode, &local->stbuf,
                                     &local->preparent, &local->postparent, NULL);
        }
out:
        return 0;
}

int32_t
stripe_mknod_ifreg_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno, inode_t *inode,
                        struct iatt *buf, struct iatt *preparent,
                        struct iatt *postparent, dict_t *xdata)
{
        int32_t           callcnt = 0;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        call_frame_t     *prev = NULL;
        xlator_list_t    *trav = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        priv  = this->private;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                        local->op_errno = op_errno;
                }
                if (op_ret >= 0) {
                        local->op_ret = op_ret;

                        /* Can be used as a mechanism to understand if mknod
                           was successful in at least one place */
                        if (uuid_is_null (local->ia_gfid))
                                uuid_copy (local->ia_gfid, buf->ia_gfid);

                        local->stbuf_blocks += buf->ia_blocks;
                        local->preparent_blocks  += preparent->ia_blocks;
                        local->postparent_blocks += postparent->ia_blocks;

                        if (local->stbuf_size < buf->ia_size)
                                local->stbuf_size = buf->ia_size;
                        if (local->preparent_size < preparent->ia_size)
                                local->preparent_size = preparent->ia_size;
                        if (local->postparent_size < postparent->ia_size)
                                local->postparent_size = postparent->ia_size;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if ((local->op_ret == -1) && !uuid_is_null (local->ia_gfid)) {
                        /* ia_gfid set means, at least on one node 'mknod'
                           is successful */
                        local->call_count = priv->child_count;
                        trav = this->children;
                        while (trav) {
                                STACK_WIND (frame,
                                            stripe_mknod_ifreg_fail_unlink_cbk,
                                            trav->xlator,
                                            trav->xlator->fops->unlink,
                                            &local->loc, 0, NULL);
                                trav = trav->next;
                        }
                        return 0;
                }


                if (local->op_ret != -1) {
                        local->preparent.ia_blocks  = local->preparent_blocks;
                        local->preparent.ia_size    = local->preparent_size;
                        local->postparent.ia_blocks = local->postparent_blocks;
                        local->postparent.ia_size   = local->postparent_size;
                        local->stbuf.ia_size        = local->stbuf_size;
                        local->stbuf.ia_blocks      = local->stbuf_blocks;
                }

                /* Create itself has failed.. so return
                   without setxattring */
                STRIPE_STACK_UNWIND (mknod, frame, local->op_ret, local->op_errno,
                                     local->inode, &local->stbuf,
                                     &local->preparent, &local->postparent, NULL);
        }
out:
        return 0;
}


int32_t
stripe_mknod_first_ifreg_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno, inode_t *inode,
                        struct iatt *buf, struct iatt *preparent,
                        struct iatt *postparent, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        call_frame_t     *prev = NULL;
        xlator_list_t    *trav = NULL;
        int               i    = 1;
        char              size_key[256]  = {0,};
        char              index_key[256] = {0,};
        char              count_key[256] = {0,};
        dict_t           *dict           = NULL;
        int               ret            = 0;
        int               need_unref     = 0;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        priv  = this->private;
        local = frame->local;
        trav = this->children;

        local->call_count--;

        if (op_ret == -1) {
                gf_log (this->name, GF_LOG_DEBUG, "%s returned error %s",
                        prev->this->name, strerror (op_errno));
                local->failed = 1;
                local->op_errno = op_errno;
                goto out;
        }

        local->op_ret = op_ret;

        local->stbuf      = *buf;
        local->preparent  = *preparent;
        local->postparent = *postparent;

        if (uuid_is_null (local->ia_gfid))
                uuid_copy (local->ia_gfid, buf->ia_gfid);
        local->preparent.ia_blocks  = local->preparent_blocks;
        local->preparent.ia_size    = local->preparent_size;
        local->postparent.ia_blocks = local->postparent_blocks;
        local->postparent.ia_size   = local->postparent_size;
        local->stbuf.ia_size        = local->stbuf_size;
        local->stbuf.ia_blocks      = local->stbuf_blocks;

        sprintf (size_key, "trusted.%s.stripe-size", this->name);
        sprintf (count_key, "trusted.%s.stripe-count", this->name);
        sprintf (index_key, "trusted.%s.stripe-index", this->name);

        trav = trav->next;
        while (trav) {
                if (priv->xattr_supported) {
                        dict = dict_new ();
                        if (!dict) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to allocate dict %s", local->loc.path);
                        }
                        need_unref = 1;

                        dict_copy (local->xattr, dict);

                        ret = dict_set_int64 (dict, size_key, local->stripe_size);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set stripe-size failed", local->loc.path);
                        ret = dict_set_int32 (dict, count_key, priv->child_count);

                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set child_count failed", local->loc.path);
                        ret = dict_set_int32 (dict, index_key, i);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set stripe-index failed", local->loc.path);
                } else {
                        dict = local->xattr;
                }

                STACK_WIND (frame, stripe_mknod_ifreg_cbk,
                            trav->xlator, trav->xlator->fops->mknod,
                            &local->loc, local->mode, local->rdev, 0, dict);
                trav = trav->next;
                i++;

                if (dict && need_unref)
                        dict_unref (dict);
        }

        return 0;

out:

       STRIPE_STACK_UNWIND (mknod, frame, op_ret, op_errno, NULL, NULL, NULL, NULL, NULL);
       return 0;
}


int32_t
stripe_single_mknod_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                         int32_t op_ret, int32_t op_errno, inode_t *inode,
                         struct iatt *buf, struct iatt *preparent,
                         struct iatt *postparent, dict_t *xdata)
{
        STRIPE_STACK_UNWIND (mknod, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent, xdata);
        return 0;
}


int
stripe_mknod (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
              dev_t rdev, mode_t umask, dict_t *xdata)
{
        stripe_private_t *priv           = NULL;
        stripe_local_t   *local          = NULL;
        int32_t           op_errno       = EINVAL;
        int32_t           i              = 0;
        char              size_key[256]  = {0,};
        char              index_key[256] = {0,};
        char              count_key[256] = {0,};
        dict_t           *dict           = NULL;
        int               ret            = 0;
        int               need_unref     = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        if (S_ISREG(mode)) {
                /* NOTE: on older kernels (older than 2.6.9),
                   creat() fops is sent as mknod() + open(). Hence handling
                   S_IFREG files is necessary */
                if (priv->nodes_down) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "Some node down, returning EIO");
                        op_errno = EIO;
                        goto err;
                }

                /* Initialization */
                local = GF_CALLOC (1, sizeof (stripe_local_t),
                                   gf_stripe_mt_stripe_local_t);
                if (!local) {
                        op_errno = ENOMEM;
                        goto err;
                }
                local->op_ret = -1;
                local->op_errno = ENOTCONN;
                local->stripe_size = stripe_get_matching_bs (loc->path,
                                                             priv->pattern,
                                                             priv->block_size);
                frame->local = local;
                local->inode = inode_ref (loc->inode);
                loc_copy (&local->loc, loc);
                local->xattr = dict_copy_with_ref (xdata, NULL);
                local->mode = mode;
                local->rdev = rdev;

                /* Everytime in stripe lookup, all child nodes should
                   be looked up */
                local->call_count = priv->child_count;

                /* Send a setxattr request to nodes where the
                   files are created */
                sprintf (size_key,
                         "trusted.%s.stripe-size", this->name);
                sprintf (count_key,
                         "trusted.%s.stripe-count", this->name);
                sprintf (index_key,
                         "trusted.%s.stripe-index", this->name);

                if (priv->xattr_supported) {
                        dict = dict_new ();
                        if (!dict) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to allocate dict %s", loc->path);
                        }
                        need_unref = 1;

                        dict_copy (xdata, dict);

                        ret = dict_set_int64 (dict, size_key,
                                              local->stripe_size);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set stripe-size failed", loc->path);
                        ret = dict_set_int32 (dict, count_key,
                                               priv->child_count);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set child_count failed", loc->path);
                        ret = dict_set_int32 (dict, index_key, i);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set stripe-index failed", loc->path);
                } else {
                        dict = xdata;
                }

                STACK_WIND (frame, stripe_mknod_first_ifreg_cbk,
                            FIRST_CHILD (this), FIRST_CHILD (this)->fops->mknod,
                            loc, mode, rdev, umask, dict);

                        if (dict && need_unref)
                                dict_unref (dict);
                return 0;
        }

        STACK_WIND (frame, stripe_single_mknod_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->mknod,
                    loc, mode, rdev, umask, xdata);

        return 0;
err:
        STRIPE_STACK_UNWIND (mknod, frame, -1, op_errno, NULL, NULL, NULL, NULL, NULL);
        return 0;
}


int32_t
stripe_mkdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, inode_t *inode,
                  struct iatt *buf, struct iatt *preparent,
                  struct iatt *postparent, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t  *local   = NULL;
        call_frame_t    *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }

                if (op_ret >= 0) {
                        local->op_ret = 0;

                        local->stbuf_blocks      += buf->ia_blocks;
                        local->preparent_blocks  += preparent->ia_blocks;
                        local->postparent_blocks += postparent->ia_blocks;

                        if (local->stbuf_size < buf->ia_size)
                                local->stbuf_size = buf->ia_size;
                        if (local->preparent_size < preparent->ia_size)
                                local->preparent_size = preparent->ia_size;
                        if (local->postparent_size < postparent->ia_size)
                                local->postparent_size = postparent->ia_size;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed != -1) {
                        local->preparent.ia_blocks  = local->preparent_blocks;
                        local->preparent.ia_size    = local->preparent_size;
                        local->postparent.ia_blocks = local->postparent_blocks;
                        local->postparent.ia_size   = local->postparent_size;
                        local->stbuf.ia_size        = local->stbuf_size;
                        local->stbuf.ia_blocks      = local->stbuf_blocks;
                }
                STRIPE_STACK_UNWIND (mkdir, frame, local->op_ret,
                                     local->op_errno, local->inode,
                                     &local->stbuf, &local->preparent,
                                     &local->postparent, NULL);
        }
out:
        return 0;
}


int32_t
stripe_first_mkdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, inode_t *inode,
                  struct iatt *buf, struct iatt *preparent,
                  struct iatt *postparent, dict_t *xdata)
{
        stripe_local_t  *local   = NULL;
        call_frame_t    *prev = NULL;
        xlator_list_t        *trav = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;
        trav = this->children;

        local->call_count--; /* first child is successful */
        trav = trav->next;   /* skip first child */

        if (op_ret == -1) {
                gf_log (this->name, GF_LOG_DEBUG, "%s returned error %s",
                        prev->this->name, strerror (op_errno));
                local->op_errno = op_errno;
                goto out;
        }

        local->op_ret = 0;

        local->inode      = inode_ref (inode);
        local->stbuf      = *buf;
        local->postparent = *postparent;
        local->preparent  = *preparent;
         
        local->stbuf_blocks      += buf->ia_blocks;
        local->preparent_blocks  += preparent->ia_blocks;
        local->postparent_blocks += postparent->ia_blocks;

        local->stbuf_size = buf->ia_size;
        local->preparent_size = preparent->ia_size;
        local->postparent_size = postparent->ia_size;

        while (trav) {
                STACK_WIND (frame, stripe_mkdir_cbk, trav->xlator,
                            trav->xlator->fops->mkdir, &local->loc, local->mode,
                            local->umask, local->xdata);
                trav = trav->next;
        }
        return 0;
out:
        STRIPE_STACK_UNWIND (mkdir, frame, -1, op_errno, NULL, NULL, NULL,
                      NULL, NULL);

        return 0;

}


int
stripe_mkdir (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
              mode_t umask, dict_t *xdata)
{
        stripe_private_t *priv = NULL;
        stripe_local_t   *local = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = 1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        local->call_count = priv->child_count;
        if (xdata)
                local->xdata = dict_ref (xdata);

        local->mode = mode;
        local->umask = umask;
        loc_copy (&local->loc, loc);
        frame->local = local;

        /* Everytime in stripe lookup, all child nodes should be looked up */
        STACK_WIND (frame, stripe_first_mkdir_cbk, trav->xlator,
                    trav->xlator->fops->mkdir, loc, mode, umask, xdata);

        return 0;
err:
        STRIPE_STACK_UNWIND (mkdir, frame, -1, op_errno, NULL, NULL, NULL, NULL, NULL);
        return 0;
}


int32_t
stripe_link_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, inode_t *inode,
                 struct iatt *buf, struct iatt *preparent,
                 struct iatt *postparent, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t  *local   = NULL;
        call_frame_t    *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }

                if (op_ret >= 0) {
                        local->op_ret = 0;

                        if (FIRST_CHILD(this) == prev->this) {
                                local->inode      = inode_ref (inode);
                                local->stbuf      = *buf;
                                local->postparent = *postparent;
                                local->preparent  = *preparent;
                        }
                        local->stbuf_blocks      += buf->ia_blocks;
                        local->preparent_blocks  += preparent->ia_blocks;
                        local->postparent_blocks += postparent->ia_blocks;

                        if (local->stbuf_size < buf->ia_size)
                                local->stbuf_size = buf->ia_size;
                        if (local->preparent_size < preparent->ia_size)
                                local->preparent_size = preparent->ia_size;
                        if (local->postparent_size < postparent->ia_size)
                                local->postparent_size = postparent->ia_size;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret != -1) {
                        local->preparent.ia_blocks  = local->preparent_blocks;
                        local->preparent.ia_size    = local->preparent_size;
                        local->postparent.ia_blocks = local->postparent_blocks;
                        local->postparent.ia_size   = local->postparent_size;
                        local->stbuf.ia_size        = local->stbuf_size;
                        local->stbuf.ia_blocks      = local->stbuf_blocks;
                }
                STRIPE_STACK_UNWIND (link, frame, local->op_ret,
                                     local->op_errno, local->inode,
                                     &local->stbuf, &local->preparent,
                                     &local->postparent, NULL);
        }
out:
        return 0;
}

int32_t
stripe_link (call_frame_t *frame, xlator_t *this, loc_t *oldloc, loc_t *newloc, dict_t *xdata)
{
        xlator_list_t    *trav = NULL;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = 1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (oldloc, err);
        VALIDATE_OR_GOTO (oldloc->path, err);
        VALIDATE_OR_GOTO (oldloc->inode, err);

        priv = this->private;
        trav = this->children;

        /* If any one node is down, don't allow link operation */
        if (priv->nodes_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;

        /* Everytime in stripe lookup, all child
           nodes should be looked up */
        while (trav) {
                STACK_WIND (frame, stripe_link_cbk,
                            trav->xlator, trav->xlator->fops->link,
                            oldloc, newloc, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (link, frame, -1, op_errno, NULL, NULL, NULL, NULL, NULL);
        return 0;
}

int32_t
stripe_create_fail_unlink_cbk (call_frame_t *frame, void *cookie,
                               xlator_t *this, int32_t op_ret,
                               int32_t op_errno, struct iatt *preparent,
                               struct iatt *postparent, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;

        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                STRIPE_STACK_UNWIND (create, frame, local->op_ret, local->op_errno,
                                     local->fd, local->inode, &local->stbuf,
                                     &local->preparent, &local->postparent, NULL);
        }
out:
        return 0;
}


int32_t
stripe_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, fd_t *fd,
                   inode_t *inode, struct iatt *buf, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
        int32_t           callcnt = 0;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        stripe_fd_ctx_t  *fctx = NULL;
        call_frame_t     *prev = NULL;
        xlator_list_t    *trav = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        priv  = this->private;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->failed = 1;
                        local->op_errno = op_errno;
                }

                if (op_ret >= 0) {
                        local->op_ret = op_ret;

                        local->stbuf_blocks += buf->ia_blocks;
                        local->preparent_blocks  += preparent->ia_blocks;
                        local->postparent_blocks += postparent->ia_blocks;

                        if (local->stbuf_size < buf->ia_size)
                                local->stbuf_size = buf->ia_size;
                        if (local->preparent_size < preparent->ia_size)
                                local->preparent_size = preparent->ia_size;
                        if (local->postparent_size < postparent->ia_size)
                                local->postparent_size = postparent->ia_size;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret == -1) {
                        local->call_count = priv->child_count;
                        trav = this->children;
                        while (trav) {
                                STACK_WIND (frame,
                                            stripe_create_fail_unlink_cbk,
                                            trav->xlator,
                                            trav->xlator->fops->unlink,
                                            &local->loc, 0, NULL);
                                trav = trav->next;
                        }

                        return 0;
                }

                if (local->op_ret >= 0) {
                        local->preparent.ia_blocks  = local->preparent_blocks;
                        local->preparent.ia_size    = local->preparent_size;
                        local->postparent.ia_blocks = local->postparent_blocks;
                        local->postparent.ia_size   = local->postparent_size;
                        local->stbuf.ia_size        = local->stbuf_size;
                        local->stbuf.ia_blocks      = local->stbuf_blocks;

                        fctx = GF_CALLOC (1, sizeof (stripe_fd_ctx_t),
                                          gf_stripe_mt_stripe_fd_ctx_t);
                        if (!fctx) {
                                local->op_ret = -1;
                                local->op_errno = ENOMEM;
                                goto unwind;
                        }

                        fctx->stripe_size  = local->stripe_size;
                        fctx->stripe_count = priv->child_count;
                        fctx->static_array = 1;
                        fctx->xl_array = priv->xl_array;
                        fd_ctx_set (local->fd, this,
                                    (uint64_t)(long)fctx);
                }

        unwind:
                /* Create itself has failed.. so return
                   without setxattring */
                STRIPE_STACK_UNWIND (create, frame, local->op_ret,
                                     local->op_errno, local->fd,
                                     local->inode, &local->stbuf,
                                     &local->preparent, &local->postparent, NULL);
        }

out:
        return 0;
}



int32_t
stripe_first_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, fd_t *fd,
                   inode_t *inode, struct iatt *buf, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        call_frame_t     *prev = NULL;
        xlator_list_t    *trav = NULL;
        int               i    = 1;
        dict_t           *dict = NULL;
        loc_t            *loc  = NULL;
        int32_t           need_unref = 0;
        int32_t           ret  = -1;
        char              size_key[256]  = {0,};
        char              index_key[256] = {0,};
        char              count_key[256] = {0,};
        char              real_size_key[256] = {0,};

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        priv  = this->private;
        local = frame->local;
        trav = this->children;
        loc = &local->loc;

        --local->call_count;

        if (op_ret == -1) {
                gf_log (this->name, GF_LOG_DEBUG, "%s returned error %s",
                        prev->this->name, strerror (op_errno));
                 local->failed = 1;
                 local->op_errno = op_errno;
        }

        local->op_ret = 0;
        /* Get the mapping in inode private */
        /* Get the stat buf right */
        local->stbuf      = *buf;
        local->preparent  = *preparent;
        local->postparent = *postparent;

        local->stbuf_blocks += buf->ia_blocks;
        local->preparent_blocks  += preparent->ia_blocks;
        local->postparent_blocks += postparent->ia_blocks;

        if (local->stbuf_size < buf->ia_size)
              local->stbuf_size = buf->ia_size;
        if (local->preparent_size < preparent->ia_size)
              local->preparent_size = preparent->ia_size;
        if (local->postparent_size < postparent->ia_size)
              local->postparent_size = postparent->ia_size;

        if (local->failed)
                local->op_ret = -1;

        if (local->op_ret == -1) {
                local->call_count = 1;
                STACK_WIND (frame, stripe_create_fail_unlink_cbk,
                            FIRST_CHILD (this), FIRST_CHILD (this)->fops->unlink,
                            &local->loc, 0, NULL);
                return 0;
        }

        if (local->op_ret >= 0) {
                local->preparent.ia_blocks  = local->preparent_blocks;
                local->preparent.ia_size    = local->preparent_size;
                local->postparent.ia_blocks = local->postparent_blocks;
                local->postparent.ia_size   = local->postparent_size;
                local->stbuf.ia_size        = local->stbuf_size;
                local->stbuf.ia_blocks      = local->stbuf_blocks;
        }

        /* Send a setxattr request to nodes where the
           files are created */
        sprintf (size_key, "trusted.%s.stripe-size", this->name);
        sprintf (count_key, "trusted.%s.stripe-count", this->name);
        sprintf (index_key, "trusted.%s.stripe-index", this->name);
        sprintf (real_size_key, "trusted.%s.real-size", this->name);

        trav = trav->next;
        while (trav) {
                if (priv->xattr_supported) {
                        dict = dict_new ();
                        if (!dict) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to allocate dict %s", loc->path);
                        }
                        need_unref = 1;

                        dict_copy (local->xattr, dict);

                        ret = dict_set_int64 (dict, size_key,
                                              local->stripe_size);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set stripe-size failed", loc->path);
                        ret = dict_set_int32 (dict, count_key,
                                              priv->child_count);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set child_count failed", loc->path);
                        ret = dict_set_int32 (dict, index_key, i);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set stripe-index failed", loc->path);

                        ret = dict_set_int64 (dict, real_size_key, 0);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "%s: set real-size failed", loc->path);

                        } else {
                                dict = local->xattr;
                }
 
                STACK_WIND (frame, stripe_create_cbk, trav->xlator,
                            trav->xlator->fops->create, &local->loc,
                            local->flags, local->mode, local->umask,local->fd,
                            dict);
                trav = trav->next;
                if (need_unref && dict)
                        dict_unref (dict);
                i++;
        }

out:
        return 0;
}



/**
 * stripe_create - If a block-size is specified for the 'name', create the
 *    file in all the child nodes. If not, create it in only first child.
 *
 * @name- complete path of the file to be created.
 */
int32_t
stripe_create (call_frame_t *frame, xlator_t *this, loc_t *loc,
               int32_t flags, mode_t mode, mode_t umask, fd_t *fd, dict_t *xdata)
{
        stripe_private_t *priv = NULL;
        stripe_local_t   *local = NULL;
        int32_t           op_errno = EINVAL;
        int               ret            = 0;
        int               need_unref     = 0;
        int               i              = 0;
        char              size_key[256]  = {0,};
        char              index_key[256] = {0,};
        char              count_key[256] = {0,};
        char              real_size_key[256] = {0,};
        dict_t           *dict           = NULL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;

        /* files created in O_APPEND mode does not allow lseek() on fd */
        flags &= ~O_APPEND;

        if (priv->first_child_down || priv->nodes_down) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "First node down, returning EIO");
                op_errno = EIO;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        local->op_errno = ENOTCONN;
        local->stripe_size = stripe_get_matching_bs (loc->path,
                                                     priv->pattern,
                                                     priv->block_size);
        frame->local = local;
        local->inode = inode_ref (loc->inode);
        loc_copy (&local->loc, loc);
        local->fd = fd_ref (fd);
        local->flags = flags;
        local->mode = mode;
        local->umask = umask;
        if(xdata)
                local->xattr = dict_ref (xdata);

        local->call_count = priv->child_count;
        /* Send a setxattr request to nodes where the
           files are created */
        sprintf (size_key, "trusted.%s.stripe-size", this->name);
        sprintf (count_key, "trusted.%s.stripe-count", this->name);
        sprintf (index_key, "trusted.%s.stripe-index", this->name);
        sprintf (real_size_key, "trusted.%s.real-size", this->name);

        if (priv->xattr_supported) {
                dict = dict_new ();
                if (!dict) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to allocate dict %s", loc->path);
                }
                need_unref = 1;

                dict_copy (xdata, dict);

                ret = dict_set_int64 (dict, size_key,
                                      local->stripe_size);
                if (ret)
                        gf_log (this->name, GF_LOG_ERROR,
                                "%s: set stripe-size failed", loc->path);
                ret = dict_set_int32 (dict, count_key,
                                      priv->child_count);
                if (ret)
                        gf_log (this->name, GF_LOG_ERROR,
                                "%s: set child_count failed", loc->path);
                ret = dict_set_int32 (dict, index_key, i);
                if (ret)
                        gf_log (this->name, GF_LOG_ERROR,
                                "%s: set stripe-index failed", loc->path);
                ret = dict_set_int64 (dict, real_size_key, 0);
                if (ret)
                        gf_log (this->name, GF_LOG_ERROR,
                                "%s: set real-size failed", loc->path);
        } else {
                        dict = xdata;
        }


        STACK_WIND (frame, stripe_first_create_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->create, loc, flags, mode,
                    umask, fd, dict);

        if (need_unref && dict)
                dict_unref (dict);


        return 0;
err:
        STRIPE_STACK_UNWIND (create, frame, -1, op_errno, NULL, NULL, NULL,
                             NULL, NULL, xdata);
        return 0;
}

int32_t
stripe_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, fd_t *fd, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {

                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                        local->op_errno = op_errno;
                }

                if (op_ret >= 0)
                        local->op_ret = op_ret;
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret == -1) {
                        if (local->fctx) {
                                if (!local->fctx->static_array)
                                        GF_FREE (local->fctx->xl_array);
                                GF_FREE (local->fctx);
                        }
                } else {
                        fd_ctx_set (local->fd, this,
                                    (uint64_t)(long)local->fctx);
                }

                STRIPE_STACK_UNWIND (open, frame, local->op_ret,
                                     local->op_errno, local->fd, xdata);
        }
out:
        return 0;
}

int32_t
stripe_open_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno, inode_t *inode,
                        struct iatt *buf, dict_t *dict, struct iatt *postparent)
{
        int32_t           index = 0;
        int32_t           callcnt = 0;
        char              key[256] = {0,};
        stripe_local_t   *local = NULL;
        xlator_list_t    *trav = NULL;
        stripe_private_t *priv = NULL;
        data_t           *data = NULL;
        call_frame_t     *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = (call_frame_t *)cookie;
        priv  = this->private;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_ret = -1;
                        if (local->op_errno != EIO)
                                local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                        goto unlock;
                }

                if (!dict)
                        goto unlock;

                if (!local->fctx) {
                        local->fctx =  GF_CALLOC (1, sizeof (stripe_fd_ctx_t),
                                                  gf_stripe_mt_stripe_fd_ctx_t);
                        if (!local->fctx) {
                                local->op_errno = ENOMEM;
                                local->op_ret = -1;
                                goto unlock;
                        }

                        local->fctx->static_array = 0;
                }
                /* Stripe block size */
                sprintf (key, "trusted.%s.stripe-size", this->name);
                data = dict_get (dict, key);
                if (!data) {
                        local->xattr_self_heal_needed = 1;
                } else {
                        if (!local->fctx->stripe_size) {
                                local->fctx->stripe_size =
                                        data_to_int64 (data);
                        }

                        if (local->fctx->stripe_size != data_to_int64 (data)) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "stripe-size mismatch in blocks");
                                local->xattr_self_heal_needed = 1;
                        }
                }
                /* Stripe count */
                sprintf (key, "trusted.%s.stripe-count", this->name);
                data = dict_get (dict, key);
                if (!data) {
                        local->xattr_self_heal_needed = 1;
                        goto unlock;
                }
                if (!local->fctx->xl_array) {
                        local->fctx->stripe_count = data_to_int32 (data);
                        if (!local->fctx->stripe_count) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "error with stripe-count xattr");
                                local->op_ret   = -1;
                                local->op_errno = EIO;
                                goto unlock;
                        }

                        local->fctx->xl_array =
                                GF_CALLOC (local->fctx->stripe_count,
                                           sizeof (xlator_t *),
                                           gf_stripe_mt_xlator_t);
                        if (!local->fctx->xl_array) {
                                local->op_errno = ENOMEM;
                                local->op_ret   = -1;
                                goto unlock;
                        }
                }
                if (local->fctx->stripe_count != data_to_int32 (data)) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "error with stripe-count xattr (%d != %d)",
                                local->fctx->stripe_count, data_to_int32 (data));
                        local->op_ret   = -1;
                        local->op_errno = EIO;
                        goto unlock;
                }

                /* index */
                sprintf (key, "trusted.%s.stripe-index", this->name);
                data = dict_get (dict, key);
                if (!data) {
                        local->xattr_self_heal_needed = 1;
                        goto unlock;
                }
                index = data_to_int32 (data);
                if (index > priv->child_count) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "error with stripe-index xattr (%d)", index);
                        local->op_ret   = -1;
                        local->op_errno = EIO;
                        goto unlock;
                }
                if (local->fctx->xl_array) {
                        if (local->fctx->xl_array[index]) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "duplicate entry @ index (%d)", index);
                                local->op_ret   = -1;
                                local->op_errno = EIO;
                                goto unlock;
                        }
                        local->fctx->xl_array[index] = prev->this;
                }

                /* real-size */
                sprintf (key, "trusted.%s.real-size", this->name);
                data = dict_get (dict, key);
                if (!data) {
                        local->xattr_self_heal_needed = 1;
                        goto unlock;
                }
                
                local->fctx->real_size = data_to_int64 (data);
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: openfile, setting size=%d",(int)local->fctx->real_size );

                local->entry_count++;
                local->op_ret = 0;
        }
unlock:
        UNLOCK (&frame->lock);

        if (!callcnt) {
                /* TODO: if self-heal flag is set, do it */
                if (local->xattr_self_heal_needed) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s: stripe info need to be healed",
                                local->loc.path);
                }

                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret)
                        goto err;

                if (local->entry_count != local->fctx->stripe_count) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "entry-count (%d) != stripe-count (%d)",
                                local->entry_count, local->fctx->stripe_count);
                        local->op_ret = -1;
                        local->op_errno = EIO;
                        goto err;
                }
                if (!local->fctx->stripe_size) {
                        gf_log (this->name, GF_LOG_ERROR, "stripe size not set");
                        local->op_ret = -1;
                        local->op_errno = EIO;
                        goto err;
                }

                local->call_count = local->fctx->stripe_count;

                trav = this->children;
                while (trav) {
                        STACK_WIND (frame, stripe_open_cbk, trav->xlator,
                                    trav->xlator->fops->open, &local->loc,
                                    local->flags, local->fd, 0);
                        trav = trav->next;
                }
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (open, frame, local->op_ret, local->op_errno,
                             local->fd, NULL);
out:
        return 0;
}

/**
 * stripe_open -
 */
int32_t
stripe_open (call_frame_t *frame, xlator_t *this, loc_t *loc,
             int32_t flags, fd_t *fd, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = 1;
        dict_t           *dict = NULL;
        int               ret = 0;
        char              key[256] = {0,};

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }

        /* files opened in O_APPEND mode does not allow lseek() on fd */
        flags &= ~O_APPEND;
        
        /* he mustn't open files in write-only mode*/
        if (flags & O_WRONLY) {
                flags &= ~O_WRONLY;
                flags |= O_RDWR;
        }

        local->fd = fd_ref (fd);
        frame->local = local;
        loc_copy (&local->loc, loc);

        /* Striped files */
        local->flags = flags;
        local->call_count = priv->child_count;
        local->stripe_size = stripe_get_matching_bs (loc->path,
                                                     priv->pattern,
                                                     priv->block_size);

        if (priv->xattr_supported) {
                dict = dict_new ();
                if (!dict)
                        goto err;

                sprintf (key, "trusted.%s.stripe-size", this->name);
                ret = dict_set_int64 (dict, key, 8);
                if (ret)
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to set %s in xattr_req dict", key);

                sprintf (key, "trusted.%s.stripe-count", this->name);
                ret = dict_set_int32 (dict, key, 4);
                if (ret)
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to set %s in xattr_req dict", key);

                sprintf (key, "trusted.%s.stripe-index", this->name);
                ret = dict_set_int32 (dict, key, 4);
                if (ret)
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to set %s in xattr_req dict", key);

                sprintf (key, "trusted.%s.real-size", this->name);
                ret = dict_set_int64 (dict, key, 8);
                if (ret)
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to set %s in xattr_req dict", key);

                while (trav) {
                        STACK_WIND (frame, stripe_open_lookup_cbk,
                                    trav->xlator, trav->xlator->fops->lookup,
                                    loc, dict);
                        trav = trav->next;
                }
                if (dict)
                        dict_unref (dict);

                return 0;
        }
        local->fctx =  GF_CALLOC (1, sizeof (stripe_fd_ctx_t),
                                  gf_stripe_mt_stripe_fd_ctx_t);
        if (!local->fctx) {
                op_errno = ENOMEM;
                goto err;
        }

        local->fctx->static_array = 1;
        local->fctx->stripe_size  = local->stripe_size;
        local->fctx->stripe_count = priv->child_count;
        local->fctx->xl_array     = priv->xl_array;

        while (trav) {
                STACK_WIND (frame, stripe_open_cbk, trav->xlator,
                            trav->xlator->fops->open,
                            &local->loc, local->flags, local->fd,
                            xdata);
                trav = trav->next;
        }
        return 0;
err:
        STRIPE_STACK_UNWIND (open, frame, -1, op_errno, NULL, NULL);
        return 0;
}


int32_t
stripe_opendir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, fd_t *fd, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_ret = -1;
                        local->op_errno = op_errno;
                }

                if (op_ret >= 0)
                        local->op_ret = op_ret;
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                STRIPE_STACK_UNWIND (opendir, frame, local->op_ret,
                                     local->op_errno, local->fd, NULL);
        }
out:
        return 0;
}


int32_t
stripe_opendir (call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd, dict_t *xdata)
{
        xlator_list_t    *trav = NULL;
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        frame->local = local;
        local->call_count = priv->child_count;
        local->fd = fd_ref (fd);

        while (trav) {
                STACK_WIND (frame, stripe_opendir_cbk, trav->xlator,
                            trav->xlator->fops->opendir, loc, fd, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (opendir, frame, -1, op_errno, NULL, NULL);
        return 0;
}

int32_t
stripe_lk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct gf_flock *lock, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }
                if (op_ret >= 0) {
                        if (FIRST_CHILD(this) == prev->this) {
                                /* First successful call, copy the *lock */
                                local->op_ret = op_ret;
                                local->lock = *lock;
                        }
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;
                STRIPE_STACK_UNWIND (lk, frame, local->op_ret,
                                     local->op_errno, &local->lock, NULL);
        }
out:
        return 0;
}

int32_t
stripe_lk (call_frame_t *frame, xlator_t *this, fd_t *fd, int32_t cmd,
           struct gf_flock *lock, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        xlator_list_t    *trav = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = EINVAL;

        gf_log (this->name, GF_LOG_WARNING, "BAY: lk" );
        
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        trav = this->children;
        priv = this->private;

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_lk_cbk, trav->xlator,
                            trav->xlator->fops->lk, fd, cmd, lock, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (lk, frame, -1, op_errno, NULL, NULL);
        return 0;
}


int32_t
stripe_flush_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local   = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }
                if (op_ret >= 0)
                        local->op_ret = op_ret;
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                STRIPE_STACK_UNWIND (flush, frame, local->op_ret,
                                     local->op_errno, NULL);
        }
out:
        return 0;
}

int32_t
stripe_flush (call_frame_t *frame, xlator_t *this, fd_t *fd, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = 1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;
        trav = this->children;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }
        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_flush_cbk,  trav->xlator,
                            trav->xlator->fops->flush, fd, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (flush, frame, -1, op_errno, NULL);
        return 0;
}


int32_t
stripe_fsync_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                  struct iatt *postbuf, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local   = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }
                if (op_ret >= 0) {
                        local->op_ret = op_ret;
                        if (FIRST_CHILD(this) == prev->this) {
                                local->pre_buf  = *prebuf;
                                local->post_buf = *postbuf;
                        }
                        local->prebuf_blocks  += prebuf->ia_blocks;
                        local->postbuf_blocks += postbuf->ia_blocks;

                        if (local->prebuf_size < prebuf->ia_size)
                                local->prebuf_size = prebuf->ia_size;

                        if (local->postbuf_size < postbuf->ia_size)
                                local->postbuf_size = postbuf->ia_size;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret != -1) {
                        local->pre_buf.ia_blocks  = local->prebuf_blocks;
                        local->pre_buf.ia_size    = local->prebuf_size;
                        local->post_buf.ia_blocks = local->postbuf_blocks;
                        local->post_buf.ia_size   = local->postbuf_size;
                }

                STRIPE_STACK_UNWIND (fsync, frame, local->op_ret,
                                     local->op_errno, &local->pre_buf,
                                     &local->post_buf, NULL);
        }
out:
        return 0;
}

int32_t
stripe_fsync (call_frame_t *frame, xlator_t *this, fd_t *fd, int32_t flags, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = 1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;
        trav = this->children;

        gf_log (this->name, GF_LOG_WARNING, "BAY: fsync" );
        
        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_fsync_cbk, trav->xlator,
                            trav->xlator->fops->fsync, fd, flags, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (fsync, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}

int32_t
stripe_fstat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct iatt *buf, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }

                if (op_ret == 0) {
                        local->op_ret = 0;

                        if (FIRST_CHILD(this) == prev->this)
                                local->stbuf = *buf;

                        local->stbuf_blocks += buf->ia_blocks;
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret != -1) {
                        local->stbuf.ia_size   = local->fctx->real_size;
                        local->stbuf.ia_blocks = local->stbuf_blocks;
                }

                STRIPE_STACK_UNWIND (fstat, frame, local->op_ret,
                                     local->op_errno, &local->stbuf, NULL);
        }

out:
        return 0;
}

int32_t
stripe_fstat (call_frame_t *frame,
              xlator_t *this,
              fd_t *fd, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = 1;
        uint64_t          tmp_fctx = 0;
        stripe_fd_ctx_t  *fctx = NULL;

        fd_ctx_get (fd, this, &tmp_fctx);
        if (!tmp_fctx) {
                op_errno = EBADFD;
                goto err;
        }
        fctx = (stripe_fd_ctx_t *)(long)tmp_fctx;

        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        gf_log (this->name, GF_LOG_WARNING, "BAY: fstat" );
        
        
        priv = this->private;
        trav = this->children;

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->fctx = fctx;
        
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_fstat_cbk, trav->xlator,
                            trav->xlator->fops->fstat, fd, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (fstat, frame, -1, op_errno, NULL, NULL);
        return 0;
}


int32_t
stripe_ftruncate (call_frame_t *frame, xlator_t *this, fd_t *fd, off_t offset, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = 1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;
        trav = this->children;

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_truncate_cbk, trav->xlator,
                            trav->xlator->fops->ftruncate, fd, offset, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (ftruncate, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}


int32_t
stripe_fsyncdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local   = NULL;
        call_frame_t   *prev = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            (prev->this == FIRST_CHILD (this)))
                                local->failed = 1;
                }
                if (op_ret >= 0)
                        local->op_ret = op_ret;
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (local->failed)
                        local->op_ret = -1;

                STRIPE_STACK_UNWIND (fsyncdir, frame, local->op_ret,
                                     local->op_errno, NULL);
        }
out:
        return 0;
}

int32_t
stripe_fsyncdir (call_frame_t *frame, xlator_t *this, fd_t *fd, int32_t flags, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = 1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;
        trav = this->children;

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_fsyncdir_cbk, trav->xlator,
                            trav->xlator->fops->fsyncdir, fd, flags, NULL);
                trav = trav->next;
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (fsyncdir, frame, -1, op_errno, NULL);
        return 0;
}

/**
 * stripe_readv_cbk - get all the striped reads, and order it properly, send it
 *        to above layer after putting it in a single vector.
 */
int32_t
stripe_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct iovec *vector,
                  int32_t count, struct iatt *stbuf, struct iobref *iobref, dict_t *xdata)
{
        int32_t         index = 0;
        int32_t         callcnt = 0;
        int32_t         final_count = 0;
        int32_t         need_to_check_proper_size = 0;
        int32_t         full_block_start = 0;
        int32_t         req_block_start = 0;
        int32_t         req_block_end = 0;
        
        call_frame_t   *mframe = NULL;
        stripe_local_t *mlocal = NULL;
        stripe_local_t *local = NULL;
        //struct iobuf   *iobuf = NULL;
        struct iovec   *final_vec = NULL;
        struct iatt     tmp_stbuf = {0,};
        struct iatt    *tmp_stbuf_p = NULL; //need it for a warning
        struct iobref  *tmp_iobref = NULL;
        stripe_fd_ctx_t  *fctx = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto end;
        }

        local  = frame->local;
        index  = local->node_index;
        
        mframe = local->orig_frame;
        if (!mframe)
                goto out;

        mlocal = mframe->local;
        if (!mlocal)
                goto out;

        full_block_start=mlocal->full_block_start;
        req_block_start=mlocal->req_block_start;
        req_block_end=mlocal->req_block_end;

        gf_log (this->name, GF_LOG_WARNING,
        "BAY: readv stripe_readv_cbk: index %d full_beg=%d, beg=%d end=%d", 
        index,full_block_start,req_block_start, req_block_end);
        
        fctx = mlocal->fctx;

        LOCK (&mframe->lock);
        {
                mlocal->replies[index].op_ret = op_ret;
                mlocal->replies[index].op_errno = op_errno;
                mlocal->replies[index].requested_size = local->readv_size;
                if (op_ret >= 0) {
                        mlocal->replies[index].stbuf  = *stbuf;
                        mlocal->replies[index].count  = count;
                        mlocal->replies[index].vector = iov_dup (vector, count);
                        if (local->stbuf_size < stbuf->ia_size)
                                local->stbuf_size = stbuf->ia_size;
                        local->stbuf_blocks += stbuf->ia_blocks;

                        if (!mlocal->iobref)
                                mlocal->iobref = iobref_new ();
                        iobref_merge (mlocal->iobref, iobref);
                }
                callcnt = ++mlocal->call_count;
        }
        UNLOCK(&mframe->lock);

        if (callcnt == mlocal->wind_count) {
                op_ret = 0;

                for (index=0; index < mlocal->wind_count; index++) {
                        /* check whether each stripe returned
                         * 'expected' number of bytes */
                        if (mlocal->replies[index].op_ret == -1) {
                                op_ret = -1;
                                op_errno = mlocal->replies[index].op_errno;
                                break;
                        }
                        /* TODO: handle the 'holes' within the read range
                           properly */
                        if (mlocal->replies[index].op_ret <
                            mlocal->replies[index].requested_size) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "BAY: index=%d %d < %d",
                                        index, mlocal->replies[index].op_ret,
                                        mlocal->replies[index].requested_size
                                       );
         
                                need_to_check_proper_size = 1;
                        }

                        op_ret       += mlocal->replies[index].op_ret;
                        mlocal->count += mlocal->replies[index].count;
                }
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "BAY: op_ret==-1 is true");
                        
                        goto done;
                }
                if (need_to_check_proper_size) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "BAY: need to check proper size");

                        goto check_size;
                }

                final_vec = GF_CALLOC (mlocal->count, sizeof (struct iovec),
                                       gf_stripe_mt_iovec);

                if (!final_vec) {
                        op_ret = -1;
                        op_errno = ENOMEM;
                        goto done;
                }

                // getting an indexes to answer
                for (index = 0; index < mlocal->wind_count; index++) {
                        //curr_block=index+req_block_start;
                        //gf_log (this->name, GF_LOG_WARNING,
                        //        "BAY: debug %d %d", curr_block,get_checksum_block_num(curr_block,fctx->stripe_count));                    
                        
                        //if(curr_block<req_block_start || curr_block>req_block_end) {
                        //        gf_log (this->name, GF_LOG_WARNING,
                        //               "BAY: skipping %d, start=%d, end=%d", curr_block,req_block_start,req_block_end);
                        //} else if(is_checksum_block(curr_block,fctx->stripe_count)) {
                        //        gf_log (this->name, GF_LOG_WARNING,
                        //                "BAY: skipping %d, as checksum block", curr_block);                    
                        //} else {
                                memcpy ((final_vec + final_count),
                                        mlocal->replies[index].vector,
                                        (mlocal->replies[index].count *
                                        sizeof (struct iovec)));
                                final_count +=  mlocal->replies[index].count;
                        //}
                        GF_FREE (mlocal->replies[index].vector);
                }

                /* FIXME: notice that st_ino, and st_dev (gen) will be
                 * different than what inode will have. Make sure this doesn't
                 * cause any bugs at higher levels */
                memcpy (&tmp_stbuf, &mlocal->replies[0].stbuf,
                        sizeof (struct iatt));
                tmp_stbuf.ia_size = local->stbuf_size;
                tmp_stbuf.ia_blocks = local->stbuf_blocks;

                goto done;

check_size:
        op_ret = 0;

        final_count = 0;
        final_vec = GF_CALLOC (mlocal->count * 2, sizeof (struct iovec),
                                gf_stripe_mt_iovec);
        if (!final_vec) {
                op_ret = -1;
                op_errno = ENOMEM;
                goto done;
        }

        gf_log (this->name, GF_LOG_WARNING,
                "BAY: stripe_readv_fstat_cbk %d %d %d", full_block_start,req_block_start,req_block_end);
        
        mlocal->stbuf_size = fctx->real_size;
        

        for (index = 0; index < mlocal->wind_count; index++) {
                //curr_block=index+req_block_start;

                //if(curr_block<req_block_start || curr_block>req_block_end) {
                //        gf_log (this->name, GF_LOG_WARNING,
                //                "BAY: skipping %d, start=%d, end=%d", curr_block,req_block_start,req_block_end);
                //} else if(is_checksum_block(curr_block,fctx->stripe_count)) {
                //        gf_log (this->name, GF_LOG_WARNING,
                //                "BAY: skipping %d, as checksum block", curr_block);                    
                //} else {
                        //gf_log (this->name, GF_LOG_WARNING,
                        //        "BAY: i %d, %d", curr_block,mlocal->replies[index].op_ret);                    
                        
                        if (mlocal->replies[index].op_ret) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "BAY: test1 %d %d %d %d",
                                        (int) mlocal->offset,
                                        (int) mlocal->replies[index].op_ret,
                                        (int) mlocal->replies[index].vector->iov_len,
                                        (int) final_count
                                       );
                                memcpy ((final_vec + final_count), mlocal->replies[index].vector,
                                        (mlocal->replies[index].count * sizeof (struct iovec)));
                                final_count +=  mlocal->replies[index].count;
                                op_ret += mlocal->replies[index].op_ret;
                        }
                        //if ((mlocal->replies[index].op_ret <
                        //mlocal->replies[index].requested_size) &&
                        //(mlocal->stbuf_size > (curr_block*fctx->stripe_size + op_ret))) {
                        //        gf_log (this->name, GF_LOG_WARNING,
                        //                "BAY: test2", curr_block,mlocal->replies[index].op_ret);                    

                                /* Fill in 0s here */
                        //        final_vec[final_count].iov_len  =
                        //                (mlocal->replies[index].requested_size -
                        //                mlocal->replies[index].op_ret);
                        //        iobuf = iobuf_get (this->ctx->iobuf_pool);
                        //        if (!iobuf) {
                        //                gf_log (this->name, GF_LOG_ERROR,
                        //                        "Out of memory.");
                        //                op_ret = -1;
                        //                op_errno = ENOMEM;
                        //                goto done;
                        //        }
                        //        memset (iobuf->ptr, 0, final_vec[final_count].iov_len);
                        //        iobref_add (mlocal->iobref, iobuf);
                        //        final_vec[final_count].iov_base = iobuf->ptr;
                        //
                        //        op_ret += final_vec[final_count].iov_len;
                        //        final_count++;
                        //}
                //}
                GF_FREE (mlocal->replies[index].vector);
        }

        /* FIXME: notice that st_ino, and st_dev (gen) will be
        * different than what inode will have. Make sure this doesn't
        * cause any bugs at higher levels */
        memcpy (&tmp_stbuf, &mlocal->replies[0].stbuf,
                sizeof (struct iatt));
        tmp_stbuf.ia_size = mlocal->stbuf_size;

                
        goto done;

done:
                GF_FREE (mlocal->replies);
                tmp_iobref = mlocal->iobref;
                /* work around for nfs truncated read. Bug 3774 */
                tmp_stbuf_p = &tmp_stbuf;
                WIPE (tmp_stbuf_p);

                int sum=0;
                for(index = 0; index < final_count; index++) {
                        sum += final_vec[index].iov_len;        
                }
                
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: stripe_readv_cbk: DONE, returning %d, op_errno=%d op_ret=%d sum=%d offset=%d size=%d", 
                        (int) final_count,(int) op_errno,(int) op_ret,(int) sum,
                        (int) mlocal->offset, (int) mlocal->readv_size);

                STRIPE_STACK_UNWIND (readv, mframe, op_ret, op_errno, final_vec,
                                     final_count, &tmp_stbuf, tmp_iobref, NULL);

                iobref_unref (tmp_iobref);
                if (final_vec)
                        GF_FREE (final_vec);
                goto out;
        }

out:
        STRIPE_STACK_DESTROY (frame);
end:
        return 0;
}


int32_t
stripe_readv (call_frame_t *frame, xlator_t *this, fd_t *fd,
              size_t size, off_t offset, uint32_t flags, dict_t *xdata)
{
        int32_t           op_errno = EINVAL;
        int32_t           idx = 0;
        int32_t           index = 0;
        int32_t           wind_num = 0;
        int32_t           num_stripe = 0;
        int32_t           remaining_size = 0;

        size_t            frame_size = 0;
        off_t             frame_offset = 0;
        uint64_t          tmp_fctx = 0;
        uint64_t          stripe_size = 0;
        off_t             req_block_start = 0;
        off_t             req_block_end = 0;
        off_t             full_block_start = 0;
        off_t             full_block_end = 0;        
        stripe_local_t   *local = NULL;
        call_frame_t     *rframe = NULL;
        stripe_local_t   *rlocal = NULL;
        stripe_fd_ctx_t  *fctx = NULL;
        stripe_private_t *priv = NULL;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (this->private, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;

        fd_ctx_get (fd, this, &tmp_fctx);
        if (!tmp_fctx) {
                op_errno = EBADFD;
                goto err;
        }
        fctx = (stripe_fd_ctx_t *)(long)tmp_fctx;
        stripe_size = fctx->stripe_size;

        gf_log (this->name, GF_LOG_WARNING,
               "BAY: READV stripe_size: %d, size: %d, offset: %d realsize=%d", 
                (int) fctx->stripe_size, (int) size, (int) (int) offset,(int) fctx->real_size);

        if (!stripe_size) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "Wrong stripe size for the file");
                goto err;
        }
        /* The file is stripe across the child nodes. Send the read request
         * to the child nodes appropriately after checking which region of
         * the file is in which child node. Always '0-<stripe_size>' part of
         * the file resides in the first child.
         */
        req_block_start = get_phys_block_num(
                offset/stripe_size,fctx->stripe_count);
        req_block_end = get_phys_block_num(
                (offset+size-1)/ stripe_size, fctx->stripe_count);
        full_block_start=floor(req_block_start,fctx->stripe_count);
        full_block_end=req_block_end / fctx->stripe_count * fctx->stripe_count + fctx->stripe_count - 1;
        
        num_stripe = full_block_end - full_block_start + 1;

        gf_log (this->name, GF_LOG_WARNING,
               "BAY: readv block_start: %d, block_end: %d, test: %d %d full_block_start=%d full_block_end=%d", 
                (int) req_block_start, (int) req_block_end, (int) num_stripe, 
                (int) fctx->stripe_count, (int) full_block_start, (int) full_block_end);
        
        
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        frame->local = local;

        /* This is where all the vectors should be copied. */
        local->replies = GF_CALLOC (num_stripe, sizeof (struct readv_replies),
                                    gf_stripe_mt_readv_replies);
        if (!local->replies) {
                op_errno = ENOMEM;
                goto err;
        }

        //off_index = (offset / stripe_size) % fctx->stripe_count;
        
        //off_index = get_phys_block_num(offset / stripe_size,fctx->stripe_count);
        //off_index = off_index % fctx->stripe_count;
        
        local->readv_size = size;
        local->offset     = offset;
        local->fd         = fd_ref (fd);
        local->fctx       = fctx;

        local->full_block_start=full_block_start;
        local->req_block_start=req_block_start;
        local->req_block_end=req_block_end;
        
        if (priv->nodes_down==0) {
                // compute the wind count
                local->wind_count = 0;
                for (index = req_block_start; index <= req_block_end; index++) {
                        if(is_checksum_block(index,fctx->stripe_count))
                                continue;
                        local->wind_count++;
                }
                
                remaining_size = size;
                wind_num = 0;
                
                //index is logical
                for (index = req_block_start; index <= req_block_end; index++) {
                        if(is_checksum_block(index,fctx->stripe_count))
                                continue;
                        
                        rframe = copy_frame (frame);
                        rlocal = GF_CALLOC (1, sizeof (stripe_local_t),
                                        gf_stripe_mt_stripe_local_t);
                        if (!rlocal) {
                                op_errno = ENOMEM;
                                goto err;
                        }
                        
                        if(index == req_block_start)
                                frame_offset = index*stripe_size + offset % stripe_size;
                        else
                                frame_offset = index*stripe_size;
                        
                        if(index == req_block_start)
                                frame_size = stripe_size - offset % stripe_size;
                        else
                                frame_size = stripe_size;
                        
                        if(remaining_size<frame_size)
                                frame_size = remaining_size;
                                
                        gf_log (this->name, GF_LOG_WARNING,
                                "BAY: readv index=%d req_block_end=%d frame_size=%d frame_offset=%d",
                                (int) index, (int) req_block_end, 
                                (int) frame_size, (int) frame_offset);

                        rframe->local = rlocal;
                        rlocal->orig_frame = frame;
                        rlocal->node_index = wind_num;
                        rlocal->readv_size = frame_size;
                        rlocal->block_num = index;
                        idx = (index % fctx->stripe_count);
                        
                        STACK_WIND (rframe, stripe_readv_cbk, fctx->xl_array[idx],
                                fctx->xl_array[idx]->fops->readv,
                                fd, frame_size, frame_offset, flags, xdata);

                        remaining_size -= frame_size;
                        wind_num += 1;
                }
        } else {
                local->wind_count = num_stripe;

                //index is logical
                for (index = full_block_start; index <= full_block_end; index++) {
                        rframe = copy_frame (frame);
                        rlocal = GF_CALLOC (1, sizeof (stripe_local_t),
                                        gf_stripe_mt_stripe_local_t);
                        if (!rlocal) {
                                op_errno = ENOMEM;
                                goto err;
                        }
                        
                        frame_offset = index*stripe_size;
                        frame_size = stripe_size;

                        if(index == req_block_end) {
                                frame_size=size % stripe_size;
                                if(frame_size==0) {
                                        frame_size=stripe_size;
                                }
                        }

                        if(index == req_block_start) {
                                frame_offset += offset%stripe_size;
                                frame_size -= offset%stripe_size;
                        }
                        

                        gf_log (this->name, GF_LOG_WARNING,
                                "BAY: readv index=%d req_block_end=%d frame_size=%d frame_offset=%d",
                                (int) index, (int) req_block_end, 
                                (int) frame_size, (int) frame_offset);

                        rframe->local = rlocal;
                        rlocal->orig_frame = frame;
                        rlocal->node_index = index-full_block_start;
                        rlocal->readv_size = frame_size;
                        idx = (index % fctx->stripe_count);
                        
                        STACK_WIND (rframe, stripe_readv_cbk, fctx->xl_array[idx],
                                fctx->xl_array[idx]->fops->readv,
                                fd, frame_size, frame_offset, flags, xdata);
                }                
        }

        return 0;
err:
        if (rframe)
                STRIPE_STACK_DESTROY (rframe);

        STRIPE_STACK_UNWIND (readv, frame, -1, op_errno, NULL, 0, NULL, NULL, NULL);
        return 0;
}


int
stripe_writev_setattr_cbk (call_frame_t *frame, void *cookie,
                      xlator_t *this, int op_ret, int op_errno, dict_t *xdata)
{
        stripe_local_t *local = NULL;


        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;
        
        if(op_ret!=0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: failed to set file size in xattr, errno=%d", op_ret);
        }

        LOCK(&frame->lock);
        {
                local->wind_count--;
        }
        UNLOCK(&frame->lock);
        
        if(local->wind_count==0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: stripe_writev_setattr_cbk, local->op_ret=%d, op_ret=%d", local->op_ret, op_ret);
                
                STRIPE_STACK_UNWIND (writev, frame, local->op_ret,
                                local->op_errno, &local->pre_buf,
                                &local->post_buf, NULL);
        }
                
out:
        return 0;
}

int32_t
stripe_writev_chksum_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                   struct iatt *postbuf, dict_t *xdata)
{
        stripe_local_t *local = NULL;        
        
        call_frame_t   *mframe = NULL;  // the main frame of operation
        stripe_local_t *mlocal = NULL;

        stripe_fd_ctx_t  *fctx = NULL;
        dict_t           *dict           = NULL;
        int32_t           ret            = -1;
        int32_t           idx;

        char              *checksum_data = NULL;

        char            real_size_xattr[256]        = {0,};

        int32_t           write_op_ret   = -1;
        int32_t           write_op_errno = EINVAL;
        
        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;

        mframe = local->orig_frame;
        if (!mframe)
                goto out;

        mlocal = mframe->local;
        if (!mlocal)
                goto out;

        fctx = mlocal->fctx;

        checksum_data = cookie;
        GF_FREE(checksum_data);
        
        LOCK(&mframe->lock);
        {
                mlocal->group_count--;
        }
        UNLOCK(&mframe->lock);
        
        if (mlocal->group_count == 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: stripe_writev_cbk unwinding,fctx->real_size=%d",
                        (int) fctx->real_size
                       );
                
                if(mlocal->op_ret==-1)
                        goto err;

                dict=dict_new();
                if (!dict) {
                        mlocal->op_errno = ENOMEM;
                        mlocal->op_ret = -1;
                        goto err;
                }

                (void) snprintf (real_size_xattr, 256,
                        "trusted.%s.real-size",
                        this->name);
                ret = dict_set_uint64 (dict, real_size_xattr, (uint64_t) 
                max(fctx->real_size,mlocal->offset+mlocal->op_ret));
                
                if(ret) {
                        mlocal->op_errno = ENOMEM;
                        mlocal->op_ret = -1;
                        goto err;                        
                }
                mlocal->wind_count=fctx->stripe_count;

                for(idx=0;idx<fctx->stripe_count;idx++) {
                        STACK_WIND (mframe, stripe_writev_setattr_cbk, fctx->xl_array[idx],
                                fctx->xl_array[idx]->fops->fsetxattr, mlocal->fd, dict, ATTR_ROOT, NULL);
                }

        }
        
        goto out;
err:
        STRIPE_STACK_UNWIND (writev, mframe, write_op_ret,
                write_op_errno, &mlocal->pre_buf,
                &mlocal->post_buf, NULL);

out:
        STRIPE_STACK_DESTROY (frame);
        return 0;
}


int32_t
stripe_writev_chksum_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t read_op_ret, int32_t read_op_errno, struct iovec *read_vector,
                  int32_t read_count, struct iatt *read_stbuf, struct iobref *read_iobref, dict_t *xdata)
{
        off_t             off            = 0;
        char              *checksum_data = NULL;
        
        int32_t           data_size      = 0;

        int32_t           write_op_ret   = -1;
        int32_t           write_op_errno = EINVAL;

        struct iovec      iovec[1]       = {{0,}};

        struct iobuf     *iobuf          = NULL;
        
        stripe_local_t   *local          = NULL;        
        
        call_frame_t     *mframe         = NULL;  // the main frame of operation
        stripe_local_t   *mlocal         = NULL;

        stripe_fd_ctx_t  *fctx           = NULL;
        
        int32_t           idx;

        
        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;

        mframe = local->orig_frame;
        if (!mframe)
                goto out;

        mlocal = mframe->local;
        if (!mlocal)
                goto out;

        fctx = mlocal->fctx;
        if (!fctx)
                goto out;
        
        
        for (idx = 0; idx< read_count; idx ++)
                data_size += read_vector[idx].iov_len;
        
        if(data_size > fctx->stripe_size) {
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: read operation returned much data, than expected on write_checksum operation");
                write_op_errno = EINVAL;
                goto err;
        }
        
        checksum_data = GF_CALLOC (fctx->stripe_size, sizeof(char),gf_stripe_mt_char);
        if ( !checksum_data) {
                write_op_errno = ENOMEM;
                goto err;                
        }
        
        off = 0;
        for (idx = 0; idx < read_count; idx++) {
                memcpy(checksum_data, read_vector[idx].iov_base,read_vector[idx].iov_len);
                off+=read_vector[idx].iov_len;
        }
        
        xor_data(checksum_data,checksum_data,local->checksum_xor_with,fctx->stripe_size);
        GF_FREE(local->checksum_xor_with);
        
        //iobuf = iobuf_get2 (this->ctx->iobuf_pool,
        //                fctx->stripe_size);
        //if (!iobuf) {
        //        gf_log (this->name, GF_LOG_ERROR, "Out of memory.");
        //        write_op_errno = ENOMEM;
        //        goto err;
        //}
        
        // JUST FOR TEST
        //for (idx = 0; idx < fctx->stripe_size; idx++) {
        //        checksum_data[idx]='P';
        //}
    
        //memcpy(iobuf->ptr,checksum_data,fctx->stripe_size);
        //GF_FREE(checksum_data);
        //iobref_add (mlocal->iobref, iobuf);
    
        idx = local->checksum_blocknum_in_group % fctx->stripe_count;
        iovec[0].iov_base = checksum_data;
        iovec[0].iov_len = fctx->stripe_size;

        gf_log (this->name, GF_LOG_WARNING,
        "BAY: writing checksum, beginning with %d data = %x, len = %d, idx = %d",
        (int) local->checksum_blocknum_in_group * fctx->stripe_size,
        (int)checksum_data,(int) data_size,idx
        );

        STACK_WIND_COOKIE (frame, stripe_writev_chksum_writev_cbk,checksum_data, fctx->xl_array[idx],
                fctx->xl_array[idx]->fops->writev, mlocal->fd, iovec,
                1, local->checksum_blocknum_in_group * fctx->stripe_size,
                0, read_iobref, xdata);
        goto out;
        
err:
        if(local->checksum_xor_with)
                GF_FREE(local->checksum_xor_with);
        STRIPE_STACK_DESTROY (frame);
        STRIPE_STACK_UNWIND (writev, mframe, write_op_ret,
                        write_op_errno, &mlocal->pre_buf,
                        &mlocal->post_buf, NULL);

out:
        return 0;
}


int32_t
stripe_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                   struct iatt *postbuf, dict_t *xdata)
{
        int32_t         callcnt = 0;
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;
        int32_t           ret  = -1;
        stripe_fd_ctx_t  *fctx = NULL;
        int             idx;

        call_frame_t   *mframe = NULL;  // the frame of operation group
        stripe_local_t *mlocal = NULL;

        call_frame_t   *mmframe = NULL; // the frame of writev
        stripe_local_t *mmlocal = NULL;
        
        
        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        local = frame->local;

        mframe = local->orig_frame;
        if (!mframe)
                goto out;

        mlocal = mframe->local;
        if (!mlocal)
                goto out;
     
        mmframe = mlocal->orig_frame;
        if (!mmframe)
                goto out;

        mmlocal = mmframe->local;
        if (!mmlocal)
                goto out;

        fctx = mmlocal->fctx;

        gf_log (this->name, GF_LOG_WARNING,
                "BAY: stripe_writev_cbk ");
        
        LOCK(&mmframe->lock);
        {
                callcnt = ++mmlocal->call_count;
                
                mlocal->call_count_in_group--;
                //if (mlocal->call_count_in_group == 0)
                //        mmlocal->group_count--;
                
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        mmlocal->op_errno = op_errno;
                        mmlocal->op_ret = -1;
                }
                if (op_ret >= 0) {
                        mmlocal->op_ret += op_ret;
                        mmlocal->post_buf = *postbuf;
                        mmlocal->pre_buf = *prebuf;
                }
        }
        UNLOCK (&mmframe->lock);

        
        
        if (mlocal->call_count_in_group==0) {
                // ALSO WRITE THE CHECKSUM BLOCK
                // read the old checksum block and xor it with new data
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: group finished, checksum_block=%d",
                        (int) mlocal->checksum_blocknum_in_group
                       );
                idx = mlocal->checksum_blocknum_in_group % fctx->stripe_count;

                STACK_WIND (mframe, stripe_writev_chksum_readv_cbk, fctx->xl_array[idx],
                                fctx->xl_array[idx]->fops->readv,
                                mmlocal->fd, 
                                fctx->stripe_size, 
                                mlocal->checksum_blocknum_in_group * fctx->stripe_size, 
                                0, NULL);
        }
        
        goto out;
err:
        STRIPE_STACK_UNWIND (writev, mmframe, mmlocal->op_ret,
                             mmlocal->op_errno, &mmlocal->pre_buf,
                             &mmlocal->post_buf, NULL);
        
out:
        STRIPE_STACK_DESTROY (frame);
        return 0;
}

int32_t
stripe_writev_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t read_op_ret, int32_t read_op_errno, struct iovec *read_vector,
                  int32_t read_count, struct iatt *read_stbuf, struct iobref *read_iobref, dict_t *xdata)
{
        stripe_local_t   *local = NULL;

        off_t             req_block_start = 0;
        off_t             req_block_end = 0;
        off_t             full_block_start = 0;
        off_t             full_block_end = 0;        

        off_t             begin_group_block = 0;
        off_t             curr_block = 0;
   
        int32_t           offset_offset = 0;
        
        off_t             block_offset = 0;
        
        call_frame_t     *rframe = NULL; // A frame for groups of operations
        stripe_local_t   *rlocal = NULL;
        
        call_frame_t     *rrframe = NULL; // A frame for one operation
        stripe_local_t   *rrlocal = NULL;
        
        // data from write contex
        fd_t             *write_fd = NULL;
        struct iovec     *write_vector = NULL;
        int32_t           write_count = 0;
        off_t             write_offset;
        uint32_t          write_flags = 0;
        
        off_t             fill_size = 0;
        uint64_t          tmp_fctx = 0;
        
        uint64_t          stripe_size = 0;

        int32_t           num_stripe = 0;
        
        int32_t           remaining_size = 0;
        int               i = 0;

        int32_t           idx = 0;
        off_t             off = 0;
                
        int32_t           tmp_count = 0;
        struct iovec     *tmp_vec = NULL;
                
        stripe_fd_ctx_t  *fctx = NULL;
        struct saved_write_contex *wc = NULL;
        
        int32_t           write_op_ret = -1;
        int32_t           write_op_errno = EINVAL;

        char              *old_data = NULL;
        char              *new_data = NULL;
        int32_t           data_size = 0;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (cookie, err);

        //if(read_op_ret ==  -1) {
        //        write_op_errno = read_op_errno;
        //        goto err;
        //}
        
        // restoring context
        wc = cookie;
        write_fd = wc->fd;
        write_vector = wc->vector;
        write_count = wc->count;
        write_offset = wc->offset;
        write_flags = wc->flags;
        GF_FREE(wc);
        
        for (idx = 0; idx< write_count; idx ++)
                data_size += write_vector[idx].iov_len;
        
        old_data = GF_CALLOC (data_size, sizeof(char),gf_stripe_mt_char);
        new_data = GF_CALLOC (data_size, sizeof(char),gf_stripe_mt_char);
        if ( !old_data || !new_data ) {
                write_op_errno = ENOMEM;
                goto err;                
        }
        
        off = 0;
        for (idx = 0; idx < read_count; idx++) {
                memcpy(old_data + off, read_vector[idx].iov_base,read_vector[idx].iov_len);
                off+=read_vector[idx].iov_len;
        }

        off = 0;
        for (idx = 0; idx < write_count; idx++) {
                memcpy(new_data + off, write_vector[idx].iov_base,write_vector[idx].iov_len);
                off+=write_vector[idx].iov_len;
        }

        tmp_count = write_count;
        
        gf_log (this->name, GF_LOG_WARNING,
                "BAY: stripe_writev_readv_cbk read_op_ret=%d read_op_errno=%d",
                read_op_ret, read_op_errno);
        
        fd_ctx_get (write_fd, this, &tmp_fctx);
        if (!tmp_fctx) {
                write_op_errno = EINVAL;
                goto err;
        }
        fctx = (stripe_fd_ctx_t *)(long)tmp_fctx;
        stripe_size = fctx->stripe_size;

        req_block_start = get_phys_block_num(
                write_offset/stripe_size,fctx->stripe_count);
        req_block_end = get_phys_block_num(
                (write_offset+data_size-1)/ stripe_size, fctx->stripe_count);
        full_block_start=floor(req_block_start,fctx->stripe_count);
        full_block_end=req_block_end / fctx->stripe_count * fctx->stripe_count + fctx->stripe_count - 1;
        
        num_stripe = full_block_end - full_block_start + 1;
                
        /* File has to be stripped across the child nodes */
        remaining_size = data_size;

        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                write_op_errno = ENOMEM;
                goto err;
        }
        frame->local = local;
        local->stripe_size = stripe_size;
        local->fd = fd_ref (write_fd);
        local->fctx = fctx;
        local->size = data_size;
        local->offset = write_offset;
        local->group_count = num_stripe / fctx->stripe_count;
        local->iobref = read_iobref;

        gf_log (this->name, GF_LOG_WARNING,
                "BAY: writev req_block_start=%d req_block_end=%d full_block_start=%d full_block_end=%d",
                (int) req_block_start, (int) req_block_end, 
                (int) full_block_start, (int) full_block_end);

        if( (full_block_end+1) % fctx->stripe_count != 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "BAY: writev: full_block_end=%d. This is very wrong.",
                        (int) full_block_end);                
        }

        // we divide the big writing task into smaller tasks, which affect only
        // one checksum block
        for(begin_group_block=full_block_start; 
            begin_group_block!=full_block_end+1; 
            begin_group_block+=fctx->stripe_count) {
                
                rframe = copy_frame (frame);
                rlocal = GF_CALLOC (1, sizeof (stripe_local_t),
                                    gf_stripe_mt_stripe_local_t);
                if (!rlocal) {
                        write_op_errno = ENOMEM;
                        goto err;
                }
                
                rframe->local = rlocal;
                rlocal->orig_frame = frame;
                
                rlocal->checksum_xor_with = GF_CALLOC(stripe_size, sizeof (char),
                                                      gf_stripe_mt_char);
                if (!rlocal->checksum_xor_with) {
                        write_op_errno = ENOMEM;
                        goto err;                      
                }
                
                memset(rlocal->checksum_xor_with,0,stripe_size); 
                
                rlocal->checksum_blocknum_in_group = get_checksum_block_num(begin_group_block,fctx->stripe_count);
                
                // calculate a num of calls in current block
                rlocal->call_count_in_group = 0;
                for(curr_block=begin_group_block;
                    curr_block<begin_group_block+fctx->stripe_count;
                    curr_block++) {
                        if(curr_block<req_block_start || curr_block>req_block_end)
                                continue;   
                        if(is_checksum_block(curr_block,fctx->stripe_count)) 
                                continue;
                        
                        rlocal->call_count_in_group++;    
                }
                
                for(curr_block=begin_group_block;
                    curr_block<begin_group_block+fctx->stripe_count;
                    curr_block++) {
                        if(curr_block<req_block_start || curr_block>req_block_end)
                                continue;   
                        if(is_checksum_block(curr_block,fctx->stripe_count)) 
                                continue;

                        rrframe = copy_frame (rframe);
                        rrlocal = GF_CALLOC (1, sizeof (stripe_local_t),
                                        gf_stripe_mt_stripe_local_t);
                        if (!rrlocal) {
                                write_op_errno = ENOMEM;
                                goto err;
                        }
                        
                        rrframe->local = rrlocal;
                        rrlocal->orig_frame = rframe;
                        
                        idx = curr_block % fctx->stripe_count;
                        
                        // fill the beginning and end of each read/write task
                        fill_size = local->stripe_size -
                             (write_offset + offset_offset) % local->stripe_size;
                        if (fill_size > remaining_size)
                                fill_size = remaining_size;
                        remaining_size -= fill_size;
                        
                        tmp_count = iov_subset (write_vector, write_count, offset_offset,
                                        offset_offset + fill_size, NULL);
                        tmp_vec = GF_CALLOC (tmp_count, sizeof (struct iovec),
                                        gf_stripe_mt_iovec);
                        if (!tmp_vec) {
                                write_op_errno = ENOMEM;
                                goto err;
                        }
                        tmp_count = iov_subset (write_vector, write_count, offset_offset,
                                                offset_offset + fill_size, tmp_vec);

                        rrlocal->count = tmp_count;
                        rrlocal->iovec = tmp_vec;
                        
                        local->wind_count++;
                        if (remaining_size == 0)
                                local->unwind = 1;
                        
                        block_offset = (write_offset + offset_offset) % local->stripe_size;
                        
                        xor_data_with(rlocal->checksum_xor_with + block_offset,
                                 old_data + offset_offset,
                                 new_data + offset_offset,
                                 fill_size);
                        
                        gf_log (this->name, GF_LOG_WARNING,
                                "BAY: writev winding for block %d, orig_offset=%d, new_offset=%d, checksum_xor_with=%d", 
                                (int) curr_block,(int) (write_offset + offset_offset),
                                (int) (local->stripe_size * curr_block + block_offset),
                                (int) rlocal->checksum_xor_with[0]
                               );
                        
                        STACK_WIND (rrframe, stripe_writev_cbk, fctx->xl_array[idx],
                            fctx->xl_array[idx]->fops->writev, write_fd, tmp_vec,
                            tmp_count, 
                            local->stripe_size * curr_block + block_offset, 
                            write_flags, read_iobref, xdata);
                        GF_FREE (tmp_vec);
                        
                        offset_offset += fill_size;
                        if (remaining_size == 0)
                                break;
                }
        }
        
        goto mem_clean;        

err:
        STRIPE_STACK_UNWIND (writev, frame, -1, 
                             write_op_errno, NULL, NULL, NULL);
mem_clean:
        
        if(old_data)
                GF_FREE (old_data);
        if(new_data)
                GF_FREE (new_data);
        
        return 0;
}

int32_t
stripe_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
               struct iovec *vector, int32_t count, off_t offset,
               uint32_t flags, struct iobref *iobref, dict_t *xdata)
{
        struct iobref *iobref_copy = NULL;
        
        int32_t           i = 0;
        int32_t           total_size = 0;
        int32_t           op_errno = 1;
        
        struct saved_write_contex *wc = NULL; // we have to save write contex
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        gf_log (this->name, GF_LOG_WARNING,
        "BAY: WRITEV");

        /* Saving write contex */
        wc = GF_CALLOC(1, sizeof (struct saved_write_contex),
                       gf_stripe_mt_saved_write_contex);
        if(!wc) {
                op_errno = ENOMEM;
                goto err;                
        }
        
        wc->fd=fd;
        wc->vector=vector;
        wc->count=count;
        wc->offset=offset;
        wc->flags=flags;
        
        // Calculating size of fs query
        for (i = 0; i< count; i ++)
                total_size += vector[i].iov_len;
        
        
        STACK_WIND_COOKIE (frame, stripe_writev_readv_cbk, wc, this,
                this->fops->readv, fd, total_size, offset, flags, xdata);
        return 0;
                      
err:
        STRIPE_STACK_UNWIND (writev, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}


int32_t
stripe_release (xlator_t *this, fd_t *fd, dict_t *xdata)
{
        uint64_t          tmp_fctx = 0;
        stripe_fd_ctx_t  *fctx = NULL;

        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

        fd_ctx_del (fd, this, &tmp_fctx);
        if (!tmp_fctx) {
                goto err;
        }

        fctx = (stripe_fd_ctx_t *)(long)tmp_fctx;

        if (!fctx->static_array)
                GF_FREE (fctx->xl_array);

        GF_FREE (fctx);

err:
	return 0;
}

int
stripe_forget (xlator_t *this, inode_t *inode)
{
        (void) inode_ctx_del (inode, this, 0);
        return 0;
}

int32_t
notify (xlator_t *this, int32_t event, void *data, ...)
{
        stripe_private_t *priv = NULL;
        int               down_client = 0;
        int               i = 0;

        if (!this)
                return 0;

        priv = this->private;
        if (!priv)
                return 0;

        switch (event)
        {
        case GF_EVENT_CHILD_UP:
        case GF_EVENT_CHILD_CONNECTING:
        {
                /* get an index number to set */
                for (i = 0; i < priv->child_count; i++) {
                        if (data == priv->xl_array[i])
                                break;
                }
                priv->state[i] = 1;
                for (i = 0; i < priv->child_count; i++) {
                        if (!priv->state[i])
                                down_client++;
                }

                LOCK (&priv->lock);
                {
                        priv->nodes_down = down_client;
                        if (data == FIRST_CHILD (this))
                                priv->first_child_down = 0;
                        if (!priv->nodes_down)
                                default_notify (this, event, data);
                }
                UNLOCK (&priv->lock);
        }
        break;
        case GF_EVENT_CHILD_DOWN:
        {
                /* get an index number to set */
                for (i = 0; i < priv->child_count; i++) {
                        if (data == priv->xl_array[i])
                                break;
                }
                priv->state[i] = 0;
                for (i = 0; i < priv->child_count; i++) {
                        if (!priv->state[i])
                                down_client++;
                }

                LOCK (&priv->lock);
                {
                        priv->nodes_down = down_client;

                        if (data == FIRST_CHILD (this))
                                priv->first_child_down = 1;
                        if (priv->nodes_down)
                                default_notify (this, event, data);
                }
                UNLOCK (&priv->lock);
        }
        break;

        default:
        {
                /* */
                default_notify (this, event, data);
        }
        break;
        }

        return 0;
}

int
set_stripe_block_size (xlator_t *this, stripe_private_t *priv, char *data)
{
        int                    ret = -1;
        char                  *tmp_str = NULL;
        char                  *tmp_str1 = NULL;
        char                  *dup_str = NULL;
        char                  *stripe_str = NULL;
        char                  *pattern = NULL;
        char                  *num = NULL;
        struct stripe_options *temp_stripeopt = NULL;
        struct stripe_options *stripe_opt = NULL;

        if (!this || !priv || !data)
                goto out;

        /* Get the pattern for striping.
           "option block-size *avi:10MB" etc */
        stripe_str = strtok_r (data, ",", &tmp_str);
        while (stripe_str) {
                dup_str = gf_strdup (stripe_str);
                stripe_opt = CALLOC (1, sizeof (struct stripe_options));
                if (!stripe_opt) {
                        GF_FREE (dup_str);
                        goto out;
                }

                pattern = strtok_r (dup_str, ":", &tmp_str1);
                num = strtok_r (NULL, ":", &tmp_str1);
                if (!num) {
                        num = pattern;
                        pattern = "*";
                }
                if (gf_string2bytesize (num, &stripe_opt->block_size) != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "invalid number format \"%s\"", num);
                        goto out;
                }

                if (stripe_opt->block_size < 512) {
                        gf_log (this->name, GF_LOG_ERROR, "Invalid Block-size: "
                                "%s. Should be atleast 512 bytes", num);
                        goto out;
                }
                if (stripe_opt->block_size % 512) {
                        gf_log (this->name, GF_LOG_ERROR, "Block-size: %s should"
                                " be a multiple of 512 bytes", num);
                        goto out;
                }

                memcpy (stripe_opt->path_pattern, pattern, strlen (pattern));

                gf_log (this->name, GF_LOG_DEBUG,
                        "block-size : pattern %s : size %"PRId64,
                        stripe_opt->path_pattern, stripe_opt->block_size);

                if (!priv->pattern) {
                        priv->pattern = stripe_opt;
                } else {
                        temp_stripeopt = priv->pattern;
                        while (temp_stripeopt->next)
                                temp_stripeopt = temp_stripeopt->next;
                        temp_stripeopt->next = stripe_opt;
                }
                stripe_str = strtok_r (NULL, ",", &tmp_str);
                GF_FREE (dup_str);
        }

        ret = 0;
out:
        return ret;
}

int32_t
stripe_iatt_merge (struct iatt *from, struct iatt *to)
{
        if (to->ia_size < from->ia_size)
                to->ia_size = from->ia_size;
        if (to->ia_mtime < from->ia_mtime)
                to->ia_mtime = from->ia_mtime;
        if (to->ia_ctime < from->ia_ctime)
                to->ia_ctime = from->ia_ctime;
        if (to->ia_atime < from->ia_atime)
                to->ia_atime = from->ia_atime;
        return 0;
}

int32_t
stripe_readdirp_entry_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                                int32_t op_ret, int32_t op_errno, struct iatt *buf)
{
        gf_dirent_t    *entry = NULL;
        stripe_local_t *local = NULL;
        int32_t        done = 0;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log (this->name, GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }
        entry = cookie;
        local = frame->local;
        LOCK (&frame->lock);
        {

                local->wind_count--;
                if (!local->wind_count)
                        done = 1;
                if (op_ret == -1) {
                        local->op_errno = op_errno;
                        local->op_ret = op_ret;
                        goto unlock;
                }
                stripe_iatt_merge (buf, &entry->d_stat);
        }
unlock:
        UNLOCK(&frame->lock);

        if (done) {
                frame->local = NULL;
                STRIPE_STACK_UNWIND (readdir, frame, local->op_ret,
                                     local->op_errno, &local->entries, NULL );

                gf_dirent_free (&local->entries);
                stripe_local_wipe (local);
                GF_FREE (local);
        }
out:
        return 0;

}

int
stripe_setxattr_cbk (call_frame_t *frame, void *cookie,
                     xlator_t *this, int op_ret, int op_errno, dict_t *xdata)
{
        STRIPE_STACK_UNWIND (setxattr, frame, op_ret, op_errno, xdata);
        return 0;
}

int
stripe_setxattr (call_frame_t *frame, xlator_t *this,
                 loc_t *loc, dict_t *dict, int flags, dict_t *xdata)
{
        data_pair_t    *trav     = NULL;
        int32_t         op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);

        GF_IF_INTERNAL_XATTR_GOTO ("trusted.*stripe*", dict,
                                   trav, op_errno, err);

        STACK_WIND (frame, stripe_setxattr_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->setxattr,
                    loc, dict, flags, xdata);
        return 0;
err:
        STRIPE_STACK_UNWIND (setxattr, frame, -1,  op_errno, NULL);
        return 0;
}


int
stripe_fsetxattr_cbk (call_frame_t *frame, void *cookie,
                      xlator_t *this, int op_ret, int op_errno, dict_t *xdata)
{
        STRIPE_STACK_UNWIND (fsetxattr, frame, op_ret, op_errno, xdata);
        return 0;
}

int
stripe_fsetxattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                  dict_t *dict, int flags, dict_t *xdata)
{
        //data_pair_t    *trav     = NULL;
        int32_t         op_ret   = -1;
        int32_t         op_errno = EINVAL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

        //GF_IF_INTERNAL_XATTR_GOTO ("trusted.*stripe*", dict,
        //                           trav, op_errno, err);

        STACK_WIND (frame, stripe_fsetxattr_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fsetxattr,
                    fd, dict, flags, xdata);
        return 0;
 err:
        STRIPE_STACK_UNWIND (fsetxattr, frame, op_ret, op_errno, NULL);
        return 0;
}

int32_t
stripe_xattr_request_build (xlator_t *this, dict_t *dict, uint64_t stripe_size,
                            uint32_t stripe_count, uint32_t stripe_index)
{
        char            key[256]       = {0,};
        int32_t         ret             = -1;

        sprintf (key, "trusted.%s.stripe-size", this->name);
        ret = dict_set_int64 (dict, key, stripe_size);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set %s in xattr_req dict", key);
                goto out;
        }

        sprintf (key, "trusted.%s.stripe-count", this->name);
        ret = dict_set_int32 (dict, key, stripe_count);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set %s in xattr_req dict", key);
                goto out;
        }

        sprintf (key, "trusted.%s.stripe-index", this->name);
        ret = dict_set_int32 (dict, key, stripe_index);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set %s in xattr_req dict", key);
                goto out;
        }
out:
        return ret;
}



int32_t
stripe_readdirp_lookup_cbk (call_frame_t *frame, void *cookie,
                            xlator_t *this, int op_ret, int op_errno,
                            inode_t *inode, struct iatt *stbuf,
                            dict_t *xattr, struct iatt *parent)
{
        stripe_local_t          *local          = NULL;
        call_frame_t            *main_frame     = NULL;
        stripe_local_t          *main_local     = NULL;
        gf_dirent_t             *entry          = NULL;
        call_frame_t            *prev           = NULL;
        int                      done           = 0;

        local = frame->local;
        prev = cookie;

        entry = local->dirent;

        main_frame = local->orig_frame;
        main_local = main_frame->local;
        LOCK (&frame->lock);
        {

                local->call_count--;
                if (!local->call_count)
                        done = 1;
                if (op_ret == -1) {
                        local->op_errno = op_errno;
                        local->op_ret = op_ret;
                        goto unlock;
                }
                stripe_iatt_merge (stbuf, &entry->d_stat);
                local->stbuf_blocks += stbuf->ia_blocks;

                stripe_ctx_handle (this, prev, local, xattr);
        }
unlock:
        UNLOCK(&frame->lock);

        if (done) {
                inode_ctx_put (entry->inode, this,
                               (uint64_t) (long)local->fctx);

                done = 0;
                LOCK (&main_frame->lock);
                {
                        main_local->wind_count--;
                        if (!main_local->wind_count)
                                done = 1;
                        if (local->op_ret == -1) {
                                main_local->op_errno = local->op_errno;
                                main_local->op_ret = local->op_ret;
                        }
                        entry->d_stat.ia_blocks = local->stbuf_blocks;
                }
                UNLOCK (&main_frame->lock);
                if (done) {
                        main_frame->local = NULL;
                        STRIPE_STACK_UNWIND (readdir, main_frame,
                                             main_local->op_ret,
                                             main_local->op_errno,
                                             &main_local->entries, NULL);
                        gf_dirent_free (&main_local->entries);
                        stripe_local_wipe (main_local);
                        mem_put (main_local);
                }
                frame->local = NULL;
                stripe_local_wipe (local);
                mem_put (local);
                STRIPE_STACK_DESTROY (frame);
        }

        return 0;
}

int32_t
stripe_readdirp_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno,
                     gf_dirent_t *orig_entries, dict_t *xdata)
{
        stripe_local_t *local = NULL;
        call_frame_t   *prev = NULL;
        gf_dirent_t    *local_entry = NULL;
        int32_t        ret = -1;
        gf_dirent_t    *tmp_entry = NULL;
        xlator_list_t  *trav = NULL;
        loc_t          loc = {0, };
        inode_t        *inode = NULL;
        char           *path;
        int32_t        count = 0;
        stripe_private_t *priv = NULL;
        int32_t        subvols = 0;
        dict_t         *xattrs = NULL;
        call_frame_t   *local_frame = NULL;
        stripe_local_t *local_ent = NULL;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }
        prev  = cookie;
        local = frame->local;
        trav = this->children;
        priv = this->private;

        subvols = priv->child_count;

        LOCK (&frame->lock);
        {
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        local->op_ret = op_ret;
                        goto unlock;
                } else {
                        local->op_ret = op_ret;
                        list_splice_init (&orig_entries->list,
                                          &local->entries.list);
                        local->wind_count = op_ret;
                }

        }
unlock:
        UNLOCK (&frame->lock);

        if (op_ret == -1)
                goto out;

        xattrs = dict_new ();
        if (xattrs)
                (void) stripe_xattr_request_build (this, xattrs, 0, 0, 0);
        count = op_ret;
        ret = 0;
        list_for_each_entry_safe (local_entry, tmp_entry,
                                  (&local->entries.list), list) {

                if (!local_entry)
                        break;
                if (!IA_ISREG (local_entry->d_stat.ia_type)) {
                        LOCK (&frame->lock);
                        {
                                local->wind_count--;
                                count = local->wind_count;
                        }
                        UNLOCK (&frame->lock);
                        continue;
                }

                inode = inode_new (local->fd->inode->table);
                if (!inode)
                        goto out;

                loc.inode = inode;
                loc.parent = local->fd->inode;
                ret = inode_path (local->fd->inode, local_entry->d_name, &path);
                if (ret != -1) {
                        loc.path = path;
                } else  if (inode) {
                        ret = inode_path (inode, NULL, &path);
                        if (ret != -1) {
                                loc.path = path;
                        } else {
                                goto out;
                        }
                }

                loc.name = strrchr (loc.path, '/');
                loc.name++;
                uuid_copy (loc.gfid, local_entry->d_stat.ia_gfid);

                local_frame = copy_frame (frame);

                if (!local_frame) {
                        op_errno = ENOMEM;
                        op_ret = -1;
                        goto out;
                }

                local_ent = mem_get0 (this->local_pool);
                if (!local_ent) {
                        op_errno = ENOMEM;
                        op_ret = -1;
                        goto out;
                }

                local_ent->orig_frame = frame;

                local_ent->call_count = subvols;

                local_ent->dirent = local_entry;

                local_frame->local = local_ent;

                trav = this->children;
                while (trav) {
                        STACK_WIND (local_frame, stripe_readdirp_lookup_cbk,
                                    trav->xlator, trav->xlator->fops->lookup,
                                    &loc, xattrs);
                        trav = trav->next;
                }
                inode_unref (loc.inode);
        }
out:
        if (!count) {
                /* all entries are directories */
                frame->local = NULL;
                STRIPE_STACK_UNWIND (readdir, frame, local->op_ret,
                                     local->op_errno, &local->entries, NULL);
                gf_dirent_free (&local->entries);
                stripe_local_wipe (local);
                mem_put (local);
        }
        if (xattrs)
                dict_unref (xattrs);
        return 0;

}

int32_t
stripe_readdirp (call_frame_t *frame, xlator_t *this,
                 fd_t *fd, size_t size, off_t off, dict_t *xdata)
{
        stripe_local_t  *local  = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t   *trav = NULL;
        int             op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

        priv = this->private;
        trav = this->children;

        if (priv->first_child_down) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = GF_CALLOC (1, sizeof (stripe_local_t),
                           gf_stripe_mt_stripe_local_t);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }

        frame->local = local;

        local->fd = fd_ref (fd);

        local->wind_count = 0;

        local->count = 0;
        local->op_ret = -1;
        INIT_LIST_HEAD(&local->entries);

        if (!trav)
                goto err;

        STACK_WIND (frame, stripe_readdirp_cbk, trav->xlator,
                    trav->xlator->fops->readdirp, fd, size, off, xdata);
        return 0;
err:
        op_errno = (op_errno == -1) ? errno : op_errno;
        STRIPE_STACK_UNWIND (readdir, frame, -1, op_errno, NULL, NULL);

        return 0;

}
int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        if (!this)
                goto out;

        ret = xlator_mem_acct_init (this, gf_stripe_mt_end + 1);

        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR, "Memory accounting init"
                        "failed");
                goto out;
        }

out:
        return ret;
}


int
reconfigure (xlator_t *this, dict_t *options)
{

	stripe_private_t *priv = NULL;
	int		  ret = -1;

	priv = this->private;

        GF_OPTION_RECONF ("block-size", priv->block_size, options, size, out);

        ret = 0;
out:
	return ret;

}

/**
 * init - This function is called when xlator-graph gets initialized.
 *     The option given in volfiles are parsed here.
 * @this -
 */
int32_t
init (xlator_t *this)
{
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        data_t           *data = NULL;
        int32_t           count = 0;
        int               ret = -1;

        if (!this)
                goto out;

        trav = this->children;
        while (trav) {
                count++;
                trav = trav->next;
        }
        gf_log (this->name, GF_LOG_WARNING, "BAY: DEBUG TEST");
        
        if (!count) {
                gf_log (this->name, GF_LOG_ERROR,
                        "stripe configured without \"subvolumes\" option. "
                        "exiting");
                goto out;
        }

        if (!this->parents) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dangling volume. check volfile ");
        }

        if (count == 1) {
                gf_log (this->name, GF_LOG_ERROR,
                        "stripe configured with only one \"subvolumes\" option."
                        " please check the volume. exiting");
                goto out;
        }

        priv = GF_CALLOC (1, sizeof (stripe_private_t),
                          gf_stripe_mt_stripe_private_t);

        if (!priv)
                goto out;
        priv->xl_array = GF_CALLOC (count, sizeof (xlator_t *),
                                    gf_stripe_mt_xlator_t);
        if (!priv->xl_array)
                goto out;

        priv->state = GF_CALLOC (count, sizeof (int8_t),
                                 gf_stripe_mt_int8_t);
        if (!priv->state)
                goto out;

        priv->child_count = count;
        LOCK_INIT (&priv->lock);

        trav = this->children;
        count = 0;
        while (trav) {
                priv->xl_array[count++] = trav->xlator;
                trav = trav->next;
        }

        if (count > 256) {
                gf_log (this->name, GF_LOG_ERROR,
                        "maximum number of stripe subvolumes supported "
                        "is 256");
                goto out;
        }


        GF_OPTION_INIT ("block-size", priv->block_size, size, out);

        /* option stripe-pattern *avi:1GB,*pdf:4096 */
        data = dict_get (this->options, "block-size");
        if (data) {
                ret = set_stripe_block_size (this, priv, data->data);
                if (ret)
                        goto out;
        }

        GF_OPTION_INIT ("use-xattr", priv->xattr_supported, bool, out);

        /* notify related */
        priv->nodes_down = priv->child_count;
        this->private = priv;


        ret = 0;
out:
        if (ret) {
                if (priv) {
                        if (priv->xl_array)
                                GF_FREE (priv->xl_array);
                        GF_FREE (priv);
                }
        }
        return ret;
}

/**
 * fini -   Free all the private variables
 * @this -
 */
void
fini (xlator_t *this)
{
        stripe_private_t      *priv = NULL;
        struct stripe_options *prev = NULL;
        struct stripe_options *trav = NULL;

        if (!this)
                goto out;

        priv = this->private;
        if (priv) {
                this->private = NULL;
                if (priv->xl_array)
                        GF_FREE (priv->xl_array);

                trav = priv->pattern;
                while (trav) {
                        prev = trav;
                        trav = trav->next;
                        FREE (prev);
                }
                LOCK_DESTROY (&priv->lock);
                GF_FREE (priv);
        }

out:
        return;
}

int32_t
stripe_getxattr_unwind (call_frame_t *frame,
                        int op_ret, int op_errno, dict_t *dict, dict_t *xdata)

{
        STRIPE_STACK_UNWIND (getxattr, frame, op_ret, op_errno, dict, xdata);
        return 0;
}


int
stripe_getxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int op_ret, int op_errno, dict_t *xattr, dict_t *xdata)
{
        int                     call_cnt = 0;
        stripe_local_t         *local = NULL;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (frame->local, out);

        local = frame->local;

        LOCK (&frame->lock);
        {
                call_cnt = --local->wind_count;
        }
        UNLOCK (&frame->lock);

        if (!xattr || (op_ret < 0))
                goto out;

        local->op_ret = 0;

        if (!local->xattr) {
                local->xattr = dict_ref (xattr);
        } else {
                stripe_aggregate_xattr (local->xattr, xattr);
        }

out:
        if (!call_cnt) {
                STRIPE_STACK_UNWIND (getxattr, frame, local->op_ret, op_errno,
                                     local->xattr, xdata);
        }

        return 0;
}

int32_t
stripe_xattr_aggregate (char *buffer, stripe_local_t *local, int32_t *total)
{
        int32_t              i     = 0;
        int32_t              ret   = -1;
        int32_t              len   = 0;
        char                *sbuf  = NULL;
        stripe_xattr_sort_t *xattr = NULL;

        if (!buffer || !local || !local->xattr_list)
                goto out;

        sbuf = buffer;

        for (i = 0; i < local->nallocs; i++) {
                xattr = local->xattr_list + i;
                len = xattr->xattr_len;

                if (len && xattr && xattr->xattr_value) {
                        memcpy (buffer, xattr->xattr_value, len);
                        buffer += len;
                        *buffer++ = ' ';
                }
        }

        *--buffer = '\0';
        if (total)
                *total = buffer - sbuf;
        ret = 0;

 out:
        return ret;
}

int32_t
stripe_free_xattr_str (stripe_local_t *local)
{
        int32_t              i     = 0;
        int32_t              ret   = -1;
        stripe_xattr_sort_t *xattr = NULL;

        if (!local || !local->xattr_list)
                goto out;

        for (i = 0; i < local->nallocs; i++) {
                xattr = local->xattr_list + i;

                if (xattr && xattr->xattr_value)
                        GF_FREE (xattr->xattr_value);
        }

        ret = 0;
 out:
        return ret;
}

int32_t
stripe_fill_pathinfo_xattr (xlator_t *this, stripe_local_t *local,
                            char **xattr_serz)
{
        int      ret             = -1;
        int32_t  padding         = 0;
        int32_t  tlen            = 0;
        char stripe_size_str[20] = {0,};
        char    *pathinfo_serz   = NULL;

        if (!local) {
                gf_log (this->name, GF_LOG_ERROR, "Possible NULL deref");
                goto out;
        }

        (void) snprintf (stripe_size_str, 20, "%ld",
                         (local->fctx) ? local->fctx->stripe_size : 0);

        /* extra bytes for decorations (brackets and <>'s) */
        padding = strlen (this->name) + strlen (STRIPE_PATHINFO_HEADER)
                + strlen (stripe_size_str) + 7;
        local->xattr_total_len += (padding + 2);

        pathinfo_serz = GF_CALLOC (local->xattr_total_len, sizeof (char),
                                   gf_common_mt_char);
        if (!pathinfo_serz)
                goto out;

        /* xlator info */
        (void) sprintf (pathinfo_serz, "(<"STRIPE_PATHINFO_HEADER"%s:[%s]> ",
                        this->name, stripe_size_str);

        ret = stripe_xattr_aggregate (pathinfo_serz + padding, local, &tlen);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Cannot aggregate pathinfo list");
                goto out;
        }

        *(pathinfo_serz + padding + tlen) = ')';
        *(pathinfo_serz + padding + tlen + 1) = '\0';

        *xattr_serz = pathinfo_serz;

        ret = 0;
 out:
        return ret;
}

int
stripe_internal_getxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                              int op_ret, int op_errno, dict_t *xattr,
                              dict_t *xdata)
{

        char        size_key[256]  = {0,};
        char        index_key[256] = {0,};
        char        count_key[256] = {0,};

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (frame->local, out);

        if (!xattr || (op_ret == -1))
            goto out;

        sprintf (size_key, "trusted.%s.stripe-size", this->name);
        sprintf (count_key, "trusted.%s.stripe-count", this->name);
        sprintf (index_key, "trusted.%s.stripe-index", this->name);

        dict_del (xattr, size_key);
        dict_del (xattr, count_key);
        dict_del (xattr, index_key);

out:
        STRIPE_STACK_UNWIND (getxattr, frame, op_ret, op_errno, xattr, xdata);

        return 0;

}

int32_t
stripe_vgetxattr_cbk (call_frame_t *frame, void *cookie,
                      xlator_t *this, int32_t op_ret, int32_t op_errno,
                      dict_t *dict, dict_t *xdata)
{
        stripe_local_t      *local         = NULL;
        int32_t              callcnt       = 0;
        int32_t              ret           = -1;
        long                 cky           = 0;
        char                *xattr_val     = NULL;
        char                *xattr_serz    = NULL;
        stripe_xattr_sort_t *xattr         = NULL;
        dict_t              *stripe_xattr  = NULL;

        if (!frame || !frame->local || !this) {
                gf_log ("", GF_LOG_ERROR, "Possible NULL deref");
                return ret;
        }

        local = frame->local;
        cky = (long) cookie;

        if (local->xsel[0] == '\0') {
                gf_log (this->name, GF_LOG_ERROR, "Empty xattr in cbk");
                return ret;
        }

        LOCK (&frame->lock);
        {
                callcnt = --local->wind_count;

                if (!dict || (op_ret < 0))
                        goto out;

                if (!local->xattr_list)
                        local->xattr_list = (stripe_xattr_sort_t *)
                                GF_CALLOC (local->nallocs,
                                           sizeof (stripe_xattr_sort_t),
                                           gf_stripe_mt_xattr_sort_t);

                if (local->xattr_list) {
                        ret = dict_get_str (dict, local->xsel, &xattr_val);
                        if (ret)
                                goto out;

                        xattr = local->xattr_list + (int32_t) cky;

                        xattr_val = gf_strdup (xattr_val);
                        xattr->pos = cky;
                        xattr->xattr_value = xattr_val;
                        xattr->xattr_len = strlen (xattr_val);

                        local->xattr_total_len += xattr->xattr_len + 1;
                }
        }
 out:
        UNLOCK (&frame->lock);

        if (!callcnt) {
                if (!local->xattr_total_len)
                        goto unwind;

                stripe_xattr = dict_new ();
                if (!stripe_xattr)
                        goto unwind;

                /* select filler based on ->xsel */
                if (XATTR_IS_PATHINFO (local->xsel))
                        ret = stripe_fill_pathinfo_xattr (this, local,
                                                          &xattr_serz);
                else {
                        gf_log (this->name, GF_LOG_WARNING,
                                "Unknown xattr in xattr request");
                        goto unwind;
                }

                if (!ret) {
                        ret = dict_set_dynstr (stripe_xattr, local->xsel,
                                               xattr_serz);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Can't set %s key in dict", local->xsel);
                }

        unwind:
                STRIPE_STACK_UNWIND (getxattr, frame, op_ret, op_errno,
                                     stripe_xattr, NULL);

                ret = stripe_free_xattr_str (local);

                if (local->xattr_list)
                        GF_FREE (local->xattr_list);

                if (stripe_xattr)
                        dict_unref (stripe_xattr);
        }

        return ret;
}

int32_t
stripe_getxattr (call_frame_t *frame, xlator_t *this,
                 loc_t *loc, const char *name, dict_t *xdata)
{
        stripe_local_t    *local    = NULL;
        xlator_list_t     *trav     = NULL;
        stripe_private_t  *priv     = NULL;
        int32_t            op_errno = EINVAL;
        int                i        = 0;
        xlator_t         **sub_volumes;
        int                ret      = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        /* Initialization */
        local = mem_get0 (this->local_pool);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        loc_copy (&local->loc, loc);


        if (name && (strcmp (GF_XATTR_MARKER_KEY, name) == 0)
            && (-1 == frame->root->pid)) {
                local->marker.call_count = priv->child_count;

                sub_volumes = alloca ( priv->child_count *
                                       sizeof (xlator_t *));
                for (i = 0, trav = this->children; trav ;
                     trav = trav->next, i++) {

                        *(sub_volumes + i)  = trav->xlator;

                }

                if (cluster_getmarkerattr (frame, this, loc, name,
                                           local, stripe_getxattr_unwind,
                                           sub_volumes, priv->child_count,
                                           MARKER_UUID_TYPE, priv->vol_uuid)) {
                        op_errno = EINVAL;
                        goto err;
                }

                return 0;
        }

        if (name && strncmp (name, GF_XATTR_QUOTA_SIZE_KEY,
                             strlen (GF_XATTR_QUOTA_SIZE_KEY)) == 0) {
                local->wind_count = priv->child_count;

                for (i = 0, trav=this->children; i < priv->child_count; i++,
                             trav = trav->next) {
                        STACK_WIND (frame, stripe_getxattr_cbk,
                                    trav->xlator, trav->xlator->fops->getxattr,
                                    loc, name, xdata);
                }

                return 0;
        }

        if (name &&
            ((strncmp (name, GF_XATTR_PATHINFO_KEY,
                       strlen (GF_XATTR_PATHINFO_KEY)) == 0))) {
                if (IA_ISREG (loc->inode->ia_type)) {
                        ret = inode_ctx_get (loc->inode, this,
                                             (uint64_t *) &local->fctx);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "stripe size unavailable from fctx"
                                        " relying on pathinfo could lead to"
                                        " wrong results");
                }

                local->nallocs = local->wind_count = priv->child_count;
                (void) strncpy (local->xsel, name, strlen (name));

                /**
                 * for xattrs that need info from all childs, fill ->xsel
                 * as above and call the filler function in cbk based on
                 * it
                 */
                for (i = 0, trav = this->children; i < priv->child_count; i++,
                     trav = trav->next) {
                        STACK_WIND_COOKIE (frame, stripe_vgetxattr_cbk,
                                           (void *) (long) i, trav->xlator,
                                           trav->xlator->fops->getxattr,
                                           loc, name, xdata);
                }

                return 0;
        }

        if (name &&(*priv->vol_uuid)) {
                if ((match_uuid_local (name, priv->vol_uuid) == 0)
                    && (-1 == frame->root->pid)) {

                        if (!IA_FILE_OR_DIR (loc->inode->ia_type))
                                local->marker.call_count = 1;
                        else
                                local->marker.call_count = priv->child_count;

                        sub_volumes = alloca (local->marker.call_count *
                                              sizeof (xlator_t *));

                        for (i = 0, trav = this->children;
                             i < local->marker.call_count;
                             i++, trav = trav->next) {
                                *(sub_volumes + i) = trav->xlator;

                        }

                        if (cluster_getmarkerattr (frame, this, loc, name,
                                                   local,
                                                   stripe_getxattr_unwind,
                                                   sub_volumes,
                                                   local->marker.call_count,
                                                   MARKER_XTIME_TYPE,
                                                   priv->vol_uuid)) {
                                op_errno = EINVAL;
                                goto err;
                        }

                        return 0;
                }
        }


        STACK_WIND (frame, stripe_internal_getxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->getxattr, loc, name, xdata);

        return 0;

err:
        STRIPE_STACK_UNWIND (getxattr, frame, -1, op_errno, NULL, NULL);
        return 0;
}


int32_t
stripe_priv_dump (xlator_t *this)
{
        char                    key[GF_DUMP_MAX_BUF_LEN];
        int                     i = 0;
        stripe_private_t       *priv = NULL;
        int                     ret = -1;
        struct stripe_options  *options = NULL;

        GF_VALIDATE_OR_GOTO ("stripe", this, out);

        priv = this->private;
        if (!priv)
                goto out;

        ret = TRY_LOCK (&priv->lock);
        if (ret != 0)
                goto out;

        gf_proc_dump_add_section("xlator.cluster.stripe.%s.priv", this->name);
        gf_proc_dump_write("child_count","%d", priv->child_count);

        for (i = 0; i < priv->child_count; i++) {
                sprintf (key, "subvolumes[%d]", i);
                gf_proc_dump_write (key, "%s.%s", priv->xl_array[i]->type,
                                    priv->xl_array[i]->name);
        }

        options = priv->pattern;
        while (options != NULL) {
                gf_proc_dump_write ("path_pattern", "%s", priv->pattern->path_pattern);
                gf_proc_dump_write ("options_block_size", "%ul", options->block_size);

                options = options->next;
        }

        gf_proc_dump_write ("block_size", "%ul", priv->block_size);
        gf_proc_dump_write ("nodes-down", "%d", priv->nodes_down);
        gf_proc_dump_write ("first-child_down", "%d", priv->first_child_down);
        gf_proc_dump_write ("xattr_supported", "%d", priv->xattr_supported);

        UNLOCK (&priv->lock);

out:
        return ret;
}

struct xlator_fops fops = {
        .stat        = stripe_stat,
        .unlink      = stripe_unlink,
        .rename      = stripe_rename,
        .link        = stripe_link,
        .truncate    = stripe_truncate,
        .create      = stripe_create,
        .open        = stripe_open,
        .readv       = stripe_readv,
        .writev      = stripe_writev,
        .statfs      = stripe_statfs,
        .flush       = stripe_flush,
        .fsync       = stripe_fsync,
        .ftruncate   = stripe_ftruncate,
        .fstat       = stripe_fstat,
        .mkdir       = stripe_mkdir,
        .rmdir       = stripe_rmdir,
        .lk          = stripe_lk,
        .opendir     = stripe_opendir,
        .fsyncdir    = stripe_fsyncdir,
        .setattr     = stripe_setattr,
        .fsetattr    = stripe_fsetattr,
        .lookup      = stripe_lookup,
        .mknod       = stripe_mknod,
        .setxattr    = stripe_setxattr,
        .fsetxattr   = stripe_fsetxattr,
        .getxattr    = stripe_getxattr,
        .readdirp    = stripe_readdirp,
};

struct xlator_cbks cbks = {
        .release = stripe_release,
        .forget  = stripe_forget,
};

struct xlator_dumpops dumpops = {
        .priv = stripe_priv_dump,
};

struct volume_options options[] = {
        { .key  = {"block-size"},
          .type = GF_OPTION_TYPE_ANY,
          .default_value = "128KB",
          .description = "Size of the stripe unit that would be read "
                         "from or written to the striped servers."
        },
        { .key  = {"use-xattr"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "true"
        },
        { .key  = {NULL} },
};
