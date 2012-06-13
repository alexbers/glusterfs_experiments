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
 * xlators/cluster/raid5:
 *    Raid5 translator. The purpose of translator is to make volume alive
 *    after one of subvolumes is down. For handling this situation 
 *    RAID5-like ditstributed checksums are used. Checksum consumes one volume
 *    in sum.
 *    Write speed is twice slow than in stripe translator. Reading is fast.
 *    We don't check checksums while reading the file, we do that only when
 *    one node is down.
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
void xor_data(unsigned char *dest, unsigned char *src_1, unsigned char *src_2, size_t size) {
        size_t off = 0;
        for(off=0; off<size; off++)
                dest[off]=src_1[off] ^ src_2[off];
}

/*
 * xors three arrays and put the result into third array
 */
void xor_data_with(unsigned char *dest, unsigned char *src_1, unsigned char *src_2, size_t size) {
        size_t off = 0;
        for(off=0; off<size; off++) 
                dest[off]^=src_1[off] ^ src_2[off];
}

 
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
stripe_ctx_handle (xlator_t *this, stripe_local_t *local, dict_t *dict)
{
        char            key[256]       = {0,};
        data_t         *data            = NULL;
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

        /* real-size */
        sprintf (key, "trusted.%s.real-size", this->name);
        data = dict_get (dict, key);
        if (!data) {
               local->xattr_self_heal_needed = 1;
               gf_log (this->name, GF_LOG_ERROR,
                        "Failed to get real-size");
               goto out;
        }
                
        local->fctx->real_size = data_to_int64 (data);

        /* bad-node-index */
        sprintf (key, "trusted.%s.bad-node-index", this->name);
        data = dict_get (dict, key);
        if (!data) {
                local->xattr_self_heal_needed = 1;
                gf_log (this->name, GF_LOG_ERROR,
                        "Failed to get bad-node-index");
                goto out;
        }
        local->fctx->bad_node_index = data_to_int32 (data);
        
        ret = 0;
out:
        return ret;
}

int32_t
stripe_xattr_request_build (xlator_t *this, dict_t *dict, uint64_t stripe_size,
                            uint64_t real_size, uint32_t bad_node_index
                           )
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

        sprintf (key, "trusted.%s.real-size", this->name);
        ret = dict_set_int64 (dict, key, real_size);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set %s in xattr_req dict", key);
                goto out;
        }

        sprintf (key, "trusted.%s.bad-node-index", this->name);
        ret = dict_set_int32 (dict, key, bad_node_index);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set %s in xattr_req dict", key);
                goto out;
        }
        
        
out:
        return ret;
}

int32_t
stripe_xattr_request_build_short (xlator_t *this, dict_t *dict, 
                            uint64_t real_size, uint32_t bad_node_index
                           )
{
        char            key[256]       = {0,};
        int32_t         ret             = -1;

        sprintf (key, "trusted.%s.real-size", this->name);
        ret = dict_set_int64 (dict, key, real_size);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set %s in xattr_req dict", key);
                goto out;
        }

        sprintf (key, "trusted.%s.bad-node-index", this->name);
        ret = dict_set_int32 (dict, key, bad_node_index);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set %s in xattr_req dict", key);
                goto out;
        }
        
        
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
        rlocal = mem_get0 (this->local_pool);
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
        int             ret         = 0;
        int             node_index  = -1;

        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }
        
        node_index = cookie;
        local = frame->local;

        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;
                
                if (op_ret == -1) {
                        if (op_errno != ENOENT)
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "%s returned error %s",
                                        this->name,
                                        strerror (op_errno));
                        if (local->op_errno != ESTALE)
                                local->op_errno = op_errno;
                        
                        if(local->bad_node_index != -1 && 
                           local->bad_node_index != node_index) {
                                local->failed = 1;
                        }
                        local->bad_node_index = node_index;
                                                        
                        if (op_errno == ENOENT)
                                local->entry_self_heal_needed = 1;
                }

                if (op_ret >= 0) {
                        local->op_ret = 0;

                        if (IA_ISREG (buf->ia_type)) {
                                ret = stripe_ctx_handle(this, local, xdata);
                                if (ret)
                                        gf_log (this->name, GF_LOG_ERROR,
                                                 "Error getting fctx info from"
                                                 " dict");
                        }
                        if(local->bad_node_index!=-1 && 
                           local->fctx->bad_node_index!=local->bad_node_index) 
                                local->failed = 1;

                        if (local->is_first) {
                                local->is_first = 0;

                                local->stbuf      = *buf;
                                local->postparent = *postparent;
                                local->inode = inode_ref (inode);
                                if (xdata)
                                        local->xdata = dict_ref (xdata);
                                if (local->xattr) {
                                        stripe_aggregate_xattr (local->xdata,
                                                                local->xattr);
                                        dict_unref (local->xattr);
                                        local->xattr = NULL;
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

                        if (local->postparent_size < postparent->ia_size)
                                local->postparent_size = postparent->ia_size;

                        if (uuid_is_null (local->ia_gfid))
                                uuid_copy (local->ia_gfid, buf->ia_gfid);

                        /* Make sure the gfid on all the nodes are same */
                        if (uuid_compare (local->ia_gfid, buf->ia_gfid)) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "%s: gfid different on subvolume %s",
                                        local->loc.path, this->name);
                        }
                }
        }
        UNLOCK (&frame->lock);

        if (!callcnt) {
                gf_log (this->name, GF_LOG_WARNING, "BAY: stripe_lookup_cbk ending op_ret = %d", local->op_ret);

                if (local->op_ret == 0 && local->entry_self_heal_needed &&
                    !uuid_is_null (local->loc.inode->gfid))
                        stripe_entry_self_heal (frame, this, local);

                if (local->failed)
                        local->op_ret = -1;

                if (local->op_ret != -1) {
                        local->stbuf.ia_size=-1;
                        if(local->fctx)
                                local->stbuf.ia_size = local->fctx->real_size;
                        
                        local->stbuf.ia_blocks      = local->stbuf_blocks;
                        local->postparent.ia_blocks = local->postparent_blocks;
                        local->postparent.ia_size   = local->postparent_size;
                        
                        inode_ctx_put (local->inode, this,
                                       (uint64_t) (long)local->fctx);
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
        int               i        = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        gf_log (this->name, GF_LOG_WARNING, "BAY: stripe_lookup path=%s name=%s, child_count=%d nodes_down=%d",
                loc->path, loc->name, priv->child_count,priv->nodes_down
        );

        if(priv->nodes_down > 1) {
                op_errno = ENOTCONN;
                goto err;
        }
        
        /* Initialization */
        local = mem_get0 (this->local_pool);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        local->is_first = 1;
        if(priv->nodes_down==0)
                local->bad_node_index = -1;
        else
                local->bad_node_index = priv->bad_node_index;
        
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
        
        if (IA_ISREG (loc->inode->ia_type) ||
            (loc->inode->ia_type == IA_INVAL)) {
                ret = stripe_xattr_request_build (this, xdata, 8, 8, 4);
                if (ret)
                        gf_log (this->name , GF_LOG_ERROR, "Failed to build"
                                " xattr request for %s", loc->path);
        }
        
        /* One node can be down */
        local->call_count = priv->child_count - priv->nodes_down;
        
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND_COOKIE (frame, stripe_lookup_cbk, i, 
                                priv->xl_array[i],
                                priv->xl_array[i]->fops->lookup, loc, xdata);
                  }
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
        int             is_first = 0;

        if (!this || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;

        LOCK (&frame->lock);
        {
                is_first = local->is_first;
                local->is_first = 0;
                
                callcnt = --local->call_count;

                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) ||
                            is_first)
                                local->failed = 1;
                }

                if (op_ret == 0) {
                        local->op_ret = 0;

                        if (is_first) {
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
stripe_stat (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        int32_t           op_errno = EINVAL;
        stripe_private_t *priv = NULL;
        int               i = 0;
        stripe_fd_ctx_t  *fctx     = NULL;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        
        local = mem_get0 (this->local_pool);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        local->is_first = 1;
        frame->local = local;
        
        inode_ctx_get(loc->inode, this, (uint64_t *) &fctx);
        if (!fctx) {
                op_errno = EBADFD;
                goto err;
        }
        local->size = fctx->real_size;
        
        local->call_count = priv->child_count - priv->nodes_down;
        
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_stat_cbk, priv->xl_array[i],
                                priv->xl_array[i]->fops->stat, loc, NULL);
                  }
        }
                
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
               
        /* Initialization */
        local = mem_get0 (this->local_pool);
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

int
stripe_truncate_setattr_cbk (call_frame_t *frame, void *cookie,
                      xlator_t *this, int op_ret, int op_errno, dict_t *xdata)
{
        stripe_local_t *local = NULL;


        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;
        
        if(op_ret!=0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "BAY: failed to set xattrs, errno=%d", op_ret);
        }

        LOCK(&frame->lock);
        {
                local->wind_count--;
        }
        UNLOCK(&frame->lock);
        
        if(local->wind_count==0) {
                STRIPE_STACK_UNWIND (truncate, frame, local->op_ret,
                                local->op_errno, &local->pre_buf,
                                &local->post_buf, NULL);
        }
                
out:
        return 0;
}


int32_t
stripe_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                     struct iatt *postbuf, dict_t *xdata)
{
        int32_t           callcnt  = 0;
        int8_t            is_first = 0;
        stripe_local_t   *local    = NULL;
        call_frame_t     *prev     = NULL;
        stripe_fd_ctx_t  *fctx     = NULL;
        int               idx      = 0;
        dict_t           *dict     = NULL;
        stripe_private_t *priv     = NULL;
        int               ret      = 0;

        if (!this || !this->private || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        priv = this->private;
        local = frame->local;
        
        VALIDATE_OR_GOTO (local, out);
        VALIDATE_OR_GOTO (local->fctx, out);
        
        fctx = local->fctx;
        
        
        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;
                is_first = local->is_first;
                local->is_first = 0;
                
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) || is_first)
                                local->failed = 1;
                }

                if (op_ret == 0) {
                        local->op_ret = 0;
                        if (is_first) {
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
                        
                        dict = dict_new();
                        if (!dict) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to allocate dict %s", local->loc.path);
                        }
                        
                        fctx->real_size = local->offset;

                        ret = stripe_xattr_request_build_short (this, dict, fctx->real_size, fctx->bad_node_index);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Failed to build short xattr request");
                                
                        local->wind_count= priv->child_count - priv->nodes_down;

                        for(idx=0;idx<priv->child_count;idx++) {
                                if(priv->state[idx]) {
                                        STACK_WIND (frame, stripe_truncate_setattr_cbk, priv->xl_array[idx],
                                                priv->xl_array[idx]->fops->setxattr, &local->loc, dict, ATTR_ROOT, NULL);
                                }
                        }
                        dict_unref(dict);
                } else {
                        STRIPE_STACK_UNWIND (truncate, frame, local->op_ret,
                                        local->op_errno, &local->pre_buf,
                                       &local->post_buf, NULL);
                }
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
        stripe_fd_ctx_t  *fctx = NULL;
        int32_t           op_errno = EINVAL;
        int               i = 0;
        off_t             new_offset;
        
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        if(priv->nodes_down > 1) {
                op_errno = ENOTCONN;
                goto err;
        }

        inode_ctx_get(loc->inode, this, (uint64_t *) &fctx);
        if (!fctx) {
                gf_log(this->name, GF_LOG_ERROR, "no stripe context");
                op_errno = EINVAL;
                goto err;
        }
        
        /* Initialization */
        local = mem_get0 (this->local_pool);
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        local->is_first = 1;
        local->fctx = fctx;
        local->offset = offset;
        loc_copy (&local->loc, loc);
        frame->local = local;
        local->call_count = priv->child_count - priv->nodes_down;
        
        
        if(priv->nodes_down == 1) {
                if(fctx->bad_node_index != -1 &&
                   (fctx->bad_node_index != priv->bad_node_index)) {
                        op_errno = ENOTCONN;
                        goto err;
                }
                
                fctx->bad_node_index = priv->bad_node_index;
        } 
        
        new_offset = get_phys_block_num( offset/fctx->stripe_size, priv->child_count) * fctx->stripe_size;
        new_offset = (new_offset + priv->child_count - 1) / priv->child_count * priv->child_count;
        
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_truncate_cbk, priv->xl_array[i],
                                priv->xl_array[i]->fops->truncate, loc, new_offset, NULL);
                  }
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
        int               i = 0; 

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;
        trav = this->children;

        if(priv->nodes_down > 1) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = mem_get0 (this->local_pool);
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

        local->call_count = priv->child_count - priv->nodes_down;
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_setattr_cbk, priv->xl_array[i],
                                priv->xl_array[i]->fops->setattr, loc, stbuf,valid,NULL);
                  }
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
        local = mem_get0 (this->local_pool);
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
        local = mem_get0 (this->local_pool);
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
        local = mem_get0 (this->local_pool);
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
        local = mem_get0 (this->local_pool);
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
        stripe_fd_ctx_t  *fctx = NULL;

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
                        
                        fctx = GF_CALLOC (1, sizeof (stripe_fd_ctx_t),
                                          gf_stripe_mt_stripe_fd_ctx_t);
                        if (!fctx) {
                                local->op_ret = -1;
                                local->op_errno = ENOMEM;
                                goto unwind;
                        }
                        fctx->stripe_size  = local->stripe_size;
                        inode_ctx_put (local->inode, this,
                                       (uint64_t)(long)fctx);
                }

                /* Create itself has failed.. so return
                   without setxattring */
unwind:
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

        trav = trav->next;
        while (trav) {
                dict = dict_new ();
                if (!dict) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to allocate dict %s", local->loc.path);
                }
                need_unref = 1;

                dict_copy (local->xattr, dict);

                ret = stripe_xattr_request_build (this, dict, local->stripe_size,
                                                  0, 
                                                  priv->nodes_down ? priv->bad_node_index : -1
                                                 );
                if (ret)
                        gf_log (this->name, GF_LOG_ERROR,
                                "Failed to build xattr request");   
                
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
                local = mem_get0 (this->local_pool);
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

                dict = dict_new ();
                if (!dict) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to allocate dict %s", loc->path);
                }
                need_unref = 1;

                dict_copy (xdata, dict);

                ret = stripe_xattr_request_build (this, dict, local->stripe_size,
                                        0, 
                                        priv->nodes_down ? priv->bad_node_index : -1
                                        );
                if (ret)
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to build xattr request");
                
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
        local = mem_get0 (this->local_pool);
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
        local = mem_get0 (this->local_pool);
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
                        fctx->bad_node_index = priv->nodes_down ? priv->bad_node_index : -1;
                        inode_ctx_put (local->inode, this,
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
        int               i    = 1;
        int               is_first = 1;
        dict_t           *dict = NULL;
        loc_t            *loc  = NULL;
        int32_t           need_unref = 0;
        int32_t           ret  = -1;

        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        priv  = this->private;
        local = frame->local;
        loc = &local->loc;

        --local->call_count;

        if (op_ret == -1) {
                gf_log (this->name, GF_LOG_DEBUG, "%s returned error %s",
                        this->name, strerror (op_errno));
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

        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        if (is_first) {
                          is_first = 0;
                          continue; /* Skip first */
                        }
                        
                        dict = dict_new ();
                        if (!dict) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to allocate dict %s", loc->path);
                        }
                        need_unref = 1;

                        dict_copy (local->xattr, dict);

                        ret = stripe_xattr_request_build (this, dict,
                                                          local->stripe_size,
                                                          0, priv->nodes_down ? priv->bad_node_index : -1);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to build xattr request");
                         
                        STACK_WIND (frame, stripe_create_cbk, priv->xl_array[i],
                                priv->xl_array[i]->fops->create, &local->loc,
                                local->flags, local->mode, local->umask,local->fd,
                                dict);
                        if (need_unref && dict)
                                dict_unref (dict);
                  }
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

        dict_t           *dict           = NULL;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;

        if (priv->nodes_down > 1 ) {
                op_errno = ENOTCONN;
                goto err;
        }
        
        /* files created in O_APPEND mode does not allow lseek() on fd */
        flags &= ~O_APPEND;

        /* he mustn't open files in write-only mode*/
        if (flags & O_WRONLY) {
                flags &= ~O_WRONLY;
                flags |= O_RDWR;
        }

        /* Initialization */
        local = mem_get0 (this->local_pool);
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

        local->call_count = priv->child_count - priv->nodes_down;
        /* Send a setxattr request to nodes where the
           files are created */

        dict = dict_new ();
        if (!dict) {
                gf_log (this->name, GF_LOG_ERROR,
                        "failed to allocate dict %s", loc->path);
        }
        need_unref = 1;

        dict_copy (xdata, dict);

        ret = stripe_xattr_request_build (this, dict,
                                          local->stripe_size,
                                          0, priv->nodes_down ? priv->bad_node_index : -1);
        if (ret)
                gf_log (this->name, GF_LOG_ERROR,
                        "failed to build xattr request");
        
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_first_create_cbk, priv->xl_array[i],
                                priv->xl_array[i]->fops->create, loc, flags, mode,
                                umask,fd, dict);
                        break;
                  }
        }

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

        gf_log (this->name, GF_LOG_WARNING,
                "BAY: openfile, open_cbk");

        
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

                STRIPE_STACK_UNWIND (open, frame, local->op_ret,
                                     local->op_errno, local->fd, xdata);
        }
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
        int               i = 0;

        int32_t           op_errno = 1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;

        if (priv->nodes_down > 1 ) {
                op_errno = ENOTCONN;
                goto err;
        }
        
        /* Initialization */
        local = mem_get0 (this->local_pool);
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
        local->call_count = priv->child_count - priv->nodes_down;
        local->stripe_size = stripe_get_matching_bs (loc->path,
                                                     priv->pattern,
                                                     priv->block_size);
                
        for (i=0; i<priv->child_count; i++) {
                if(priv->state[i]) {
                        STACK_WIND (frame, stripe_open_cbk, priv->xl_array[i],
                                priv->xl_array[i]->fops->open, &local->loc, 
                                local->flags, local->fd, xdata);
                }
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
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        int32_t           op_errno = EINVAL;

        int32_t           i = 0;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);

        priv = this->private;

        if (priv->nodes_down > 1 ) {
                op_errno = ENOTCONN;
                goto err;
        }
        
        /* Initialization */
        local = mem_get0 (this->local_pool);

        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        frame->local = local;
        local->call_count = priv->child_count - priv->nodes_down;
        local->fd = fd_ref (fd);

        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_opendir_cbk ,priv->xl_array[i],
                                priv->xl_array[i]->fops->opendir, loc, fd, NULL);
                  }
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
        local = mem_get0 (this->local_pool);

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
        int32_t           op_errno = 1;
        int               i = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;

        /* Initialization */
        local = mem_get0 (this->local_pool);

        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;

        local->call_count = priv->child_count - priv->nodes_down;
        
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_flush_cbk,priv->xl_array[i],
                                priv->xl_array[i]->fops->flush, fd, NULL);
                  }
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
        int               i = 0;
        int32_t           op_errno = 1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;

        /* Initialization */
        local = mem_get0 (this->local_pool);

        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;

        local->call_count = priv->child_count - priv->nodes_down;
        
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_fsync_cbk,priv->xl_array[i],
                                priv->xl_array[i]->fops->fsync, fd, flags, NULL);
                  }
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
        int               i = 0;
        int32_t           op_errno = 1;
        uint64_t          tmp_fctx = 0;
        stripe_fd_ctx_t  *fctx = NULL;

        inode_ctx_get (fd->inode, this, &tmp_fctx);
        if (!tmp_fctx) {
                op_errno = EBADFD;
                goto err;
        }
        fctx = (stripe_fd_ctx_t *)(long)tmp_fctx;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;

        /* Initialization */
        local = mem_get0 (this->local_pool);

        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->fctx = fctx;
        
        local->call_count = priv->child_count - priv->nodes_down;
        
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_fstat_cbk,priv->xl_array[i],
                                priv->xl_array[i]->fops->fstat, fd, NULL);
                  }
        }

        return 0;
err:
        STRIPE_STACK_UNWIND (fstat, frame, -1, op_errno, NULL, NULL);
        return 0;
}


int
stripe_ftruncate_setattr_cbk (call_frame_t *frame, void *cookie,
                      xlator_t *this, int op_ret, int op_errno, dict_t *xdata)
{
        stripe_local_t *local = NULL;


        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        local = frame->local;
        
        if(op_ret!=0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "BAY: failed to set xattrs, errno=%d", op_ret);
        }

        LOCK(&frame->lock);
        {
                local->wind_count--;
        }
        UNLOCK(&frame->lock);
        
        if(local->wind_count==0) {
                STRIPE_STACK_UNWIND (ftruncate, frame, local->op_ret,
                                local->op_errno, &local->pre_buf,
                                &local->post_buf, NULL);
        }
                
out:
        return 0;
}

int32_t
stripe_ftruncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                     struct iatt *postbuf, dict_t *xdata)
{
        int32_t           callcnt  = 0;
        int8_t            is_first = 0;
        stripe_local_t   *local    = NULL;
        call_frame_t     *prev     = NULL;
        stripe_fd_ctx_t  *fctx     = NULL;
        int               idx      = 0;
        dict_t           *dict     = NULL;
        stripe_private_t *priv     = NULL;
        int               ret      = 0;

        if (!this || !this->private || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        prev  = cookie;
        priv = this->private;
        local = frame->local;
        
        VALIDATE_OR_GOTO (local, out);
        VALIDATE_OR_GOTO (local->fctx, out);
        
        fctx = local->fctx;
        
        
        LOCK (&frame->lock);
        {
                callcnt = --local->call_count;
                is_first = local->is_first;
                local->is_first = 0;
                
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        local->op_errno = op_errno;
                        if ((op_errno != ENOENT) || is_first)
                                local->failed = 1;
                }

                if (op_ret == 0) {
                        local->op_ret = 0;
                        if (is_first) {
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
                        
                        dict = dict_new();
                        if (!dict) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to allocate dict");
                        }
                        
                        fctx->real_size = local->offset;

                        ret = stripe_xattr_request_build_short (this, dict, fctx->real_size, fctx->bad_node_index);
                        if (ret)
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Failed to build short xattr request");
                                
                        local->wind_count= priv->child_count - priv->nodes_down;

                        for(idx=0;idx<priv->child_count;idx++) {
                                if(priv->state[idx]) {
                                        STACK_WIND (frame, stripe_ftruncate_setattr_cbk, priv->xl_array[idx],
                                                priv->xl_array[idx]->fops->fsetxattr, local->fd, dict, ATTR_ROOT, NULL);
                                }
                        }
                        dict_unref(dict);
                } else {
                        STRIPE_STACK_UNWIND (truncate, frame, local->op_ret,
                                        local->op_errno, &local->pre_buf,
                                       &local->post_buf, NULL);
                }
                //fd_unref(local->fd);
        }
out:
        return 0;
}


int32_t
stripe_ftruncate (call_frame_t *frame, xlator_t *this, fd_t *fd, off_t offset, dict_t *xdata)
{
        stripe_local_t   *local = NULL;
        stripe_private_t *priv = NULL;
        xlator_list_t    *trav = NULL;
        int32_t           op_errno = 1;
        stripe_fd_ctx_t  *fctx = NULL;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;
        trav = this->children;
 
        inode_ctx_get(fd->inode, this, (uint64_t *) &fctx);
        if (!fctx) {
                gf_log(this->name, GF_LOG_ERROR, "no stripe context");
                op_errno = EINVAL;
                goto err;
        }
        /* Initialization */
        local = mem_get0 (this->local_pool);

        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        frame->local = local;
        local->fctx = fctx;
        local->fd = fd_ref(fd);
        local->is_first = 1;
        local->call_count = priv->child_count;

        while (trav) {
                STACK_WIND (frame, stripe_ftruncate_cbk, trav->xlator,
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
        local = mem_get0 (this->local_pool);

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
 * finalize_readv - this function is called either form bypassing read, or from
 * usual
 */
int32_t
finalize_readv(call_frame_t *frame, xlator_t *this,
               stripe_fd_ctx_t  *fctx 
              ) {
        int32_t         op_ret   = 0;
        int32_t         op_errno = 0;
        int32_t         index    = 0;
        int32_t         need_to_check_proper_size = 0;

        struct iovec   *final_vec = NULL;
        int32_t         final_count = 0;

        struct iatt     tmp_stbuf = {0,};
        struct iobref  *tmp_iobref = NULL;
        struct iatt    *tmp_stbuf_p = NULL; //need it for a warning

        call_frame_t   *mframe = NULL;
        stripe_local_t *mlocal = NULL;
        stripe_local_t *local = NULL;
        
        local  = frame->local;
        
        mframe = local->orig_frame;
        if (!mframe)
                goto end;

        mlocal = mframe->local;
        if (!mlocal)
                goto end;
        
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
                        //gf_log (this->name, GF_LOG_WARNING,
                        //        "BAY: index=%d %d < %d",
                        //        index, mlocal->replies[index].op_ret,
                        //        mlocal->replies[index].requested_size
                        //        );
        
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
                //gf_log (this->name, GF_LOG_WARNING,
                //        "BAY: need to check proper size");

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
                memcpy ((final_vec + final_count),
                        mlocal->replies[index].vector,
                        (mlocal->replies[index].count *
                        sizeof (struct iovec)));
                final_count +=  mlocal->replies[index].count;

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

        mlocal->stbuf_size = fctx->real_size;

        for (index = 0; index < mlocal->wind_count; index++) {                        
                if (mlocal->replies[index].op_ret) {
                        //gf_log (this->name, GF_LOG_WARNING,
                        //        "BAY: test1 %d %d %d %d",
                        //        (int) mlocal->offset,
                        //        (int) mlocal->replies[index].op_ret,
                        //        (int) mlocal->replies[index].vector->iov_len,
                        //        (int) final_count
                        //        );
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
        for(index = 0; index < final_count; index++)
                sum += final_vec[index].iov_len;
        
        //gf_log (this->name, GF_LOG_WARNING,
        //        "BAY: stripe_readv_cbk: DONE, returning %d, op_errno=%d op_ret=%d sum=%d offset=%d size=%d", 
        //        (int) final_count,(int) op_errno,(int) op_ret,(int) sum,
        //        (int) mlocal->offset, (int) mlocal->readv_size);

        STRIPE_STACK_UNWIND (readv, mframe, op_ret, op_errno, final_vec,
                                final_count, &tmp_stbuf, tmp_iobref, NULL);

        iobref_unref (tmp_iobref);
        if (final_vec)
                GF_FREE (final_vec);
end:
        return 0;
}

/**
 * stripe_bypassing_readv_cbk - this is callback for bypassed reads
 */
int32_t
stripe_bypassing_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct iovec *vector,
                  int32_t count, struct iatt *stbuf, struct iobref *iobref, dict_t *xdata) {
        int32_t          index = 0;
        int32_t          orig_index = 0;
        int32_t          bad_node = 0;

        off_t            off = 0;
        
        call_frame_t    *mmframe = NULL;
        stripe_local_t  *mmlocal = NULL;
        call_frame_t    *mframe = NULL;
        stripe_local_t  *mlocal = NULL;
        stripe_local_t  *local = NULL;

        stripe_fd_ctx_t *fctx = NULL;
        int32_t          callcnt = 0;
        int              i = 0;
        int              j = 0;

        stripe_private_t *priv = NULL;        
        
        struct iovec    *result_vec = NULL;
        unsigned char   *result = NULL;
        
        int32_t          bytes_readed = -1;
        
        struct iobuf     *iobuf = NULL;
        
        if (!this || !this->private || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto end;
        }
        
        priv = this->private;
        
        local  = frame->local;
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

        index  = local->node_index;
        orig_index = mlocal->node_index;
        fctx = mmlocal->fctx;
        bad_node = mlocal->block_num % priv->child_count;
       
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
                for (i=0; i < priv->child_count; i++) {
                        if(i==bad_node)
                                continue;
                        if(mlocal->replies[i].op_ret<0) {
                                mmlocal->replies[orig_index].op_ret = -1;
                                mmlocal->replies[orig_index].op_errno = ENOTCONN;
                                mmlocal->replies[orig_index].requested_size = local->readv_size;
                                
                                goto cleanup;
                        }
                }

                
                result_vec = GF_CALLOC (1, sizeof (struct iovec),
                               gf_stripe_mt_iovec);
                
                iobuf = iobuf_get2 (this->ctx->iobuf_pool,fctx->stripe_size);
                
                if (!iobuf || !result_vec) {
                        mmlocal->replies[orig_index].op_ret = -1;
                        mmlocal->replies[orig_index].op_errno = ENOMEM;
                        mmlocal->replies[orig_index].requested_size = local->readv_size;

                        goto cleanup;
                }

                result = iobuf->ptr;
                memset(result, 0, fctx->stripe_size);
                
                bytes_readed = min(mlocal->readv_size,fctx->stripe_size);
                if (mlocal->offset + bytes_readed > fctx->real_size) {
                        bytes_readed = fctx->real_size - mlocal->offset;
                        if (bytes_readed < 0)
                                bytes_readed = 0;
                }
                
                result_vec[0].iov_base = result;
                result_vec[0].iov_len = bytes_readed;
                //gf_log (this->name, GF_LOG_WARNING, "BAY: bytes_readed %d",bytes_readed);
                
                for (i=0; i < priv->child_count; i++) {
                        if(i==bad_node)
                                continue;
                        
                        off = 0;
                        for (j = 0; j < mlocal->replies[index].count; j++) {
                                xor_data(result+off,result+off,
                                              mlocal->replies[i].vector[j].iov_base,
                                              mlocal->replies[i].vector[j].iov_len );
                                off+=mlocal->replies[i].vector[j].iov_len;
                        }
                        
                        GF_FREE (mlocal->replies[i].vector);
                }
                                
                mmlocal->replies[orig_index].op_ret = bytes_readed;
                mmlocal->replies[orig_index].stbuf = *stbuf;
                mmlocal->replies[orig_index].count = 1;
                mmlocal->replies[orig_index].vector = result_vec;
                if (!mmlocal->iobref)
                        mmlocal->iobref = iobref_new ();
                iobref_merge (mmlocal->iobref, iobref);
                iobref_add (mmlocal->iobref, iobuf);
                iobuf_unref(iobuf);

cleanup:
                GF_FREE (mlocal->replies);
                LOCK(&mmframe->lock);
                {
                        mmlocal->call_count++;
                }
                UNLOCK(&mmframe->lock);
                iobref_unref (mlocal->iobref);
        }        

        if (mmlocal->call_count == mmlocal->wind_count)
                finalize_readv(mframe, this,fctx);
        
out:
        if (callcnt == mlocal->wind_count) {
                STRIPE_STACK_DESTROY (mframe);                
        }

        STRIPE_STACK_DESTROY (frame);
end:
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
        
        call_frame_t   *mframe = NULL;
        stripe_local_t *mlocal = NULL;
        stripe_local_t *local = NULL;
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

        //gf_log (this->name, GF_LOG_WARNING,
        //        "BAY: readv stripe_readv_cbk: index %d, op_ret=%d", 
        //        index, op_ret);
        
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

        if (callcnt == mlocal->wind_count)
                finalize_readv(frame, this,fctx);

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
        int32_t           new_idx = 0;
        int32_t           index = 0;
        int32_t           i = 0;
        int32_t           wind_num = 0;
        int32_t           num_stripe = 0;
        int32_t           remaining_size = 0;

        size_t            frame_size = 0;
        off_t             frame_offset = 0;
        uint64_t          tmp_fctx = 0;
        uint64_t          stripe_size = 0;
        off_t             req_block_start = 0;
        off_t             req_block_end = 0;
        stripe_local_t   *local = NULL;
        call_frame_t     *rframe = NULL;
        stripe_local_t   *rlocal = NULL;
        call_frame_t     *rrframe = NULL;
        stripe_local_t   *rrlocal = NULL;
        stripe_fd_ctx_t  *fctx = NULL;
        stripe_private_t *priv = NULL;
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (this->private, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;

        if (priv->nodes_down > 1 ) {
                op_errno = ENOTCONN;
                goto err;
        }
        
        inode_ctx_get (fd->inode, this, &tmp_fctx);
        if (!tmp_fctx) {
                op_errno = EBADFD;
                goto err;
        }
        fctx = (stripe_fd_ctx_t *)(long)tmp_fctx;
        
        if (priv->nodes_down == 1 && fctx->bad_node_index!= -1 &&
            fctx->bad_node_index != priv->bad_node_index) {
                op_errno = ENOTCONN;
                goto err;                
        }
        
        stripe_size = fctx->stripe_size;

        //gf_log (this->name, GF_LOG_WARNING,
        //       "BAY: READV stripe_size: %d, size: %d, offset: %d realsize=%d", 
        //        (int) fctx->stripe_size, (int) size, (int) (int) offset,(int) fctx->real_size);

        if (!stripe_size) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "Wrong stripe size for the file");
                goto err;
        }

        req_block_start = get_phys_block_num(
                offset/stripe_size,priv->child_count);
        req_block_end = get_phys_block_num(
                (offset+size-1)/ stripe_size, priv->child_count);
        
        num_stripe = req_block_end - req_block_start + 1;

        //gf_log (this->name, GF_LOG_WARNING,
        //       "BAY: readv block_start: %d, block_end: %d, test: %d %d", 
        //        (int) req_block_start, (int) req_block_end, (int) num_stripe, 
        //        (int) priv->child_count);
        
        local = mem_get0 (this->local_pool);

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

        local->readv_size = size;
        local->offset     = offset;
        local->fd         = fd_ref (fd);
        local->fctx       = fctx;
                
        // compute the wind count
        local->wind_count = 0;
        for (index = req_block_start; index <= req_block_end; index++) {
                if(is_checksum_block(index,priv->child_count))
                        continue;
                local->wind_count++;
        }
        
        remaining_size = size;
        wind_num = 0;
        
        //index is logical
        for (index = req_block_start; index <= req_block_end; index++) {
                if(is_checksum_block(index,priv->child_count))
                        continue;
                
                rframe = copy_frame (frame);
                rlocal = mem_get0 (this->local_pool);

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
                        
                //gf_log (this->name, GF_LOG_WARNING,
                //        "BAY: readv index=%d req_block_end=%d frame_size=%d frame_offset=%d",
                //        (int) index, (int) req_block_end, 
                //        (int) frame_size, (int) frame_offset);

                rframe->local = rlocal;
                rlocal->orig_frame = frame;
                rlocal->node_index = wind_num;
                rlocal->readv_size = frame_size;
                rlocal->offset = offset + (size - remaining_size);
                rlocal->block_num = index;
                idx = (index % priv->child_count);

                // simple case: direct reading is possible
                if ( idx != fctx->bad_node_index && 
                     (priv->nodes_down==0 || idx != priv->bad_node_index )) {
                        //gf_log (this->name, GF_LOG_WARNING,
                        //        "BAY: %d %d %d",
                        //        (int) idx, (int) fctx->bad_node_index, 
                        //        (int) priv->bad_node_index);

                        STACK_WIND (rframe, stripe_readv_cbk, priv->xl_array[idx],
                                priv->xl_array[idx]->fops->readv,
                                fd, frame_size, frame_offset, flags, xdata);
                } else {
                        /* This is where all the vectors should be copied. */
                        rlocal->replies = GF_CALLOC (priv->child_count, sizeof (struct readv_replies),
                                                gf_stripe_mt_readv_replies);
                        if (!rlocal->replies) {
                                op_errno = ENOMEM;
                                goto err;
                        }

                        rlocal->wind_count = priv->child_count - 1;
                        
                        for(i = floor(index,priv->child_count); 
                            i< floor(index,priv->child_count) + priv->child_count;
                            i++) 
                        {       
                                new_idx = i % priv->child_count;
                                if (new_idx == idx) /* we have to bypass idx */
                                        continue;
                            
                                rrframe = copy_frame (rframe);
                                rrlocal = mem_get0 (this->local_pool);

                                if (!rrlocal) {
                                        op_errno = ENOMEM;
                                        goto err;
                                }

                                rrframe->local = rrlocal;
                                rrlocal->orig_frame = rframe;
                                rrlocal->readv_size = frame_size;
                                rrlocal->node_index = new_idx;

                                //gf_log (this->name, GF_LOG_WARNING,
                                //        "BAY: readv winding b: i=%d orig_off=%d node_index=%d off=%d, size=%d", 
                                //                (int)i,(int)index,(int)rlocal->node_index,(int)i * stripe_size + frame_offset % stripe_size,(int) frame_size);
                       
                                STACK_WIND (rrframe, stripe_bypassing_readv_cbk, priv->xl_array[new_idx],
                                        priv->xl_array[new_idx]->fops->readv,
                                        fd, frame_size, 
                                        i * stripe_size + frame_offset % stripe_size, 
                                        flags, xdata);
                        }                            
                }

                remaining_size -= frame_size;
                wind_num += 1;
        }

        return 0;
err:
        if (rframe)
                STRIPE_STACK_DESTROY (rframe);
        if (rrframe)
                STRIPE_STACK_DESTROY (rrframe);
        
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
                //gf_log (this->name, GF_LOG_WARNING,
                //        "BAY: stripe_writev_setattr_cbk, local->op_ret=%d, op_ret=%d", local->op_ret, op_ret);
                
                STRIPE_STACK_UNWIND (writev, frame, local->op_ret,
                                local->op_errno, &local->pre_buf,
                                &local->post_buf, NULL);
        }
                
out:
        return 0;
}

void stripe_prefinalize_writev(call_frame_t *frame,xlator_t *this) {
        dict_t           *dict           = NULL;
        stripe_local_t   *local          = NULL;
        stripe_private_t *priv = NULL;
        stripe_fd_ctx_t  *fctx = NULL;

        int32_t           ret            = -1;
        int32_t           idx = 0;

        
        int32_t           write_op_ret   = -1;
        int32_t           write_op_errno = EINVAL;

        
        if (!this || !this->private || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }        

        priv = this->private;

        local = frame->local;
        if (!local)
                goto out;

        fctx = local->fctx;
        
        dict=dict_new();
        if (!dict) {
                local->op_errno = ENOMEM;
                local->op_ret = -1;
                goto err;
        }

        if(local->op_ret>=0)
                local->op_ret=local->size;
        
        fctx->real_size = max(fctx->real_size,local->offset+local->op_ret);
        
        ret = stripe_xattr_request_build_short (this, dict, fctx->real_size, fctx->bad_node_index);
        if (ret)
                gf_log (this->name , GF_LOG_ERROR, "Failed to build"
                        " xattr request");
                        
        if(ret) {
                local->op_errno = ENOMEM;
                local->op_ret = -1;
                goto err;                        
        }
        local->wind_count=priv->child_count;
        if (fctx->bad_node_index!=-1)
                local->wind_count--;

        for(idx=0;idx<priv->child_count;idx++) {
                if(idx!=fctx->bad_node_index) {
                        STACK_WIND (frame, stripe_writev_setattr_cbk, priv->xl_array[idx],
                                priv->xl_array[idx]->fops->fsetxattr, local->fd, dict, ATTR_ROOT, NULL);
                }
        }
        dict_unref(dict);
        goto out;
err:
        STRIPE_STACK_UNWIND (writev, frame, write_op_ret,
                write_op_errno, &local->pre_buf,
                &local->post_buf, NULL);

out:
        return;
}

int32_t
stripe_writev_chksum_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                   struct iatt *postbuf, dict_t *xdata)
{
        stripe_local_t *local = NULL;        
        
        call_frame_t   *mframe = NULL;  // the main frame of operation
        stripe_local_t *mlocal = NULL;


        char              *checksum_data = NULL;

        
        int               callcnt = 0;

        stripe_private_t *priv = NULL;
        
        
        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        priv = this->private;
        
        local = frame->local;

        mframe = local->orig_frame;
        if (!mframe)
                goto out;

        mlocal = mframe->local;
        if (!mlocal)
                goto out;


        checksum_data = cookie;
        GF_FREE(checksum_data);
        
        LOCK(&mframe->lock);
        {
                callcnt=--mlocal->group_count;
        }
        UNLOCK(&mframe->lock);
        
        if (callcnt == 0) {
                //gf_log (this->name, GF_LOG_WARNING,
                //        "BAY: stripe_writev_cbk unwinding,fctx->real_size=%d",
                //        (int) fctx->real_size
                //       );
                
                if(mlocal->op_ret==-1)
                        goto err;

                stripe_prefinalize_writev(mframe,this);
                
        }
        
        goto out;
err:
        STRIPE_STACK_UNWIND (writev, mframe, mlocal->op_ret,
                mlocal->op_errno, &mlocal->pre_buf,
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
        unsigned char    *checksum_data = NULL;
        
        int32_t           data_size      = 0;

        int32_t           write_op_ret   = -1;
        int32_t           write_op_errno = EINVAL;

        struct iovec      iovec[1]       = {{0,}};

        stripe_local_t   *local          = NULL;        
        
        call_frame_t     *mframe         = NULL;  // the main frame of operation
        stripe_local_t   *mlocal         = NULL;

        stripe_fd_ctx_t  *fctx           = NULL;
        stripe_private_t *priv = NULL;
        
        int32_t           idx = 0;
        int32_t           node_index = 0;
        
        int               callcnt = 0;

        if (!this || !this->private || !frame || !frame->local) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        priv = this->private;

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
        
        node_index = local->checksum_blocknum_in_group % priv->child_count;
        
        if (read_op_ret<0 && read_op_errno==ENOTCONN) {
                if(fctx->bad_node_index==-1) {
                        fctx->bad_node_index=local->checksum_blocknum_in_group % priv->child_count;
                } else if(fctx->bad_node_index!=node_index) {
                        write_op_errno=ENOTCONN;
                        goto err;
                }
                //gf_log (this->name, GF_LOG_WARNING,
                //        "BAY: BYPASSING");
               
                /* bypassing */
                GF_FREE(local->checksum_xor_with);

                LOCK(&mframe->lock);
                {
                        callcnt=--mlocal->group_count;
                }
                UNLOCK(&mframe->lock);
                
                if(callcnt==0) {
                        stripe_prefinalize_writev(mframe,this);
                }
                
                STRIPE_STACK_DESTROY (frame);          
                goto out;
                
        }      
        
        
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
    
        idx = local->checksum_blocknum_in_group % priv->child_count;
        iovec[0].iov_base = checksum_data;
        iovec[0].iov_len = fctx->stripe_size;

        //gf_log (this->name, GF_LOG_WARNING,
        //"BAY: writing checksum, beginning with %d data = %x, len = %d, idx = %d",
        //(int) local->checksum_blocknum_in_group * fctx->stripe_size,
        //(int)checksum_data,(int) data_size,idx
        //);

        STACK_WIND_COOKIE (frame, stripe_writev_chksum_writev_cbk,checksum_data, priv->xl_array[idx],
                priv->xl_array[idx]->fops->writev, mlocal->fd, iovec,
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
        stripe_fd_ctx_t  *fctx = NULL;
        int             idx;

        call_frame_t   *mframe = NULL;  // the frame of operation group
        stripe_local_t *mlocal = NULL;

        call_frame_t   *mmframe = NULL; // the frame of writev
        stripe_local_t *mmlocal = NULL;

        stripe_private_t *priv = NULL;
        
        if (!this || !frame || !frame->local || !cookie) {
                gf_log ("stripe", GF_LOG_DEBUG, "possible NULL deref");
                goto out;
        }

        priv = this->private;
        
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

        //gf_log (this->name, GF_LOG_WARNING, "BAY: stripe_writev_cbk ");
        
        LOCK(&mmframe->lock);
        {
                callcnt = ++mmlocal->call_count;
                
                mlocal->call_count_in_group--;
                
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                prev->this->name, strerror (op_errno));
                        if (op_errno==ENOTCONN) {
                                if(fctx->bad_node_index==-1)
                                        fctx->bad_node_index=local->node_index;
                                else if(fctx->bad_node_index!=local->node_index) {
                                        mmlocal->op_errno = op_errno;
                                        mmlocal->op_ret = -1;                                        
                                } 
                                
                        } else {
                                mmlocal->op_errno = op_errno;
                                mmlocal->op_ret = -1;
                        }
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
                //gf_log (this->name, GF_LOG_WARNING,
                //        "BAY: group finished, checksum_block=%d",
                //        (int) mlocal->checksum_blocknum_in_group
                //       );
                idx = mlocal->checksum_blocknum_in_group % priv->child_count;

                STACK_WIND (mframe, stripe_writev_chksum_readv_cbk, priv->xl_array[idx],
                                priv->xl_array[idx]->fops->readv,
                                mmlocal->fd, 
                                fctx->stripe_size, 
                                mlocal->checksum_blocknum_in_group * fctx->stripe_size, 
                                0, NULL);
        }
        
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
        //int               i = 0;

        int32_t           idx = 0;
        off_t             off = 0;
                
        int32_t           tmp_count = 0;
        struct iovec     *tmp_vec = NULL;
                
        stripe_fd_ctx_t  *fctx = NULL;
        struct saved_write_contex *wc = NULL;
        
        //int32_t           write_op_ret = -1;
        int32_t           write_op_errno = EINVAL;

        unsigned char    *old_data = NULL;
        unsigned char    *new_data = NULL;
        int32_t           data_size = 0;
 
        stripe_private_t *priv = NULL;

        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (cookie, err);

        priv = this->private;
        
        if(read_op_ret ==  -1 && read_op_errno != ENOENT) {
                write_op_errno = read_op_errno;
                goto err;
        }
        
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
        
        //gf_log (this->name, GF_LOG_WARNING,
        //        "BAY: stripe_writev_readv_cbk read_op_ret=%d read_op_errno=%d",
        //        read_op_ret, read_op_errno);
        
        inode_ctx_get (write_fd->inode, this, &tmp_fctx);
        if (!tmp_fctx) {
                write_op_errno = EINVAL;
                goto err;
        }
        fctx = (stripe_fd_ctx_t *)(long)tmp_fctx;
        stripe_size = fctx->stripe_size;

        req_block_start = get_phys_block_num(
                write_offset/stripe_size,priv->child_count);
        req_block_end = get_phys_block_num(
                (write_offset+data_size-1)/ stripe_size, priv->child_count);
        full_block_start=floor(req_block_start,priv->child_count);
        full_block_end=req_block_end / priv->child_count * priv->child_count + priv->child_count - 1;
        
        num_stripe = full_block_end - full_block_start + 1;
                
        /* File has to be stripped across the child nodes */
        remaining_size = data_size;

        local = mem_get0 (this->local_pool);
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
        local->group_count = num_stripe / priv->child_count;
        local->iobref = read_iobref;

        //gf_log (this->name, GF_LOG_WARNING,
        //        "BAY: writev req_block_start=%d req_block_end=%d full_block_start=%d full_block_end=%d",
        //        (int) req_block_start, (int) req_block_end, 
        //        (int) full_block_start, (int) full_block_end);

        if( (full_block_end+1) % priv->child_count != 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "BAY: writev: full_block_end=%d. This is very wrong.",
                        (int) full_block_end);                
        }

        // we divide the big writing task into smaller tasks, which affect only
        // one checksum block
        for(begin_group_block=full_block_start; 
            begin_group_block!=full_block_end+1; 
            begin_group_block+=priv->child_count) {
                rframe = copy_frame (frame);
                rlocal = mem_get0 (this->local_pool);
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
                
                rlocal->checksum_blocknum_in_group = get_checksum_block_num(begin_group_block,priv->child_count);
                
                // calculate a num of calls in current block
                rlocal->call_count_in_group = 0;
                for(curr_block=begin_group_block;
                    curr_block<begin_group_block+priv->child_count;
                    curr_block++) {
                        if(curr_block<req_block_start || curr_block>req_block_end)
                                continue;   
                        if(is_checksum_block(curr_block,priv->child_count)) 
                                continue;
                        
                        //idx = curr_block % priv->child_count;
                        //if(!(fctx->bad_node_index != idx))
                        //        continue;
                        
                        rlocal->call_count_in_group++;    
                }
                                
                for(curr_block=begin_group_block;
                    curr_block<begin_group_block+priv->child_count;
                    curr_block++) {
                        if(curr_block<req_block_start || curr_block>req_block_end)
                                continue;   
                        if(is_checksum_block(curr_block,priv->child_count)) 
                                continue;

                        idx = curr_block % priv->child_count;
                        
                        rrframe = copy_frame (rframe);
                        rrlocal = mem_get0 (this->local_pool);
                        if (!rrlocal) {
                                write_op_errno = ENOMEM;
                                goto err;
                        }
                        
                        rrframe->local = rrlocal;
                        rrlocal->orig_frame = rframe;
                        rrlocal->node_index = idx;
                        
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
                        
                        //gf_log (this->name, GF_LOG_WARNING,
                        //        "BAY: writev winding for block %d, orig_offset=%d, new_offset=%d, checksum_xor_with=%x %x %x "
                        //        "new data: %x %x %x", 
                        //        (int) curr_block,(int) (write_offset + offset_offset),
                        //        (int) (local->stripe_size * curr_block + block_offset),
                        //        (unsigned int) rlocal->checksum_xor_with[0],
                        //        (unsigned int) rlocal->checksum_xor_with[1],
                        //        (unsigned int) rlocal->checksum_xor_with[2],
                        //        *(char *)(new_data + offset_offset),
                        //        *(char *)(new_data + offset_offset + 1),
                        //        *(char *)(new_data + offset_offset + 2)
                        //       );
 
                        //if( fctx->bad_node_index != idx) {
                        STACK_WIND (rrframe, stripe_writev_cbk, priv->xl_array[idx],
                        priv->xl_array[idx]->fops->writev, write_fd, tmp_vec,
                        tmp_count, 
                        local->stripe_size * curr_block + block_offset, 
                        write_flags, read_iobref, xdata);
                        //}
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
        int32_t           i = 0;
        int32_t           total_size = 0;
        int32_t           op_errno = 1;
        
        stripe_private_t *priv = NULL;

        struct saved_write_contex *wc = NULL; // we have to save write contex
        
        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

        priv = this->private;

        if (priv->nodes_down > 1 ) {
                op_errno = ENOTCONN;
                goto err;
        }

        //gf_log (this->name, GF_LOG_WARNING, "BAY: WRITEV flags = %x",flags);
        
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

int
stripe_forget (xlator_t *this, inode_t *inode)
{
        uint64_t          tmp_fctx = 0;
        stripe_fd_ctx_t  *fctx = NULL;
        
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (inode, err);
        
        (void) inode_ctx_del (inode, this, &tmp_fctx);
        if (!tmp_fctx) {
                goto err;
        }
        fctx = (stripe_fd_ctx_t *)(long)tmp_fctx;
                
        GF_FREE (fctx);
err:
        return 0;
}

int32_t
notify (xlator_t *this, int32_t event, void *data, ...)
{
        stripe_private_t *priv = NULL;
        int               down_client = 0;
        uint8_t           last_down_node = 0;
        int               i = 0;

        if (!this)
                return 0;

        priv = this->private;
        if (!priv)
                return 0;

        switch (event)
        {
        case GF_EVENT_CHILD_UP:
        //case GF_EVENT_CHILD_CONNECTING:
        {
                /* get an index number to set */
                for (i = 0; i < priv->child_count; i++) {
                        if (data == priv->xl_array[i])
                                break;
                }
                priv->state[i] = 1;
                
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: child %d is up", (int) i);

                for (i = 0; i < priv->child_count; i++) {
                        if (!priv->state[i]) {
                                down_client++;
                                last_down_node = i;
                        }
                }

                LOCK (&priv->lock);
                {
                        priv->nodes_down = down_client;
                        priv->bad_node_index = last_down_node;
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
                last_down_node = i;
                
                gf_log (this->name, GF_LOG_WARNING,
                        "BAY: child %d is down", (int) i);
                
                for (i = 0; i < priv->child_count; i++) {
                        if (!priv->state[i])
                                down_client++;
                }

                LOCK (&priv->lock);
                {
                        priv->nodes_down = down_client;
                        priv->bad_node_index = last_down_node;

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

                if (stripe_opt->block_size < 16384) {
                        gf_log (this->name, GF_LOG_ERROR, "Invalid Block-size: "
                                "%s. Should be atleast 16384 bytes", num);
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
                mem_put (local);
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

                stripe_ctx_handle (this, local, xattr);
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
        gf_log ("stripe", GF_LOG_WARNING, "stripe_readdirp_cbk");

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
        int32_t         i = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);

        priv = this->private;
        trav = this->children;

        if (priv->nodes_down > 1 ) {
                op_errno = ENOTCONN;
                goto err;
        }

        /* Initialization */
        local = mem_get0 (this->local_pool);
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

        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_readdirp_cbk, priv->xl_array[i],
                                priv->xl_array[i]->fops->readdirp, fd, size, off, xdata);
                        break;
                  }
        }

        return 0;
err:
        op_errno = (op_errno == -1) ? errno : op_errno;
        STRIPE_STACK_UNWIND (readdir, frame, -1, op_errno, NULL, NULL);

        return 0;

}

int32_t
stripe_readdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, gf_dirent_t *buf, 
                   dict_t *xdata)
{
        STRIPE_STACK_UNWIND (readdir, frame, op_ret, op_errno, buf, NULL);

        return 0;
}

int32_t
stripe_readdir(call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size, 
               off_t offset, dict_t *xdata)
{
        int32_t i = 0;
        stripe_private_t *priv = NULL;
        
        priv = this->private;
        
        for (i=0; i<priv->child_count; i++) {
                  if(priv->state[i]) {
                        STACK_WIND (frame, stripe_readdir_cbk, priv->xl_array[i],
                                priv->xl_array[i]->fops->readdir, fd, size, offset, NULL);
                        break;
                  }
        }

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
        volume_option_t  *opt = NULL;
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

        ret = 0;
        LOCK (&priv->lock);
        {
                opt = xlator_volume_option_get (this, "block-size");
                if (!opt) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "option 'block-size' not found");
                        ret = -1;
                        goto unlock;
                }
                if (gf_string2bytesize (opt->default_value, &priv->block_size)){
                        gf_log (this->name, GF_LOG_ERROR,
                                "Unable to set default block-size ");
                        ret = -1;
                        goto unlock;
                }
                /* option stripe-pattern *avi:1GB,*pdf:16K */
                data = dict_get (this->options, "block-size");
                if (data) {
                        ret = set_stripe_block_size (this, priv, data->data);
                        if (ret)
                                goto unlock;
                }
        }
 unlock:
        UNLOCK (&priv->lock);
        if (ret)
                goto out;

        /* notify related */
        priv->nodes_down = priv->child_count;

        this->local_pool = mem_pool_new (stripe_local_t, 128);
        if (!this->local_pool) {
                ret = -1;
                gf_log (this->name, GF_LOG_ERROR,
                        "failed to create local_t's memory pool");
                goto out;
        }

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
        char        real_size_key[256] = {0,};

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (frame->local, out);

        if (!xattr || (op_ret == -1))
            goto out;

        sprintf (size_key, "trusted.%s.stripe-size", this->name);
        sprintf (count_key, "trusted.%s.stripe-count", this->name);
        sprintf (index_key, "trusted.%s.stripe-index", this->name);
        sprintf (real_size_key, "trusted.%s.real-size", this->name);

        dict_del (xattr, size_key);
        dict_del (xattr, count_key);
        dict_del (xattr, index_key);
        dict_del (xattr, real_size_key);
        
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

        gf_log (this->name, GF_LOG_WARNING,
                "BAY: getxattr");
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
        .readdir     = stripe_readdir,
};

struct xlator_cbks cbks = {
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
        { .key  = {NULL} },
};
