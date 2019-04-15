/**
 * Copyright (C) 2016 Kaj Magnus Lindberg
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.debiki.dao.rdb

import com.debiki.core._
import com.debiki.core.Prelude._
import Rdb._
import SearchSiteDaoMixin._



trait SpamCheckQueueDaoMixin extends SiteTransaction {
  self: RdbSiteTransaction =>


  def spamCheckPostsSoon(byWho: Who, spamRelReqStuff: SpamRelReqStuff, posts: Post*) {
    posts.foreach(enqueuePost(byWho, spamRelReqStuff, _))
  }


  private def enqueuePost(byWho: Who, spamRelReqStuff: SpamRelReqStuff, post: Post) {
    val statement = s"""
      insert into spam_check_queue3 (
        action_at,
        site_id,
        post_id,
        post_rev_nr,
        user_id,
        browser_id_cookie,
        browser_fingerprint,
        req_user_agent,
        req_referer,
        req_ip,
        req_uri)
      values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      -- probably not needed:
      on conflict (site_id, post_id, post_rev_nr) do nothing
      """
    val createdAt = post.currentRevLastEditedAt.getOrElse(post.createdAt)
    val values = List(
      createdAt, siteId.asAnyRef, post.id.asAnyRef, post.currentRevisionNr.asAnyRef,
      byWho.id.asAnyRef, byWho.idCookie.orNullVarchar, byWho.browserFingerprint.asAnyRef,
      spamRelReqStuff.userAgent.orNullVarchar, spamRelReqStuff.referer.orNullVarchar,
      byWho.ip, spamRelReqStuff.uri)

    runUpdateSingleRow(statement, values)
  }

}
