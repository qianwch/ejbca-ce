/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.protocol;

import org.ejbca.core.protocol.ocsp.HashID;


/**
 * Create RFC4387 URLs and HTML references to such URLs. 
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
enum RFC4387URL {
	sHash,
	iHash,
	sKIDHash;
	/**
	 * @param url The URL except the query
	 * @param hash
	 * @return URL to fetch certificate or CRL.
	 */
	String appendQueryToURL(String url, HashID hash) {
		return url+"?"+this.toString()+"="+hash.b64;
	}
	/**
	 * HTML string that show the reference to fetch a certificate or CRL.
	 * @param url
	 * @param hash
	 * @return
	 */
	String getRef(String url, HashID hash) {
		final String resURL = appendQueryToURL(url, hash);
		return "<a href=\""+resURL+"\">"+resURL+"</a>";
	}
}