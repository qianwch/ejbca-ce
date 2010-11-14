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

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.core.protocol.certificatestore.ICertStore;
import org.ejbca.core.protocol.crlstore.CRLCacheFactory;
import org.ejbca.core.protocol.crlstore.ICRLCache;
import org.ejbca.core.protocol.crlstore.ICRLStore;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class CRLStoreServletBase extends StoreServletBase {
	private final ICRLCache crlCache;
	/**
	 * Sets the object to get certificates from.
	 */
	CRLStoreServletBase( ICertStore certStore, ICRLStore crlStore ) {
		super(certStore);
		this.crlCache = CRLCacheFactory.getInstance(crlStore, this.certCashe);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sHash(String iHash, HttpServletResponse resp) throws IOException, ServletException {
		// do nothing for CRLs
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#iHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void iHash(String iHash, HttpServletResponse resp) throws IOException, ServletException {
		final SearchInfo info = new SearchInfo(iHash);
		returnCrl( this.crlCache.findLatestByIssuerDN(info.hashID, info.isDelta), resp, iHash );		
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sKIDHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sKIDHash(String sKIDHash, HttpServletResponse resp) throws IOException, ServletException {
		final SearchInfo info = new SearchInfo(sKIDHash);
		returnCrl( this.crlCache.findBySubjectKeyIdentifier(info.hashID, info.isDelta), resp, sKIDHash );
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#printInfo(java.security.cert.X509Certificate, java.lang.String, java.io.PrintWriter, java.lang.String)
	 */
	void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url) {
		pw.println(indent+cert.getSubjectX500Principal());
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert)));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert)));
	}
	private class SearchInfo {
		private static final String DELTA_PREFIX="d";
		final private boolean isDelta;
		final private HashID hashID;
		SearchInfo(String param) {
			if ( !param.startsWith(DELTA_PREFIX) ) {
				this.isDelta = false;
				this.hashID = HashID.getFromB64(param);
				return;
			}
			final HashID tmpID =  HashID.getFromB64(param);
			if ( tmpID.isOK ) {
				this.isDelta=false;
				this.hashID=tmpID;
				return;
			}
			this.isDelta=true;
			this.hashID= HashID.getFromB64(param.substring(DELTA_PREFIX.length()));
		}
	}
	private void returnCrl( byte crl[], HttpServletResponse resp, String name ) throws IOException {
		resp.setContentType("application/pkix-crl");
		resp.setHeader("Content-disposition", "attachment; filename=crl" + name + ".der");
		resp.setContentLength(crl.length);
		resp.getOutputStream().write(crl);
	}
}
