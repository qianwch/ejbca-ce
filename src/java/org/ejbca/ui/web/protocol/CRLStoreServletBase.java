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
import javax.servlet.http.HttpServletRequest;
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
	void sHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		// do nothing for CRLs
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#iHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void iHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		returnCrl( this.crlCache.findLatestByIssuerDN(HashID.getFromB64(iHash), isDelta(req)), resp, iHash );		
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sKIDHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		returnCrl( this.crlCache.findBySubjectKeyIdentifier(HashID.getFromB64(sKIDHash), isDelta(req)), resp, sKIDHash );
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#printInfo(java.security.cert.X509Certificate, java.lang.String, java.io.PrintWriter, java.lang.String)
	 */
	void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url) {
		pw.println(indent+cert.getSubjectX500Principal());
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert)));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert)));
		final String deltaParam = "%2Bdelta";
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert), deltaParam));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert), deltaParam));
	}
	private boolean isDelta(HttpServletRequest req) {
		return req.getParameterMap().get("delta")!=null;
	}
	private void returnCrl( byte crl[], HttpServletResponse resp, String name ) throws IOException {
		resp.setContentType("application/pkix-crl");
		resp.setHeader("Content-disposition", "attachment; filename=crl" + name + ".der");
		resp.setContentLength(crl.length);
		resp.getOutputStream().write(crl);
	}
}
