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
import java.io.PrintStream;
import java.io.PrintWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.core.protocol.certificatestore.ICertStore;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class CertStoreServletBase extends StoreServletBase {
	/**
	 * Sets the object to get certificates from.
	 */
	CertStoreServletBase( ICertStore certStore ) {
		super(certStore);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#iHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void iHash(String iHash, HttpServletResponse resp) throws IOException, ServletException {
		returnCerts( this.certCashe.findLatestByIssuerDN(HashID.getFromB64(iHash)), resp, iHash );
		return;
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sKIDHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sKIDHash(String sKIDHash, HttpServletResponse resp) throws IOException, ServletException {
		returnCert( this.certCashe.findBySubjectKeyIdentifier(HashID.getFromB64(sKIDHash)), resp, sKIDHash );
		return;
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sHash(String sHash, HttpServletResponse resp) throws IOException, ServletException {
		final X509Certificate cert = this.certCashe.findLatestBySubjectDN(HashID.getFromB64(sHash));
		returnCert( cert, resp, sHash);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#printInfo(java.security.cert.X509Certificate, java.lang.String, java.io.PrintWriter, java.lang.String)
	 */
	void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url) {
		pw.println(indent+cert.getSubjectX500Principal());
		pw.println(indent+" "+RFC4387URL.sHash.getRef(url, HashID.getFromSubjectDN(cert)));
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert)));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert)));
	}
	private void returnCert(X509Certificate cert, HttpServletResponse resp, String name) throws IOException, ServletException {
		if (cert==null) {
			resp.sendError(HttpServletResponse.SC_NO_CONTENT, "No certificate with hash DN: "+name);
			return;
		}
		final byte encoded[];
		try {
			encoded = cert.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new ServletException(e);
		}
		resp.setContentType("application/pkix-cert");
		resp.setHeader("Content-disposition", "attachment; filename=cert" + name + ".der");
		resp.setContentLength(encoded.length);
		resp.getOutputStream().write(encoded);
	}
	private void returnCerts(X509Certificate certs[], HttpServletResponse resp, String name) throws IOException, ServletException {
		if (certs==null) {
			resp.sendError(HttpServletResponse.SC_NO_CONTENT, "No certificate with issuer hash DN: "+name);
			return;
		}
		resp.setContentType("multipart/mixed; boundary="+BOUNDARY);
		final PrintStream ps = new PrintStream(resp.getOutputStream());
		ps.println("This is a multi-part message in MIME format.");
		for( int i=0; i<certs.length; i++ ) {
			// Upload the certificates with mime-header for user certificates.
			ps.println("--"+BOUNDARY);
			ps.println("Content-type: application/pkix-cert");
			ps.println("Content-disposition: attachment; filename=cert" + name + '-' + i + ".der");
			ps.println();
			try {
				ps.write(certs[i].getEncoded());
			} catch (CertificateEncodingException e) {
				throw new ServletException(e);
			}
			ps.println();
		}
		// ready
		ps.println("--"+BOUNDARY+"--");
		ps.flush();
	}
}
