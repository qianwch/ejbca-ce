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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.ocsp.ICertificateCache;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class CertStoreServletBase extends HttpServlet {
    private final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private final static String BOUNDARY = "\"BOUNDARY\"";

    private final ICertificateCache certCashe;
    /**
     * Sets the object to get certificates from.
     */
    CertStoreServletBase(ICertificateCache _certCache ) {
        this.certCashe = _certCache;
    }
    /* (non-Javadoc)
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, java.io.IOException {
    	final String sHash = req.getParameter("sHash");
    	final X509Certificate cert = this.certCashe.findLatestByHashedSubjectDN(sHash);
    	if (cert==null) {
    		resp.sendError(HttpServletResponse.SC_NO_CONTENT, "No certificate with hash DN: "+sHash);
    		return;
    	}
    	final byte encoded[];
    	try {
			encoded = cert.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new ServletException(e);
		}
        resp.setContentType("application/pkix-cert");
    	resp.setHeader("Content-disposition", "attachment; filename=cert" + sHash + ".der");
    	resp.setContentLength(encoded.length);
    	resp.getOutputStream().write(encoded);
    }
    private void returnCerts( Iterator i, HttpServletResponse resp ) throws IOException, ServletException {
        resp.setContentType("multipart/mixed; boundary="+BOUNDARY);
        final PrintStream ps = new PrintStream(resp.getOutputStream());
        ps.println("This is a multi-part message in MIME format.");
        final Random r = new Random();
        while( i.hasNext() ) {
            final X509Certificate cert = (X509Certificate)i.next();
            // Upload the certificates with mime-header for user certificates.
            ps.println("--"+BOUNDARY);
            ps.println("Content-type: application/pkix-cert");
            ps.println("Content-disposition: attachment; filename=cert" + r.nextInt(1000) + ".der");
            ps.println();
            try {
                ps.write(cert.getEncoded());
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
