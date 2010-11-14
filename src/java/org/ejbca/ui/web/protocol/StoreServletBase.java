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
import java.io.StringWriter;
import java.io.Writer;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ejbca.core.protocol.certificatestore.CertificateCacheFactory;
import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.core.protocol.certificatestore.ICertStore;
import org.ejbca.core.protocol.certificatestore.ICertificateCache;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
public abstract class StoreServletBase extends HttpServlet {

	protected static final String BOUNDARY = "\"BOUNDARY\"";
	final ICertificateCache certCashe;
	final String space = "|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";

	StoreServletBase(ICertStore certStore) {
		super();
		this.certCashe = CertificateCacheFactory.getInstance(certStore);
	}

	abstract void sHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	abstract void iHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	abstract void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	/* (non-Javadoc)
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, java.io.IOException {
		{
			final String sHash = req.getParameter(RFC4387URL.sHash.toString());
			if ( sHash!=null ) {
				sHash( sHash, resp, req );
				return;
			}
		}{
			final String iHash = req.getParameter(RFC4387URL.iHash.toString());
			if ( iHash!=null ) {
				iHash( iHash, resp, req );
				return;
			}
		}{
			final String sKIDHash = req.getParameter(RFC4387URL.sKIDHash.toString());
			if ( sKIDHash!=null ) {
				sKIDHash(sKIDHash, resp, req );
				return;
			}
		}
		printInfo(req, resp);
	}
	private void printInfo(X509Certificate certs[], String indent, PrintWriter pw, String url) {
		for ( int i=0; i<certs.length; i++ ) {
			printInfo(certs[i], indent, pw, url);
			pw.println();
			final X509Certificate issuedCerts[] = this.certCashe.findLatestByIssuerDN(HashID.getFromSubjectDN(certs[i]));
			if ( issuedCerts==null || issuedCerts.length<1 ) {
				continue;
			}
			printInfo(issuedCerts, this.space+indent, pw, url);
		}
	}

	abstract void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url);
	abstract String getTitle();

	private void returnInfoPage(HttpServletResponse response, String info) throws IOException {
		response.setContentType("text/html");
		final PrintWriter writer = response.getWriter();

		writer.println("<html>");
		writer.println("<head>");
		writer.println("<title>"+getTitle()+"</title>");
		writer.println("</head>");

		writer.println("<table border=\"0\">");
		writer.println("<tr>");
		writer.println("<td>");
		writer.println("<h1>"+getTitle()+"</h1>");
		writer.println(info);
		writer.println("</td>");
		writer.println("</tr>");
		writer.println("</table>");

		writer.println("</body>");
		writer.println("</html>");
	}
	private void printInfo(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new MyPrintWriter(sw);
		printInfo(this.certCashe.getRootCertificates(), "", pw, req.getRequestURL().toString());
		pw.flush();
		pw.close();
		sw.flush();
		returnInfoPage(resp, sw.toString());
		sw.close();
	}
	private class MyPrintWriter extends PrintWriter {
		/**
		 * @param out
		 */
		public MyPrintWriter(Writer out) {
			super(out);
		}
		/* (non-Javadoc)
		 * @see java.io.PrintWriter#println()
		 */
		public void println() {
			super.print("<br/>");
			super.println();
		}
		/* (non-Javadoc)
		 * @see java.io.PrintWriter#println(java.lang.String)
		 */
		public void println(String s) {
			super.print(s);
			println();
		}
	}
}
