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
import java.io.StringWriter;
import java.io.Writer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ejbca.core.protocol.ocsp.HashID;
import org.ejbca.core.protocol.ocsp.ICertificateCache;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class CertStoreServletBase extends HttpServlet {
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
		final String sHash = req.getParameter(RFC4387URL.sHash.toString());
		if ( sHash!=null ) {
			final X509Certificate cert = this.certCashe.findLatestBySubjectDN(HashID.getFromB64(sHash));
			returnCert( cert, resp, sHash);
			return;
		}
		final String iHash = req.getParameter(RFC4387URL.iHash.toString());
		if ( iHash!=null ) {
			returnCerts( this.certCashe.findLatestByIssuerDN(HashID.getFromB64(iHash)), resp, iHash );
			return;
		}
		final String sKIDHash = req.getParameter(RFC4387URL.sKIDHash.toString());
		if ( sKIDHash!=null ) {
			returnCert( this.certCashe.findBySubjectKeyIdentifier(HashID.getFromB64(sKIDHash)), resp, sKIDHash );
			return;
		}
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new MyPrintWriter(sw);
		printCerts(this.certCashe.getRootCertificates(), "", pw, req.getRequestURL().toString());
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
	private void returnCert( X509Certificate cert, HttpServletResponse resp, String name ) throws IOException, ServletException {
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
	private void returnCerts( X509Certificate certs[], HttpServletResponse resp, String name ) throws IOException, ServletException {
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
	final String space = "|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"; // 5 html spaces
	private void printCerts(X509Certificate certs[], String indent, PrintWriter pw, String url) {
		for ( int i=0; i<certs.length; i++ ) {
			pw.println(indent+certs[i].getSubjectX500Principal());
			pw.println(indent+" "+RFC4387URL.sHash.getRef(url, HashID.getFromSubjectDN(certs[i])));
			pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(certs[i])));
			pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(certs[i])));
			pw.println();
			final X509Certificate issuedCerts[] = this.certCashe.findLatestByIssuerDN(HashID.getFromSubjectDN(certs[i]));
			if ( issuedCerts==null || issuedCerts.length<1 ) {
				continue;
			}
			printCerts(issuedCerts, this.space+indent, pw, url);
		}
	}
	private void returnInfoPage( HttpServletResponse response, String info ) throws IOException {
		response.setContentType("text/html");
		final PrintWriter writer = response.getWriter();
		final String title = "CA certificates";

		writer.println("<html>");
		writer.println("<head>");
		writer.println("<title>"+title+"</title>");
		writer.println("</head>");

		writer.println("<table border=\"0\">");
		writer.println("<tr>");
		writer.println("<td>");
		writer.println("<h1>"+title+"</h1>");
		writer.println(info);
		writer.println("</td>");
		writer.println("</tr>");
		writer.println("</table>");

		writer.println("</body>");
		writer.println("</html>");
		
	}
}
