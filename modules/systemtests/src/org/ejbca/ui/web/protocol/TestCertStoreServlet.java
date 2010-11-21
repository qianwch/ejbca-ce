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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.activation.DataSource;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.MimeMultipart;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.crl.TestCreateCRLSession;
import org.ejbca.util.TestTools;

/**
 * Testing of CertStoreServlet
 * 
 * @author lars
 * @version $Id$
 *
 */
public class TestCertStoreServlet extends TestCase {
	final private static CAInHierarchy rootCA;
	private final static Logger log = Logger.getLogger(TestCreateCRLSession.class);
	private final static CertificateFactory cf;
	static {
		rootCA = new CAInHierarchy("root");
		final CAInHierarchy sub1_1 = new CAInHierarchy("Sub Level 1 Nr 1");
		rootCA.subs.add(sub1_1);
		final CAInHierarchy sub1_2 = new CAInHierarchy("Sub Level 1 Nr 2");
		rootCA.subs.add(sub1_2);
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new Error(e);
		}
	}
	/**
	 * @throws RemoteException
	 */
	public void test00CreateCAs() throws RemoteException {
		final String pKey="certstore.enabled";
		final String sEnabled = TestTools.getConfigurationSession().getProperty(pKey, null);
		if ( sEnabled==null || sEnabled.toLowerCase().indexOf("false")>=0 ) {
			assertTrue("crlstore test not done because crlstore not enabled. To run the test set '"+pKey+"' in ./conf/crl.properties and then 'ant deploy' and restart appserver.", false);
			return;
		}
		final String result = rootCA.createCA();
		assertNull(result, result);
	}
	/**
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws CertificateException
	 */
	public void test01GetFromSubject() throws MalformedURLException, IOException, URISyntaxException, CertificateException {
		final String sURI = RFC4387URL.sHash.appendQueryToURL("http://localhost:8080/certificates/search.cgi", rootCA.getSubjectID());
		log.debug("URL: '"+sURI+"'.");
		final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
		connection.connect();
		assertTrue ( " Fetching CRL with '"+sURI+"' is not working.", HttpURLConnection.HTTP_OK==connection.getResponseCode() );
		final X509Certificate cert = (X509Certificate)cf.generateCertificate(connection.getInputStream());
		log.info(cert.toString());
	}
	/**
	 * One could thin that the class javax.activation.URLDataSource should be usable when connection to a server to retrieve a multipart
	 * message, but it is not. URLDataSource makes two connections when a message is received.
	 *
	 */
	private class MyDataSource implements DataSource {
		final private HttpURLConnection connection;
		MyDataSource(URL url) throws MalformedURLException, IOException {
			this.connection = (HttpURLConnection)url.openConnection();
			this.connection.connect();
			assertTrue ( " Fetching CRL with '"+url+"' is not working.", HttpURLConnection.HTTP_OK==this.connection.getResponseCode() );
		}
		/* (non-Javadoc)
		 * @see javax.activation.DataSource#getContentType()
		 */
		@Override
		public String getContentType() {
			final String contentType = this.connection.getContentType();
			log.info("content type: "+contentType);
			return contentType;
		}
		/* (non-Javadoc)
		 * @see javax.activation.DataSource#getInputStream()
		 */
		@Override
		public InputStream getInputStream() throws IOException {
			return this.connection.getInputStream();
		}
		/* (non-Javadoc)
		 * @see javax.activation.DataSource#getName()
		 */
		@Override
		public String getName() {
			return "my name";
		}
		/* (non-Javadoc)
		 * @see javax.activation.DataSource#getOutputStream()
		 */
		@Override
		public OutputStream getOutputStream() throws IOException {
			return null;
		}
	}
	/**
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws CertificateException
	 * @throws MessagingException
	 */
	public void test02GetIssuedBy() throws MalformedURLException, IOException, URISyntaxException, CertificateException, MessagingException {
		final String sURI = RFC4387URL.iHash.appendQueryToURL("http://localhost:8080/certificates/search.cgi", rootCA.getSubjectID());
		log.debug("URL: '"+sURI+"'.");
		final Multipart multipart = new MimeMultipart(new MyDataSource(new URI(sURI).toURL()));
		final int nrOfCerts = multipart.getCount();
		for ( int i=0; i<nrOfCerts; i++ ) {
			final X509Certificate cert = (X509Certificate)cf.generateCertificate(multipart.getBodyPart(i).getInputStream());
			log.info(cert.toString());
		}
	}
	/**
	 * 
	 */
	public void test99DeleteCAs() {
		rootCA.deleteCA();
	}
}
