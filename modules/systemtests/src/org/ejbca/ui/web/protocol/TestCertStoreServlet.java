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
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.mail.MessagingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.util.TestTools;

/**
 * Testing of CertStoreServlet
 * 
 * @author lars
 * @version $Id$
 *
 */
public class TestCertStoreServlet extends TestCase {
	private final static Logger log = Logger.getLogger(TestCertStoreServlet.class);
	/**
	 * @throws MessagingException 
	 * @throws URISyntaxException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws MalformedURLException 
	 */
	public void testIt() throws MalformedURLException, CertificateException, IOException, URISyntaxException, MessagingException {
		final CAInHierarchy ca1 = new CAInHierarchy("root");
		final CAInHierarchy ca1_1 = new CAInHierarchy("1 from root");
		ca1.subs.add(ca1_1);
		final CAInHierarchy ca2_1 = new CAInHierarchy("2 from root at"+new Date());
		ca1.subs.add(ca2_1);
		final CAInHierarchy ca1_1_1 = new CAInHierarchy("1 from 1 from root");
		ca1_1.subs.add(ca1_1_1);
		final CAInHierarchy ca2_1_1 = new CAInHierarchy("2 from 1 from root at "+new Date());
		ca1_1.subs.add(ca2_1_1);
		final CAInHierarchy ca3_1_1 = new CAInHierarchy("3 from 1 from root");
		ca1_1.subs.add(ca3_1_1);
		
		try {
			final String pKey="certstore.enabled";
			final String sEnabled = TestTools.getConfigurationSession().getProperty(pKey, null);
			assertFalse("certstore test not done because certstore not enabled. To run the test set '"+pKey+"' in ./conf/certstore.properties and then 'ant deploy' and restart appserver.",
			            sEnabled==null || sEnabled.toLowerCase().indexOf("false")>=0);
			final Set<Integer> setOfSubjectKeyIDs = new HashSet<Integer>();
			final X509Certificate rootCert = ca1.createCA(setOfSubjectKeyIDs);
			log.info("The number of CAs created was "+setOfSubjectKeyIDs.size()+".");
			new CertFetchAndVerify().doIt( rootCert, setOfSubjectKeyIDs );
			assertEquals("All created CA certificates not found.", 0, setOfSubjectKeyIDs.size());
		}finally {
			ca1.deleteCA();
		}
	}
}
