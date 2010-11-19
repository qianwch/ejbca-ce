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

import java.rmi.RemoteException;

import junit.framework.TestCase;

/**
 * Testing of CertStoreServlet
 * 
 * @author lars
 * @version $Id$
 *
 */
public class TestCertStoreServlet extends TestCase {
	final private static CAInHierarchy rootCA;
	
	static {
		rootCA = new CAInHierarchy("root");
		rootCA.subs.add(new CAInHierarchy("Sub Level 1 Nr 1"));
	}
	public void test00CreateCAs() throws RemoteException {
		final String result = rootCA.createCA();
		assertNull(result, result);
	}

	public void test99DeleteCAs() {
		rootCA.deleteCA();
	}
}
