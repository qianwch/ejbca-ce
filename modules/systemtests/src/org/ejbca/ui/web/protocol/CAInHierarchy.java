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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import junit.framework.Assert;

import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.util.TestTools;

/**
 * This class is needed because a junit test class can not have a nested classes.
 * Nested classes will be seen as extra classes with '$1' appended to the class name.
 * The junit framework can't stand these extra classes if they have "Test" in the name.
 * 
 * @author Lars Silven Primekey
 * @version $Id$
 *
 */
class CAInHierarchy {
	private final static Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
	final String name;
	final Set<CAInHierarchy> subs;
	CAInHierarchy( String _name ) {
		this.name = _name;
		this.subs = new HashSet<CAInHierarchy>();
	}
	X509Certificate createCA(Set<Integer> setOfSubjectKeyIDs) throws RemoteException {
		return createCA(CAInfo.SELFSIGNED, null, setOfSubjectKeyIDs);
	}
	private X509Certificate createCA( int signedBy, Collection certificateChain, Set<Integer> setOfSubjectKeyIDs ) throws RemoteException {
		Assert.assertTrue( "Failed to created certificate.",
		                   TestTools.createTestCA(this.name, 1024, "CN="+this.name+",O=EJBCA junit,OU=TestCertStoreServlet",
		                                          signedBy, certificateChain) );
		final CAInfo info = getCAInfo();
		final Collection newCertificateChain = info.getCertificateChain();
		final X509Certificate caCert = (X509Certificate)newCertificateChain.iterator().next();
		setOfSubjectKeyIDs.add(HashID.getFromKeyID(caCert).key);
		final Iterator<CAInHierarchy> i = this.subs.iterator();
		final int caid = info.getCAId();
		while ( i.hasNext() ) {
			i.next().createCA( caid, newCertificateChain, setOfSubjectKeyIDs );
		}
		return caCert;
	}
	void deleteCA() {
		final Iterator<CAInHierarchy> i = this.subs.iterator();
		while ( i.hasNext() ) {
			i.next().deleteCA();
		}
		TestTools.removeTestCA(this.name);
	}
	private CAInfo getCAInfo() throws RemoteException {
		return TestTools.getCAAdminSession().getCAInfo(admin, this.name);
	}
}
