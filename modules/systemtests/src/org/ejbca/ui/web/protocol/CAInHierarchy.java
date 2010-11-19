/**
 * 
 */
package org.ejbca.ui.web.protocol;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.TestTools;

/**
 * This class is needed because a junit test class can not have a nested classes.
 * Nested classes will be seen as extra classes with '$1' appended to the class name.
 * The junit framework can't stand these extra classes if they have "Test" in the name.
 * 
 * @author lars
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
	String createCA() throws RemoteException {
		return createCA(CAInfo.SELFSIGNED, null);
	}
	private String createCA( int signedBy, Collection certificateChain ) throws RemoteException {
		if ( !TestTools.createTestCA(this.name, 2048, "CN="+this.name+",O=EJBCA junit,OU=TestCertStoreServlet", signedBy, certificateChain) ) {
			return "Failed to created certificate.";
		}
		final CAInfo info = TestTools.getCAAdminSession().getCAInfo(admin, this.name);
		final Iterator<CAInHierarchy> i = this.subs.iterator();
		while ( i.hasNext() ) {
			i.next().createCA( info.getCAId(), info.getCertificateChain() );
		}
		return null;
	}
	void deleteCA() {
		final Iterator<CAInHierarchy> i = this.subs.iterator();
		while ( i.hasNext() ) {
			i.next().deleteCA();
		}
		TestTools.removeTestCA(this.name);
	}
}
