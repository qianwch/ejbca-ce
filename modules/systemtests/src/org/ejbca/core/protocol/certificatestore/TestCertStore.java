/**
 * 
 */
package org.ejbca.core.protocol.certificatestore;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;
import org.ejbca.util.TestTools;

import junit.framework.TestCase;

/**
 * @author lars
 *
 */
public class TestCertStore extends TestCase {
	private final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
	private class CA {
		final String name;
		final Set<CA> subs;
		CA( String _name ) {
			this.name = _name;
			this.subs = new HashSet<CA>();
		}
		void createCA() throws RemoteException {
			createCA(CAInfo.SELFSIGNED, null);
		}
		private void createCA( int signedBy, Collection certificateChain ) throws RemoteException {
			assertTrue("Failed to created certificate.", TestTools.createTestCA(this.name, 2048, "CN="+this.name+",O=EJBCA junit,OU=TestCertStore", signedBy, certificateChain) );
			final CAInfo info = TestTools.getCAAdminSession().getCAInfo(TestCertStore.this.admin, this.name);
			final Iterator<CA> i = this.subs.iterator();
			while ( i.hasNext() ) {
				i.next().createCA( info.getCAId(), info.getCertificateChain() );
			}
		}
		void deleteCA() {
			final Iterator<CA> i = this.subs.iterator();
			while ( i.hasNext() ) {
				i.next().deleteCA();
			}
			TestTools.removeTestCA(this.name);
		}
	}
	private final CA rootCA;
	/**
	 * @param name
	 */
	public TestCertStore(String name) {
		super(name);
		this.rootCA = new CA("root");
		this.rootCA.subs.add(new CA("Sub Level 1 Nr 1"));
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		this.rootCA.createCA();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		this.rootCA.deleteCA();
		super.tearDown();
	}

	public void test01Dummy() {
		// do nothing
	}
}
