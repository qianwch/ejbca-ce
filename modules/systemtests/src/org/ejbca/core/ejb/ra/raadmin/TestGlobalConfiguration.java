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

package org.ejbca.core.ejb.ra.raadmin;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.TestTools;

/**
 * Tests the global configuration entity bean.
 *
 * @version $Id$
 */
public class TestGlobalConfiguration extends TestCase {
    private static Logger log = Logger.getLogger(TestGlobalConfiguration.class);
    
    private static final Admin[] NON_CLI_ADMINS = new Admin[] {
		new Admin(Admin.TYPE_INTERNALUSER),
		new Admin(Admin.TYPE_PUBLIC_WEB_USER)
	};

	private Collection/*Integer*/ caids;

    private IRaAdminSessionRemote cacheAdmin;
//    private ICaSessionRemote caSession = InterfaceCache.getCaSession();
	private ICAAdminSessionRemote caAdminSession;
	private IAuthorizationSessionRemote authorizationSession;

    private static IRaAdminSessionHome cacheHome;

    private static GlobalConfiguration original = null;

    private Admin administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);

    /**
     * Creates a new TestGlobalConfiguration object.
     *
     * @param name name
     */
    public TestGlobalConfiguration(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.trace(">setUp()");
        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup(IRaAdminSessionHome.JNDI_NAME);
                cacheHome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);

            }
            cacheAdmin = cacheHome.create();
        }
        if (caAdminSession == null) {
            Context jndiContext = getInitialContext();
            Object obj1 = jndiContext.lookup(ICAAdminSessionHome.JNDI_NAME);
            caAdminSession = ((ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionHome.class)).create();
        }
        if (authorizationSession == null) {
            Context jndiContext = getInitialContext();
            Object obj1 = jndiContext.lookup(IAuthorizationSessionHome.JNDI_NAME);
            authorizationSession = ((IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IAuthorizationSessionHome.class)).create();
        }
        enableCLI(true);
        TestTools.createTestCA();
        caids = caAdminSession.getAvailableCAs(administrator);
    	assertFalse("No CAs exists so this test will not work", caids.isEmpty());
        log.trace("<setUp()");
    }

    protected void tearDown() throws Exception {
        enableCLI(true);
        TestTools.removeTestCA();
    }

    private Context getInitialContext() throws NamingException {
        log.trace(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        log.trace("<getInitialContext");
        return ctx;
    }


    /**
     * tests adding a global configuration
     *
     * @throws Exception error
     */
    public void test01AddGlobalConfiguration() throws Exception {
        log.trace(">test01AddGlobalConfiguration()");

        Admin administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);

        // First save the original
        original = this.cacheAdmin.loadGlobalConfiguration(administrator);

        GlobalConfiguration conf = new GlobalConfiguration();
        conf.setEjbcaTitle("TESTTITLE");
        this.cacheAdmin.saveGlobalConfigurationRemote(administrator, conf);

        log.trace("<test01AddGlobalConfiguration()");
    }

    /**
     * tests modifying an global configuration
     *
     * @throws Exception error
     */
    public void test02ModifyGlobalConfiguration() throws Exception {
        log.trace(">test01ModifyGlobalConfiguration()");

        Admin administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);

        GlobalConfiguration conf = this.cacheAdmin.loadGlobalConfiguration(administrator);
        assertTrue("Error Retreiving Global Configuration.", conf.getEjbcaTitle().equals("TESTTITLE"));

        conf.setEjbcaTitle("TESTTITLE2");
        this.cacheAdmin.saveGlobalConfigurationRemote(administrator, conf);

        // Replace with original
        this.cacheAdmin.saveGlobalConfigurationRemote(administrator, original);

        log.trace("<test01ModifyGlobalConfiguration()");
    }

    /**
     * Tests that we can not pretend to be something other than command line
     * user and call the method getAvailableCAs.
     * @throws Exception
     */
    public void test03NonCLIUser_getAvailableCAs() throws Exception {
    	enableCLI(true);
    	for (Admin admin : NON_CLI_ADMINS) {
    		operationGetAvailabeCAs(admin);
    	}
    }
    /**
     * Tests that we can disable the CLI and then that we can not call the
     * method getAvailableCAs.
     * @throws Exception
     */
    public void test04DisabledCLI_getAvailableCAs() throws Exception {
    	enableCLI(false);
    	operationGetAvailabeCAs(administrator);
    }

    /**
     * Tests that we can not pretend to be something other than command line
     * user and call the method getAvailableCAs.
     * @throws Exception
     */
    public void test05NonCLIUser_getCAInfo() throws Exception {
    	enableCLI(true);
    	for (Admin admin : NON_CLI_ADMINS) {
    		operationGetCAInfo(admin, caids);
    	}
    }
    /**
     * Tests that we can disable the CLI and then that we can not call the
     * method getAvailableCAs.
     * @throws Exception
     */
    public void test06DisabledCLI_getCAInfo() throws Exception {
    	enableCLI(false);
    	operationGetCAInfo(administrator, caids);
    }

    /**
     * Enables/disables CLI and flushes caches unless the property does not
     * aready have the right value.
     * @param enable
     */
    private void enableCLI(final boolean enable) throws Exception {
    	final GlobalConfiguration config = cacheAdmin.loadGlobalConfiguration(administrator);
    	final GlobalConfiguration newConfig;
    	if (config.getEnableCommandLineInterface() == enable) {
    		newConfig = config;
    	} else {
	    	config.setEnableCommandLineInterface(enable);
	    	cacheAdmin.saveGlobalConfigurationRemote(administrator, config);
	    	cacheAdmin.flushGlobalConfigurationCache();
	    	newConfig = cacheAdmin.loadGlobalConfiguration(administrator);
    	}
    	assertEquals("CLI should have been enabled/disabled",
    			enable, newConfig.getEnableCommandLineInterface());
    	authorizationSession.flushAuthorizationRuleCache();
    }

    /**
     * Try to get available CAs. Test assumes the CLI is disabled or that the admin
     *  is not authorized.
     * @param admin To perform the operation with.
     */
    private void operationGetAvailabeCAs(final Admin admin) throws RemoteException {
    	// Get some CA ids: should be empty now
    	final Collection emptyCaids = caAdminSession.getAvailableCAs(admin);
    	assertTrue("Should not have got any CAs as admin of type "
    			+ admin.getAdminType(), emptyCaids.isEmpty());
    }

    /**
     * Try to get CA infos. Test assumes the CLI is disabled or that the admin
     *  is not authorized.
     * @param admin to perform the operation with.
     * @param knownCaids IDs to test with.
     */
    private void operationGetCAInfo(final Admin admin, final Collection knownCaids) throws RemoteException {
    	// Get CA infos: We should not get any CA infos even if we know the IDs
    	final Iterator iter = knownCaids.iterator();
    	while (iter.hasNext())  {
    		final Integer caid = (Integer) iter.next();
    		final CAInfo ca = caAdminSession.getCAInfo(admin, caid);
    		assertNull("Got CA " + caid + " as admin of type " + admin.getAdminType(), ca);
    	}
    }

}
