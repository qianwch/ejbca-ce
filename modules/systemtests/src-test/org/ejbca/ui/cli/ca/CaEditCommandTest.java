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

package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CaEditCommand
 * 
 * @version $Id: CaInitCommandTest.java 16723 2013-05-02 15:34:40Z anatom $
 */
public class CaEditCommandTest {

    private static final String CA_NAME = "1327editca2";
    private static final String CA_DN = "CN=CLI Test CA 1237ca2,O=EJBCA,C=SE";
    private static final String[] HAPPY_PATH_ARGS = { "editca", CA_NAME, "CRLPeriod", "2592000000"};
    private static final String[] CREATE_CA_ARGS = { "init", CA_NAME, CA_DN, "soft", "foo123", "1024", "RSA",
            "365", "null", "SHA1WithRSA" };

    private CaInitCommand caInitCommand;
    private CaEditCaCommand caEditCommand;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaEditCommandTest"));

    private CaSessionRemote caSession = InterfaceCache.getCaSession();

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caInitCommand = new CaInitCommand();
        caEditCommand = new CaEditCaCommand();
        try {
            caSession.removeCA(admin, caSession.getCAInfo(admin, CA_NAME).getCAId());
        } catch (Exception e) {
            // Ignore.

        }
    }

    /** Test trivial happy path for execute, i.e, edit an ordinary CA. */
    @Test
    public void testExecuteHappyPath() throws Exception {
        try {
            caInitCommand.execute(CREATE_CA_ARGS);
            CAInfo info = caSession.getCAInfo(admin, CA_NAME);
            assertEquals("CRLPeriod of a newly created default CA is incorrect, did default value change?", 86400000L, info.getCRLPeriod());
            caEditCommand.execute(HAPPY_PATH_ARGS);
            info = caSession.getCAInfo(admin, CA_NAME);
            assertEquals("CRLPeriod of a edited CA is incorrect. Edit did not work?", 2592000000L, info.getCRLPeriod());
        } finally {
            caSession.removeCA(admin, caSession.getCAInfo(admin, CA_NAME).getCAId());
        }
    }
    
}
