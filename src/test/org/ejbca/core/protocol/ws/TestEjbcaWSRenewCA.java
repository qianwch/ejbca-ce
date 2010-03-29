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
package org.ejbca.core.protocol.ws; 



/** To run you must have the file tmp/bin/junit/jndi.properties
 * 
 * @version $Id$
 */
public class TestEjbcaWSRenewCA extends CommonEjbcaWSTest {
	
	
	public void test00SetupAccessRights() throws Exception{
		super.test00SetupAccessRights();
	}

	public void test34CaRenewCertRequest() throws Exception{
		super.test34CaRenewCertRequest(true);
	}

	public void test35CleanUpCACertRequest() throws Exception{
		super.test35CleanUpCACertRequest(true);
	}

    public void test99cleanUpAdmins() throws Exception {
    	super.test99cleanUpAdmins();
    }

}

