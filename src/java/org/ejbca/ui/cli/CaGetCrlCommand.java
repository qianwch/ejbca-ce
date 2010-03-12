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
 
package org.ejbca.ui.cli;

import java.io.FileOutputStream;
import java.util.List;

import org.ejbca.util.CertTools;
import org.ejbca.util.CliTools;


/**
 * Retrieves the latest CRL from the CA.
 *
 * @version $Id$
 */
public class CaGetCrlCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaGetCrlCommand
     *
     * @param args command line arguments
     */
    public CaGetCrlCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
    	// Get and remove switches
    	List<String> argsList = CliTools.getAsModifyableList(args);
    	boolean deltaSelector = argsList.remove("-delta");
    	boolean pem = argsList.remove("-pem");
    	args = argsList.toArray(new String[0]);
			if (args.length < 3) {
				throw new IllegalAdminCommandException("Retrieves CRL in DER format.\nUsage: CA getcrl [-delta] <caname> <outfile> (-pem)");
			}
			try {
				String caname = args[1];
				String outfile = args[2];

                String issuerdn = getIssuerDN(caname);
				byte[] crl = getCertificateStoreSession().getLastCRL(administrator, issuerdn, deltaSelector);
				FileOutputStream fos = new FileOutputStream(outfile);
                if (pem) {		
                    fos.write(CertTools.getPEMFromCrl(crl));
                } else {					
                	fos.write(crl);
                }
				fos.close();
				getOutputStream().println("Wrote latest " + (deltaSelector?"delta ":"") + "CRL to " + outfile + " using " + (pem?"PEM":"DER") + " format");
			} catch (Exception e) {
				e.printStackTrace();
				throw new ErrorAdminCommandException(e);
			}
    } // execute

}
