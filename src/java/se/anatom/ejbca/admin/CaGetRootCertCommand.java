
package se.anatom.ejbca.admin;

import java.io.*;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import se.anatom.ejbca.util.CertTools;

/** Export root CA certificate.
 *
 * @version $Id: CaGetRootCertCommand.java,v 1.2.8.1 2003-09-07 09:51:11 anatom Exp $
 */
public class CaGetRootCertCommand extends BaseCaAdminCommand {

    /** Creates a new instance of CaGetRootCertCommand */
    public CaGetRootCertCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 2) {
            String msg = "Save root CA certificates (PEM- or DER-format) to file.\n";
            msg += "Usage: CA rootcert <filename> <-der>";
            throw new IllegalAdminCommandException(msg);
        }
        String filename = args[1];
        boolean pem = true;
        if (args.length > 2) {
            if (("-der").equals(args[2])) {
                pem = true;
            }
        }
        
        try {
            Certificate[] chain = getCertChain();
            ArrayList certs = new ArrayList();
            for (int i =0;i<chain.length;i++) {
                certs.add(chain[i]);
            }
            X509Certificate rootcert = (X509Certificate)chain[chain.length-1];
            FileOutputStream fos = new FileOutputStream(filename);
            if (pem) {
                fos.write(CertTools.getPEMFromCerts(certs));
            } else {
                fos.write(rootcert.getEncoded());
            }
            fos.close();
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
        System.out.println("Wrote Root CA certificate to '"+filename+"'");
    } // execute
    
}
