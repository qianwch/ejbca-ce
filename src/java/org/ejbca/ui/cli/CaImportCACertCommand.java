package org.ejbca.ui.cli;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.List;

import javax.ejb.CreateException;

import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CliTools;

/**
 * Imports a PEM file and created a new external CA representation from it.
 */
public class CaImportCACertCommand extends BaseCaAdminCommand {

	public CaImportCACertCommand(String[] args) {
		super(args);
	}

	/**
	 * @see org.ejbca.ui.cli.IAdminCommand
	 */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		if (args.length < 3) {
			String msg = "Usage: ca importcacert <CA name> <PEM file> [-initauthorization]\n\n";
			msg += "Imports a CA certificate, crating an \"External CA\"\n";
			msg += "Add the argument initauthorization if you are importing an initial administration CA, and this will be the first CA in your system. Only used during installation when there is no local AdminCA on the EJBCA instance, but an external CA is used for administration.";
			throw new IllegalAdminCommandException(msg);
		}
		String caName = args[1];
		String pemFile = args[2];
		List<String> argsList = CliTools.getAsModifyableList(args);
		boolean initAuth = argsList.remove("-initauthorization");
		try {
			Collection certs = CertTools.getCertsFromPEM(pemFile);
			if (certs.size() != 1) {
				throw new ErrorAdminCommandException("PEM file must only contain one CA certificate, this PEM file contains "+certs.size()+".");
			}
			if (initAuth) {
				String subjectdn = CertTools.getSubjectDN((Certificate)certs.iterator().next());
				Integer caid = new Integer(subjectdn.hashCode());
				getOutputStream().println("Initializing authorization module for caid: "+caid);
				initAuthorizationModule(caid.intValue());
			}
			getCAAdminSession().importCACertificate(administrator, caName, certs);
			getOutputStream().println("Imported CA "+caName);			
		} catch (CertificateException e) {
			error(e.getMessage());
		} catch (IOException e) {
			error(e.getMessage());
		} catch (CreateException e) {
			error(e.getMessage());
		} catch (AdminGroupExistsException e) {
			error(e.getMessage());
		}
	}
}
