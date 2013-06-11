/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalCertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalCertificateStoreSessionBean implements InternalCertificateStoreSessionRemote {

    private static final Logger log = Logger.getLogger(InternalCertificateStoreSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    CertificateStoreSessionLocal certStore;

    @Override
    public void removeCertificate(BigInteger serno) {
        if ( serno==null ) {
            return;
        }
        final Collection<CertificateData> coll = CertificateData.findBySerialNumber(this.entityManager, serno.toString());
        for (CertificateData certificateData : coll) {
            this.entityManager.remove(certificateData);
            final Base64CertData b64cert = Base64CertData.findByFingerprint(this.entityManager, certificateData.getFingerprint());
            if ( b64cert!=null ) {
                this.entityManager.remove(b64cert);
            }
        }
    }

    private int deleteRow(final String tableName, final String fingerPrint) {
        // This is done as a native query because we do not want to be depending on rowProtection validating
        // correctly, since publisher tests inserts directly in the database with null rowProtection.
        final Query query = this.entityManager.createNativeQuery("DELETE from "+tableName+" where fingerprint=:fingerprint");
        query.setParameter("fingerprint", fingerPrint);
        return query.executeUpdate();
    }

    @Override
    public int removeCertificate(String fingerPrint) {
        deleteRow("CertificateData", fingerPrint);
        return deleteRow("Base64CertData", fingerPrint);
    }

    @Override
    public void removeCertificate(Certificate certificate) {
        if ( certificate==null ) {
            return;
        }
        final String fingerprint = CertTools.getFingerprintAsString(certificate);
        removeCertificate(fingerprint);
    }

    @Override
    public List<Object[]> findExpirationInfo(Collection<String> cas, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax,
            long activeExpireDateMin) {
        return certStore.findExpirationInfo(cas, new ArrayList<Integer>(), activeNotifiedExpireDateMin, activeNotifiedExpireDateMax,
                activeExpireDateMin);
    }

	@SuppressWarnings("unchecked")
	@Override
	public Collection<Certificate> findCertificatesByIssuer(String issuerDN) {
		if (null == issuerDN || issuerDN.length() <= 0) {
			return new ArrayList<Certificate>();
		}
		final Query query = this.entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.issuerDN=:issuerDN");
		query.setParameter("issuerDN", issuerDN);
		return CertificateData.getCertificateList( query.getResultList(), this.entityManager );
	}

	@Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCRL(final AuthenticationToken admin, final String fingerprint) throws AuthorizationDeniedException {
        final CRLData crld = CRLData.findByFingerprint(entityManager, fingerprint);
        if (crld == null) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to remove a CRL that does not exist: " + fingerprint);
            }
        } else {
            entityManager.remove(crld);
        }
    }

}
