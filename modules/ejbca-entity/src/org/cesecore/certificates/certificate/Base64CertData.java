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

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.persistence.ColumnResult;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.SqlResultSetMapping;
import javax.persistence.SqlResultSetMappings;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * Base64 encoded certificate. Use {@link CertificateData#getFingerprint()} to get the encoded data.
 * The class is not extending {@link ProtectedData} this since each row is a Certificate.
 * A certificate is all ready integrity  protected since it is signed by the CA.
 * 
 * @version $Id$
 */
@Entity
@Table(name = "Base64CertData")
@SqlResultSetMappings(value = {
        @SqlResultSetMapping(name = "FingerprintUsernameSubset", columns = { @ColumnResult(name = "fingerprint"), @ColumnResult(name = "username") }) })
public class Base64CertData implements Serializable {

    private static final long serialVersionUID = 4132839902195978822L;

    private static final Logger log = Logger.getLogger(Base64CertData.class);

    private String fingerprint = "";
    private String base64Cert;

    /**
     * Entity holding info about a certificate. Create by sending in the certificate, which extracts (from the cert) fingerprint (primary key),
     * 
     * @param incert the (X509)Certificate to be stored in the database.
     */
    public Base64CertData(Certificate incert) {
        // Extract all fields to store with the certificate.
        try {
            setBase64Cert(new String(Base64.encode(incert.getEncoded())));

            String fp = CertTools.getFingerprintAsString(incert);
            setFingerprint(fp);

        } catch (CertificateEncodingException cee) {
            final String msg = "Can't extract DER encoded certificate information.";
            log.error(msg, cee);
            throw new RuntimeException(msg);
        }
    }

    public Base64CertData() {
    }

    /**
     * Fingerprint of certificate
     * 
     * @return fingerprint
     */
    // @Id @Column
    public String getFingerprint() {
        return this.fingerprint;
    }

    /**
     * Fingerprint of certificate
     * 
     * @param fingerprint fingerprint
     */
    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     * The certificate itself
     * 
     * @return base64 encoded certificate
     */
    // @Column @Lob
    public String getBase64Cert() {
        return this.base64Cert;
    }

    /**
     * The certificate itself
     * 
     * @param base64Cert base64 encoded certificate
     */
    public void setBase64Cert(String base64Cert) {
        this.base64Cert = base64Cert;
    }

    //
    // Public business methods used to help us manage certificates
    //

    /**
     * certificate itself
     * 
     * @return certificate
     */
    @Transient
    public Certificate getCertificate() {
        Certificate cert = null;
        try {
            cert = CertTools.getCertfromByteArray(Base64.decode(getBase64Cert().getBytes()));
        } catch (CertificateException ce) {
            log.error("Can't decode certificate.", ce);
            return null;
        }
        return cert;
    }

    /**
     * certificate itself
     * 
     * @param incert certificate
     */
    public void setCertificate(Certificate incert) {
        try {
            final String b64Cert = new String(Base64.encode(incert.getEncoded()));
            setBase64Cert(b64Cert);
            final X509Certificate tmpcert = (X509Certificate) incert;
            String fp = CertTools.getFingerprintAsString(tmpcert);
            setFingerprint(fp);
        } catch (CertificateEncodingException cee) {
            log.error("Can't extract DER encoded certificate information.", cee);
        }
    }

    //
    // Search functions.
    //

    /** @return the found entity instance or null if the entity does not exist */
    public static Base64CertData findByFingerprint(EntityManager entityManager, String fingerprint) {
        return entityManager.find(Base64CertData.class, fingerprint);
    }

    /** @return the number of entries with the given parameter */
    public static long getCount(EntityManager entityManager) {
        final Query countQuery = entityManager.createQuery("SELECT COUNT(a) FROM Base64CertData a");
        return ((Long) countQuery.getSingleResult()).longValue(); // Always returns a result
    }
}
