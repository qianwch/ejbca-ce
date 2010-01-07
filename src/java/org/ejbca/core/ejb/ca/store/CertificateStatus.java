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

package org.ejbca.core.ejb.ca.store;

import java.io.Serializable;
import java.util.Date;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;

/** Simple class encapsulating the certificate status information needed when making revocation checks.
 * 
 * @version $Id$
 */
public class CertificateStatus implements Serializable {

	private static final long serialVersionUID = 1136817557047738919L;
	
	public final static CertificateStatus REVOKED = new CertificateStatus("REVOKED", SecConst.CERTPROFILE_NO_PROFILE);
    public final static CertificateStatus OK = new CertificateStatus("OK", SecConst.CERTPROFILE_NO_PROFILE);
    public final static CertificateStatus NOT_AVAILABLE = new CertificateStatus("NOT_AVAILABLE", SecConst.CERTPROFILE_NO_PROFILE);

    /** Algorithm:
     * if status is CERT_REVOKED the certificate is revoked and reason and date is picked up
     * if status is CERT_ARCHIVED and reason is _NOT_ REMOVEFROMCRL or NOT_REVOKED the certificate is revoked and reason and date is picked up
     * if status is CERT_ARCHIVED and reason is REMOVEFROMCRL or NOT_REVOKED the certificate is NOT revoked
     * if status is neither CERT_REVOKED or CERT_ARCHIVED the certificate is NOT revoked
     * 
     * @param data
     * @return CertificateStatus, can be compared (==) with CertificateStatus.OK, CertificateStatus.REVOKED and CertificateStatus.NOT_AVAILABLE
     */
    public final static CertificateStatus getIt( CertificateDataLocal data) {
        if ( data == null ) {
            return NOT_AVAILABLE;
        }
        Integer pId = data.getCertificateProfileId();
        if (pId == null) {
        	pId = Integer.valueOf(SecConst.CERTPROFILE_NO_PROFILE);
        }
        final int revReason = data.getRevocationReason();
        final int status = data.getStatus();
        if ( status != CertificateDataBean.CERT_REVOKED ) {
        	// If the certificate have status ARCHIVED, BUT revocationReason is REMOVEFROMCRL or NOTREVOKED, the certificate is OK
        	// Otherwise it is a revoked certificate that has been archived and we must return REVOKED
        	if ( (status != CertificateDataBean.CERT_ARCHIVED) || ((revReason == RevokedCertInfo.REVOKATION_REASON_REMOVEFROMCRL) || (revReason == RevokedCertInfo.NOT_REVOKED)) ) {
                return new CertificateStatus(CertificateStatus.OK.name, pId.intValue());        		
        	}
        }
        return new CertificateStatus(data.getRevocationDate(), revReason, pId.intValue());
    }
    
    private final String name;
    public final Date revocationDate;
    public final int revocationReason;
    public final int certificateProfileId;
    
    private CertificateStatus(String s, int certProfileId) {
        this.name = s;
        this.revocationDate = null;
        this.revocationReason = RevokedCertInfo.NOT_REVOKED;
        this.certificateProfileId = certProfileId;
    }
    private CertificateStatus( long date, int reason, int certProfileId ) {
        this.name = CertificateStatus.REVOKED.name;
        this.revocationDate = new Date(date);
        this.revocationReason = reason;
        this.certificateProfileId = certProfileId;
    }
    public String toString() {
        return this.name;
    }
    public boolean equals(Object obj) {
        return obj instanceof CertificateStatus && this.name.equals(obj.toString());
    }
}
