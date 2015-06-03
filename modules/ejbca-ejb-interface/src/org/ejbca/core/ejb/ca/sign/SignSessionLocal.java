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
package org.ejbca.core.ejb.ca.sign;

import javax.ejb.Local;

import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;

/**
 * Local interface for RSASignSession.
 */
@Local
public interface SignSessionLocal extends SignSession {
    /**
     * Returns a CA that a request is targeted for. Uses different methods in priority order to try to find it.
     * 
     * @param admin an authenticating token
     * @param req the request
     * @param doLog if this operation should log in the audit log.
     * @return CA object
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     */
    CA getCAFromRequest(AuthenticationToken admin, RequestMessage req, boolean doLog) throws CADoesntExistsException, AuthorizationDeniedException;
    
    /**
     * Requests for a certificate to be created for the passed public key wrapped in a certification request message (ex PKCS10).  The username and password used to 
     * authorize is taken from the request message. Verification of the signature (proof-of-possesion) on the request is performed, and an exception thrown if verification fails. 
     * The method queries the user database for authorization of the user.
     * 
     * Works like the standard methods in this class for creating certificates, but will set status to NEW if it is GENERATED. Is guaranteed to roll back user status change if an 
     * error is encountered during certificate creation. 
     * 
     *
     * @param admin         Information about the administrator or admin performing the event.
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * @param keyUsage      integer with bit mask describing desired keys usage. Bit mask is packed in
     *                      in integer using constants from CertificateDataBean. ex. int keyusage =
     *                      CertificateDataBean.digitalSignature | CertificateDataBean.nonRepudiation; gives
     *                      digitalSignature and nonRepudiation. ex. int keyusage = CertificateDataBean.keyCertSign
     *                      | CertificateDataBean.cRLSign; gives keyCertSign and cRLSign. Keyusage < 0 means that default
     *                      keyUsage should be used, or should be taken from extensions in the request.
     * @param responseClass The implementation class that will be used as the response message.
     * @param suppliedUserData Optional (can be null) supplied user data, if we are running without storing UserData this will be used. Should only 
     *  be supplied when we issue certificates in a single transaction.
     *  
     * @return The newly created response
     * 
     * @throws NoSuchEndEntityException      if the user does not exist (does not require rollback)
     * @throws CertificateRevokeException if certificate was meant to be issued revoked, but could not.  (rollback)
     * @throws CertificateCreateException if certificate couldn't be created.  (rollback)
     * @throws AuthorizationDeniedException if the authentication token wasn't authorized to the CA defined in the request  (rollback)
     * @throws ApprovalException if changing the end entity status requires approval (does not require rollback)
     * @throws WaitingForApprovalException if an approval is already waiting for the status to be changed (does not require rollback)
     * @throws CesecoreException 
     * @throws EjbcaException 
     */
    ResponseMessage createCertificateIgnoreStatus(final AuthenticationToken admin, final RequestMessage req,
            Class<? extends CertificateResponseMessage> responseClass) throws AuthorizationDeniedException, NoSuchEndEntityException,
            CertificateCreateException, CertificateRevokeException, InvalidAlgorithmException, ApprovalException, WaitingForApprovalException, EjbcaException, CesecoreException;

}
