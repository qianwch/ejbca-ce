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

package org.ejbca.core.protocol.cmp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.core.protocol.cmp.authentication.EndEntityCertificateAuthenticationModule;

/**
 * Message handler for certificate request messages in the CRMF format
 * @author tomas
 * @version $Id: CrmfMessageHandler.java 12950 2011-10-20 16:56:05Z anatom $
 */
public class CrmfKeyUpdateHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
    
    private static final Logger LOG = Logger.getLogger(CrmfKeyUpdateHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    /** strings for error messages defined in internal resources */
    private static final String CMP_ERRORGENERAL = "cmp.errorgeneral";

    private final SignSession signSession;
    private final CertificateStoreSession certStoreSession;
    private final AuthorizationSession authorizationSession;
    private final UserAdminSession userAdminSession;

    /**
     * Used only by unit test.
     */
    public CrmfKeyUpdateHandler() {
        super();
        this.signSession =null;
        this.certStoreSession = null;
        this.authorizationSession = null;
        this.userAdminSession = null;
    }
    
    /**
     * Construct the message handler.
     * @param admin
     * @param caSession
     * @param certificateProfileSession
     * @param certificateRequestSession
     * @param endEntityProfileSession
     * @param signSession
     * @param userAdminSession
     */
    public CrmfKeyUpdateHandler(final Admin admin, CAAdminSession caAdminSession, CertificateProfileSession certificateProfileSession, 
            EndEntityProfileSession endEntityProfileSession, SignSession signSession, 
            CertificateStoreSession certStoreSession, AuthorizationSession authSession, UserAdminSession userAdminSession) {
        
        super(admin, caAdminSession, endEntityProfileSession, certificateProfileSession);
        // Get EJB beans, we can not use local beans here because the TCP listener does not work with that
        this.signSession = signSession;
        this.certStoreSession = certStoreSession;
        this.authorizationSession = authSession;
        this.userAdminSession = userAdminSession;

    }

    /**
     * Handles the CMP message
     * 
     * Expects the CMP message to be a CrmfRequestMessage. The message is authenticated using 
     * EndEntityCertificateAuthenticationModule in client mode. It used the attached certificate 
     * to find then End Entity which this certificate belongs to and requesting for a new certificate 
     * to be generated. 
     * 
     * If automatic update of the key (same as certificate renewal), the end entity's status is set to 
     * 'NEW' before processing the request. If using the same old keys in the new certificate is not allowed, 
     * a check is made to insure the the key specified in the request is not the same as the key of the attached 
     * certificate.
     * 
     * The KeyUpdateRequet is processed only in client mode.
     * 
     * @param msg
     * @throws AuthorizationDeniedException when the concerned end entity could not be found
     * @throws CADoesntExistsException
     * @throws UserDoesntFullfillEndEntityProfile when the end entity fails to update
     * @throws WaitingForApprovalException when the end entity fails to update
     * @throws EjbcaException when the end entity fails to update
     * @throws FinderException when updating the end entity status fails
     * @throws InvalidKeyException when failing to read the key from the crmf request
     * @throws NoSuchAlgorithmException when failing to read the key from the crmf request
     * @throws NoSuchProviderException when failing to read the key from the crmf request
     */
    public IResponseMessage handleMessage(final BaseCmpMessage msg) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">handleMessage");
        }
        
        if(CmpConfiguration.getRAOperationMode()) {
            final String errMsg = "This request can only be processed in client mode";
            LOG.info(errMsg);
            return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, errMsg);
        }
        
        
        IResponseMessage resp = null;
        try {

            CrmfRequestMessage crmfreq = null;
            if (msg instanceof CrmfRequestMessage) {
                crmfreq = (CrmfRequestMessage) msg;
                crmfreq.getMessage();               
                
                // Authenticate the request
                EndEntityCertificateAuthenticationModule eecmodule = new EndEntityCertificateAuthenticationModule("-");
                eecmodule.setSession(this.admin, this.caAdminSession, this.certStoreSession, this.authorizationSession, this.endEntityProfileSession, 
                        this.userAdminSession);
                if(!eecmodule.verifyOrExtract(crmfreq.getPKIMessage(), null)) {
                    String errMsg = eecmodule.getErrorMessage();
                    if( errMsg == null) {
                        errMsg = "Failed to verify the request";
                    }
                    LOG.error(errMsg);
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
                }
            
                // Get the certificate attached to the request
                X509Certificate oldCert = (X509Certificate) eecmodule.getExtraCert();
            
                // Find the end entity that the certificate belongs to
                String subjectDN = oldCert.getSubjectDN().toString();
                String issuerDN = oldCert.getIssuerDN().toString();
                UserDataVO userdata = userAdminSession.findUserBySubjectAndIssuerDN(admin, subjectDN, issuerDN);
                if(userdata == null) {
                    final String errMsg = INTRES.getLocalizedMessage("cmp.infonouserfordn", subjectDN);
                    LOG.info(errMsg);
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
                } else {
                    if(LOG.isDebugEnabled()) {
                        LOG.debug("Found user '" + userdata.getUsername() + "'");
                    }
                }
            
                // The password that should be used to obtain the new certificate
                String password = StringUtils.isNotEmpty(userdata.getPassword()) ? userdata.getPassword() : eecmodule.getAuthenticationString();
                
                // Set the appropriate parameters in the end entity
                userdata.setPassword(password);
                userAdminSession.changeUser(admin, userdata, true);
                if(CmpConfiguration.getAllowAutomaticKeyUpdate()) {
                    if(LOG.isDebugEnabled()) {
                        LOG.debug("Setting the end entity status to 'NEW'. Username: " + userdata.getUsername());
                    }

                    userAdminSession.setUserStatus(admin, userdata.getUsername(), UserDataConstants.STATUS_NEW);
                }
                
                // Set the appropriate parameters in the request
                crmfreq.setUsername(userdata.getUsername());
                crmfreq.setPassword(password);
                
                
                // Check the public key, whether it is allowed to use the old keys or not.
                if(!CmpConfiguration.getAllowUpdateWithSameKey()) {
                	PublicKey certPublicKey = oldCert.getPublicKey();
                	PublicKey requestPublicKey = crmfreq.getRequestPublicKey();
                	if(certPublicKey.equals(requestPublicKey)) {
                        final String errMsg = "Invalid key. The public key in the KeyUpdateRequest is the same as the public key in the existing end entity certiticate";
                        LOG.error(errMsg);
                        return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
                	}
                }
                
                // Process the request
                resp = signSession.createCertificate(admin, crmfreq, org.ejbca.core.protocol.cmp.CmpResponseMessage.class, userdata);               

                if (resp == null) {
                    final String errMsg = INTRES.getLocalizedMessage("cmp.errornullresp");
                    LOG.error(errMsg);
                    resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
                }
            } else {
                final String errMsg = INTRES.getLocalizedMessage("cmp.errornocmrfreq");
                LOG.error(errMsg);
                resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
            }
        
        } catch (AuthorizationDeniedException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (CADoesntExistsException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (UserDoesntFullfillEndEntityProfile e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (WaitingForApprovalException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (EjbcaException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (FinderException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (InvalidKeyException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info("Error while reading the public key of the extraCert attached to the CMP request");
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (NoSuchAlgorithmException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info("Error while reading the public key of the extraCert attached to the CMP request");
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (NoSuchProviderException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info("Error while reading the public key of the extraCert attached to the CMP request");
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		}

        if (LOG.isTraceEnabled()) {
            LOG.trace("<handleMessage");
        }
        return resp;
    }


}
