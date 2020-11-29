/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.payment.stellar;

interface PaymentVerificationModuleBuilder {
    /**
     * Get the payment reference which can be used to ask the Stellar network for
     * the actual payment.
     *
     * @return the payment reference.
     */
    String getPaymentReference();

    /**
     * Get the minimum amount of Stellar lumens (XLM) which must have been transferred to the CA
     * in order to accept the CSR.
     *
     * @return the minimum amount in XLM.
     */
    String getMinimumAcceptedPayment();

    /**
     * Get the URL of the Horizon server to use when talking to the Stellar network.
     *
     * @return the URL of the Horizon server.
     */
    String getHorizonServer();
}
