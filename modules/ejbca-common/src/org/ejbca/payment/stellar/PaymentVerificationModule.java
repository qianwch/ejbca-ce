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

/**
 * Performs payment verification against the Stellar network.
 */
public class PaymentVerificationModule {
    private String paymentReference;
    private String horizonServer;
    private String mininumAcceptedPayment;

    public PaymentVerificationModule(final Pkcs10PaymentVerificationModuleBuilder builder) {
        this.paymentReference = builder.getPaymentReference();
        this.horizonServer = builder.getHorizonServer();
        this.mininumAcceptedPayment = builder.getMinimumAcceptedPayment();
    }
}
