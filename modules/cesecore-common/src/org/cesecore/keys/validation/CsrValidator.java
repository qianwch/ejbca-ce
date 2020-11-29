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

package org.cesecore.keys.validation;

import org.cesecore.util.ui.DynamicUiModelAware;

/**
 * Describes a validator of certificate signing requests (CSRs).
 */
public interface CsrValidator extends Validator, DynamicUiModelAware {

    /**
     * Validate a certificate signing request.
     *
     * @param csr the certificate signing request (CSR) sent from the client.
     * @throws ValidationException if the validation failed.
     * @throws ValidatorNotApplicableException if no validation could be performed.
     */
    void validate(final byte[] csr) throws ValidationException, ValidatorNotApplicableException;
}
