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

package org.ejbca.core.model.validation;

import org.cesecore.keys.validation.CsrValidator;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.ValidationException;
import org.cesecore.keys.validation.Validator;
import org.cesecore.keys.validation.ValidatorBase;
import org.cesecore.profiles.Profile;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;

import java.util.Arrays;
import java.util.List;

/**
 * Validates the Stellar payment extension inside a PKCS#10 CSR.
 */
public class StellarPaymentValidator extends ValidatorBase implements CsrValidator {
    private static final String ACCOUNT_ID_KEY = "ACCOUNTID";
    private static final String HORIZON_SERVER_KEY = "HORIZONSERVER";
    private static final String ALLOW_RENEWAL_KEY = "ALLOWRENEWAL";
    private static final String CERTIFICATE_COST_KEY = "CERTIFICATECOST";
    private DynamicUiModel dynamicUiModel = new DynamicUiModel(data);

    @Override
    public void validate(byte[] csr) throws ValidationException {
        throw new ValidationException("Not implemented.");
    }

    @Override
    public String getValidatorTypeIdentifier() {
        return "STELLAR_PAYMENT_VALIDATOR";
    }

    @Override
    public String getLabel() {
        return "Stellar Payment Validator";
    }

    @Override
    public Class<? extends Validator> getValidatorSubType() {
        return CsrValidator.class;
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return StellarPaymentValidator.class;
    }

    @Override
    public void initDynamicUiModel() {
        dynamicUiModel.add(new DynamicUiProperty<>("SETTINGS"));
        dynamicUiModel.add(new DynamicUiProperty<>("ACCOUNTANDNETWORKSETTINGS"));
        dynamicUiModel.add(new DynamicUiProperty<>(String.class, ACCOUNT_ID_KEY, getString(ACCOUNT_ID_KEY, "")));
        dynamicUiModel.add(new DynamicUiProperty<>(String.class, HORIZON_SERVER_KEY, getString(HORIZON_SERVER_KEY, "https://horizon-testnet.stellar.org")));
        dynamicUiModel.add(new DynamicUiProperty<>("VALIDATIONSETTINGS"));
        dynamicUiModel.add(new DynamicUiProperty<>(String.class, CERTIFICATE_COST_KEY, getString(CERTIFICATE_COST_KEY, "1")));
        dynamicUiModel.add(new DynamicUiProperty<>(Boolean.class, ALLOW_RENEWAL_KEY, getBoolean(ALLOW_RENEWAL_KEY, false)));
    }

    @Override
    public DynamicUiModel getDynamicUiModel() {
        return dynamicUiModel;
    }

    @Override
    public List<Integer> getApplicablePhases() {
        return Arrays.asList(IssuancePhase.DATA_VALIDATION.getIndex());
    }
}
