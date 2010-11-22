
-- ServiceData gets two new columns
-- ALTER TABLE ServiceData ADD nextRunTimeStamp BIGINT NOT NULL DEFAULT '0';
-- ALTER TABLE ServiceData ADD runTimeStamp BIGINT NOT NULL DEFAULT '0';

-- Add rowVersion column to all tables
ALTER TABLE AccessRulesData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE AdminEntityData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE AdminGroupData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE AdminPreferencesData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE ApprovalData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE AuthorizationTreeUpdateData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE CAData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE CRLData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE CertReqHistoryData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE CertificateData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE CertificateProfileData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE EndEntityProfileData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE GlobalConfigurationData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE HardTokenCertificateMap ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE HardTokenData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE HardTokenIssuerData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE HardTokenProfileData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE HardTokenPropertyData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE KeyRecoveryData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE LogConfigurationData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE LogEntryData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE PublisherData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE ServiceData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE UserData ADD rowVersion INTEGER NOT NULL DEFAULT '0';
ALTER TABLE UserDataSourceData ADD rowVersion INTEGER NOT NULL DEFAULT '0';

-- Add rowProtection column to all tables
ALTER TABLE AccessRulesData ADD rowProtection TEXT DEFAULT NULL; 
ALTER TABLE AdminEntityData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE AdminGroupData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE AdminPreferencesData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE ApprovalData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE AuthorizationTreeUpdateData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE CAData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE CRLData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE CertReqHistoryData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE CertificateData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE CertificateProfileData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE EndEntityProfileData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE GlobalConfigurationData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE HardTokenCertificateMap ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE HardTokenData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE HardTokenIssuerData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE HardTokenProfileData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE HardTokenPropertyData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE KeyRecoveryData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE LogConfigurationData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE LogEntryData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE PublisherData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE ServiceData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE UserData ADD rowProtection TEXT DEFAULT NULL;
ALTER TABLE UserDataSourceData ADD rowProtection TEXT DEFAULT NULL;
