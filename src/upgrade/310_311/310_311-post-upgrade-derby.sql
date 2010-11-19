-- PublisherQueueData was a late add-on so we need to check if the column was created during appserver start-up

-- Add rowVersion column to all tables
ALTER TABLE PublisherQueueData ADD COLUMN rowVersion INTEGER NOT NULL WITH DEFAULT 0;

--  PublisherQueueData.volatileData is currently LONG VARCHAR, but is defined as CLOB on other databases
ALTER TABLE PublisherQueueData ADD tmpvolatileData CLOB DEFAULT NULL;
UPDATE PublisherQueueData SET tmpvolatileData=volatileData;
ALTER TABLE PublisherQueueData DROP COLUMN volatileData;
ALTER TABLE PublisherQueueData ADD volatileData CLOB DEFAULT NULL;
UPDATE PublisherQueueData SET volatileData=tmpvolatileData;
ALTER TABLE PublisherQueueData DROP COLUMN tmpvolatileData;

-- Add rowProtection column to all tables
ALTER TABLE PublisherQueueData ADD COLUMN rowProtection CLOB(10 K) DEFAULT NULL;
