-- Add rowVersion column to all tables
-- PublisherQueueData was a late add-on so we need to check if the column was created during appserver start-up
ALTER TABLE PublisherQueueData ADD rowVersion INTEGER NOT NULL DEFAULT '0';

-- Add rowProtection column to all tables
ALTER TABLE PublisherQueueData ADD rowProtection TEXT DEFAULT NULL;
