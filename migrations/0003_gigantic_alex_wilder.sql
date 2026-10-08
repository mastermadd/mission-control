CREATE TABLE `removed_assets` (
	`owner` text NOT NULL,
	`integration_id` text NOT NULL,
	`asset_id` text NOT NULL,
	`created_at` text NOT NULL,
	PRIMARY KEY(`owner`, `integration_id`, `asset_id`)
);
