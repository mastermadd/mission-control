CREATE TABLE `classic_cache` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`revision` integer NOT NULL,
	`session` text,
	`snapshot` text,
	`last_success` text,
	`last_attempt` text,
	`error` text,
	`next_due` integer DEFAULT 0 NOT NULL,
	`lease` text,
	`lease_until` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
ALTER TABLE `integrations` ADD `connector` text DEFAULT 'generic' NOT NULL;--> statement-breakpoint
ALTER TABLE `integrations` ADD `revision` integer DEFAULT 0 NOT NULL;