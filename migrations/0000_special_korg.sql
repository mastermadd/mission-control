CREATE TABLE `audit` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`action` text NOT NULL,
	`name` text NOT NULL,
	`time` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `integrations` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`name` text NOT NULL,
	`endpoint` text NOT NULL,
	`target` text,
	`mode` text NOT NULL,
	`auth` text NOT NULL,
	`header` text,
	`customer` text,
	`encrypted` text NOT NULL,
	`status` text NOT NULL,
	`http_code` integer,
	`latency` integer,
	`checked_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `workspaces` (
	`owner` text PRIMARY KEY NOT NULL,
	`data` text NOT NULL,
	`updated_at` text NOT NULL
);
