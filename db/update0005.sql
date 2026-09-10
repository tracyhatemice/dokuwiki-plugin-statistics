-- audit events captured from DokuWiki's native Logger (LOGGER_DATA_FORMAT)

CREATE TABLE `audit`
(
    `id`       INTEGER PRIMARY KEY,
    `dt`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- UTC, from the event's datetime
    `facility` TEXT     NOT NULL,
    `user`     TEXT     NOT NULL DEFAULT '',                -- '' when unknown or anonymous
    `ip`       TEXT     NOT NULL DEFAULT '',
    `action`   TEXT     NOT NULL DEFAULT '',                -- short event name, e.g. item_created, edit
    `subject`  TEXT     NOT NULL DEFAULT '',                -- the thing acted on: page id, item id, ...
    `message`  TEXT     NOT NULL,                           -- original scan line
    `details`  TEXT     NOT NULL DEFAULT '',                -- original details, compact JSON when it was JSON
    `file`     TEXT     NOT NULL DEFAULT '',
    `line`     INTEGER  NOT NULL DEFAULT 0
);
CREATE INDEX `idx_audit_dt` ON `audit` (`dt`);
CREATE INDEX `idx_audit_facility` ON `audit` (`facility`, `dt`);
CREATE INDEX `idx_audit_user` ON `audit` (`user`, `dt`);
CREATE INDEX `idx_audit_action` ON `audit` (`action`, `dt`);
