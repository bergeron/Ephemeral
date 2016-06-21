DROP TABLE IF EXISTS `messages`;
CREATE TABLE `messages` (
    `id` VARBINARY(32) NOT NULL,
    `encrypted_text` VARBINARY(43688) NOT NULL,
    `salt` VARCHAR(255),
    `dt_created_epoch` BIGINT NOT NULL,
    `expire_minutes` INT,
    `server_encrypted` BOOLEAN NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Self destruct expired messages
--
SET GLOBAL event_scheduler = ON;
DROP EVENT IF EXISTS message_reaper;

CREATE EVENT message_reaper ON SCHEDULE EVERY 1 MINUTE DO
DELETE FROM messages WHERE (dt_created_epoch + (60 * expire_minutes)) < UNIX_TIMESTAMP();

