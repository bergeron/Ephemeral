--
-- Table structure for table `messages`
--
DROP TABLE IF EXISTS `messages`;
CREATE TABLE `messages` (
  `ct` text NOT NULL,
  `from_pub_str` text NOT NULL,
  `to_pub_str` text NOT NULL,
  `dt_created_epoch` bigint(20) NOT NULL,
  `expire_minutes` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


--
-- Self destruct expired messages
--
SET GLOBAL event_scheduler = ON;
DROP event message_reaper;

CREATE event message_reaper ON schedule EVERY 1 MINUTE DO DELETE FROM messages WHERE (dt_created_epoch + (60 * expire_minutes)) < UNIX_TIMESTAMP();
