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
