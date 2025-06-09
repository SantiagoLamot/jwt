CREATE DATABASE `db_jwt` /*!40100 DEFAULT CHARACTER SET utf8 */;
USE `db_jwt`;
CREATE TABLE `user` (
  `id` bigint(25) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `rol` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8;
