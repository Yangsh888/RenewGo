<?php

namespace TypechoPlugin\RenewGo;

use Typecho\Db;
use Utils\Schema as CoreSchema;

class Schema
{
    public static function ensure(Db $db): void
    {
        $dialect = CoreSchema::dialect($db);
        $table = $db->getPrefix() . 'renew_go_logs';

        $db->query(self::tableSql($db, $dialect, $table), Db::WRITE);

        foreach (self::columns($dialect) as $column => $definition) {
            if (!CoreSchema::columnExists($db, $table, $column)) {
                $db->query(
                    'ALTER TABLE ' . CoreSchema::quote($table, $dialect) . ' ADD COLUMN ' . $definition,
                    Db::WRITE
                );
            }
        }

        $name = static fn(string $mysql, string $other): string => $dialect === 'mysql' ? $mysql : $table . '_' . $other;

        CoreSchema::ensureIndex($db, $table, $name('idx_ip_action_created', 'ip_action_created'), ['ip', 'action', 'created_at']);
        CoreSchema::ensureIndex($db, $table, $name('idx_created', 'created'), ['created_at']);
    }

    private static function tableSql(Db $db, string $dialect, string $table): string
    {
        $name = CoreSchema::quote($table, $dialect);

        return match ($dialect) {
            'sqlite' => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '"id" INTEGER PRIMARY KEY AUTOINCREMENT,'
                . '"ip" TEXT NOT NULL,'
                . '"action" TEXT NOT NULL,'
                . '"result" TEXT NOT NULL,'
                . '"target" TEXT DEFAULT NULL,'
                . '"referer" TEXT DEFAULT NULL,'
                . '"created_at" INTEGER NOT NULL'
                . ')',
            'pgsql' => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '"id" BIGSERIAL PRIMARY KEY,'
                . '"ip" VARCHAR(45) NOT NULL,'
                . '"action" VARCHAR(24) NOT NULL,'
                . '"result" VARCHAR(16) NOT NULL,'
                . '"target" TEXT DEFAULT NULL,'
                . '"referer" TEXT DEFAULT NULL,'
                . '"created_at" INTEGER NOT NULL'
                . ')',
            default => 'CREATE TABLE IF NOT EXISTS ' . $name . ' ('
                . '`id` bigint unsigned NOT NULL auto_increment,'
                . '`ip` varchar(45) NOT NULL,'
                . '`action` varchar(24) NOT NULL,'
                . '`result` varchar(16) NOT NULL,'
                . '`target` varchar(512) DEFAULT NULL,'
                . '`referer` varchar(512) DEFAULT NULL,'
                . '`created_at` int unsigned NOT NULL,'
                . 'PRIMARY KEY (`id`)'
                . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=' . CoreSchema::detectMysqlCollation($db),
        };
    }

    private static function columns(string $dialect): array
    {
        if ($dialect === 'mysql') {
            return [
                'ip' => '`ip` varchar(45) NOT NULL default \'\'',
                'action' => '`action` varchar(24) NOT NULL default \'\'',
                'result' => '`result` varchar(16) NOT NULL default \'\'',
                'target' => '`target` varchar(512) DEFAULT NULL',
                'referer' => '`referer` varchar(512) DEFAULT NULL',
                'created_at' => '`created_at` int unsigned NOT NULL default 0',
            ];
        }

        return [
            'ip' => '"ip" VARCHAR(45) NOT NULL DEFAULT \'\'',
            'action' => '"action" VARCHAR(24) NOT NULL DEFAULT \'\'',
            'result' => '"result" VARCHAR(16) NOT NULL DEFAULT \'\'',
            'target' => '"target" TEXT DEFAULT NULL',
            'referer' => '"referer" TEXT DEFAULT NULL',
            'created_at' => '"created_at" INT NOT NULL DEFAULT 0',
        ];
    }
}
